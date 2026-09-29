/**
 * Counter -> rate, with reset detection.
 *
 * ─── Why the agent divides and the control plane does not ───────────────────
 *
 * K3: "counters are turned into rates in the agent". Two reasons, and both are
 * about being close to the source:
 *
 *  · A counter RESETS when the container behind it restarts. Detecting that
 *    needs the previous reading of the same counter, and the agent is the only
 *    place that has one 30 seconds old. On the control plane the previous
 *    reading may be an hour old, on the other side of a tunnel outage, or
 *    missing because the ring dropped it.
 *  · Roll-up. Averaging a RATE over an hour is a rate; averaging a COUNTER over
 *    an hour is a number with no meaning. The control plane rolls up, so what
 *    reaches it must already be a rate.
 *
 * ─── What happens at a reset, and the alternative that was rejected ─────────
 *
 * When the current reading is BELOW the previous one, the counter restarted at
 * some unknown point inside the interval. This module emits `NO_READING` for
 * that one interval and takes the new value as the baseline for the next.
 *
 * Prometheus's `rate()` does the other thing: it assumes the counter restarted
 * at exactly zero and adds the whole current value to the delta. That is a
 * defensible choice for a graph that will be smoothed over five minutes, and it
 * is the wrong one here. The assumption is unverifiable — the counter may have
 * reset at the start of the interval or a millisecond before the read — and
 * when it is wrong it does not produce a missing point, it produces a SPIKE:
 * one interval showing a burst of disk writes that never happened, in a product
 * whose entire diagnostic claim is that the number on the screen is real. One
 * absent point every time a container restarts is cheap; a phantom spike costs
 * the operator an investigation.
 *
 * The first reading of any counter also produces `NO_READING`: a rate needs two
 * points, and inventing a zero would put a flat line under every pod for its
 * first 30 seconds of life.
 *
 * ─── Why time comes from the reading and not from the clock ─────────────────
 *
 * The divisor is the elapsed time between the two READINGS, not the nominal 30
 * second period. A tick that ran late (a slow kubelet, a paused event loop)
 * would otherwise inflate every rate on that node by exactly the amount of the
 * delay — an artefact that looks like load.
 */
import { NO_READING, float32 } from "./types.js";

interface Reading {
  readonly value: number;
  readonly at: number;
}

/**
 * Below this the divisor is not trustworthy and no rate is produced.
 *
 * Two readings within the same 100 ms cannot describe a per-second rate: the
 * kubelet's own cAdvisor housekeeping runs every 10 seconds (K3, "freshness
 * ceiling"), so a sub-100ms gap means the same underlying sample was read
 * twice and the delta is noise divided by nearly zero.
 */
const MIN_INTERVAL_MS = 100;

/**
 * Remembers one previous reading per key and turns the next into a rate.
 *
 * Keys are opaque strings owned by the caller — `<entityId>|<metric>` in the
 * readers. This class knows nothing about entities on purpose: the same
 * arithmetic serves the Summary's network counters and cAdvisor's IO counters,
 * and duplicating it would let the two drift apart in exactly the place where
 * a difference is invisible.
 */
export class CounterRates {
  readonly #previous = new Map<string, Reading>();

  /**
   * @returns bytes (or events) per second, or `NO_READING` for the first
   *          reading, a reset, or an untrustworthy interval.
   */
  rate(key: string, value: number, at: number): number {
    const step = this.#step(key, value, at);
    if (step === undefined) return NO_READING;
    return float32((step.delta * 1000) / step.elapsedMs);
  }

  /**
   * The share of WALL-CLOCK time a container spent throttled — the only user
   * is `cpu.throttledWall` (`cadvisor.ts`).
   *
   *     w = Δthrottled_periods × period_µs / (Δt_ms × 1000)
   *
   * Each throttled CFS period is one `period_µs` slice of wall time in which
   * the cgroup had used up its quota and sat waiting; the sum over the
   * interval, divided by the interval, is "how much of the time was this
   * container held at its limit". It is bounded by 1 by construction (a
   * period cannot be throttled twice) and is clamped there because the two
   * timestamps it divides by can jitter by a few milliseconds — a value above
   * 1 is a stamp error, not a measurement.
   *
   * ─── The ratio this replaced, and why it answered the wrong question ─────
   *
   * The previous metric was `Δthrottled / Δperiods` (`cpu.throttled`). The
   * kernel advances `nr_periods` ONLY in periods where the cgroup had runnable
   * work, so that denominator is "periods the container was awake", not
   * elapsed time. A process that wakes rarely and bursts on several cores
   * exhausts a small quota inside every period it is awake in, and reads as
   * heavily throttled while it is almost never actually held back. Measured on
   * a production node (29.09.2026, two readings 76 s apart, one container with
   * a 50m limit using 0.8m): active 1.7% of periods, old ratio 76.9%, wall
   * share 1.32%. The two are related by `w = ratio × active share`, so `w` is
   * never larger than the old ratio, and it is the number that says whether
   * the limit costs the workload anything.
   *
   * Same first-reading / reset / short-interval rules as `rate`, for the same
   * reasons (a phantom spike is worse than a missing point).
   */
  wallShare(key: string, throttledPeriods: number, periodUs: number, at: number): number {
    const step = this.#step(key, throttledPeriods, at);
    if (step === undefined) return NO_READING;
    const share = (step.delta * periodUs) / (step.elapsedMs * 1000);
    return float32(Math.min(1, Math.max(0, share)));
  }

  /**
   * Stores the reading and returns the step from the previous one, or
   * `undefined` when there is no trustworthy step: the first reading, a reset
   * (the value went DOWN), or an interval under `MIN_INTERVAL_MS`.
   */
  #step(key: string, value: number, at: number): { delta: number; elapsedMs: number } | undefined {
    const previous = this.#previous.get(key);
    this.#previous.set(key, { value, at });

    if (previous === undefined) return undefined;
    if (value < previous.value) return undefined; // reset
    const elapsedMs = at - previous.at;
    if (elapsedMs < MIN_INTERVAL_MS) return undefined;
    return { delta: value - previous.value, elapsedMs };
  }

  /**
   * Forgets keys that no counter reported this round.
   *
   * Without this the map is a leak with the shape of a pod churn rate: every
   * pod that ever ran on a node keeps its entries forever. `keep` is the set of
   * keys the current round produced; every key this class stores is exactly a
   * caller's key (per container for `wallShare`), so the match is exact.
   */
  retain(keep: ReadonlySet<string>): void {
    for (const key of this.#previous.keys()) {
      if (!keep.has(key)) this.#previous.delete(key);
    }
  }

  /** Number of remembered readings — the leak assertion in the tests reads this. */
  get size(): number {
    return this.#previous.size;
  }
}
