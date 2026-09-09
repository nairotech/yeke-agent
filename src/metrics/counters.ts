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
    const previous = this.#previous.get(key);
    this.#previous.set(key, { value, at });

    if (previous === undefined) return NO_READING;
    if (value < previous.value) return NO_READING; // reset
    const elapsedMs = at - previous.at;
    if (elapsedMs < MIN_INTERVAL_MS) return NO_READING;

    return float32(((value - previous.value) * 1000) / elapsedMs);
  }

  /**
   * The ratio of two counters' DELTAS — `cpu.throttled` is the only user.
   *
   * The ratio of the raw totals would answer a different question ("what
   * fraction of every period since this container started was throttled") and
   * would be almost immovable after a day of uptime: a container that is being
   * throttled right now would still read near zero, which is the one case the
   * metric exists for.
   */
  ratio(key: string, numerator: number, denominator: number, at: number): number {
    const previousNumerator = this.#previous.get(`${key}#n`);
    const previousDenominator = this.#previous.get(`${key}#d`);
    this.#previous.set(`${key}#n`, { value: numerator, at });
    this.#previous.set(`${key}#d`, { value: denominator, at });

    if (previousNumerator === undefined || previousDenominator === undefined) return NO_READING;
    if (numerator < previousNumerator.value || denominator < previousDenominator.value) {
      return NO_READING; // either counter reset: the pair is no longer comparable
    }
    const periods = denominator - previousDenominator.value;
    if (periods <= 0) return NO_READING; // the cgroup saw no CFS period; nothing to divide
    return float32((numerator - previousNumerator.value) / periods);
  }

  /**
   * Forgets keys that no counter reported this round.
   *
   * Without this the map is a leak with the shape of a pod churn rate: every
   * pod that ever ran on a node keeps two entries forever. `keep` is the set of
   * keys the current round produced.
   */
  retain(keep: ReadonlySet<string>): void {
    for (const key of this.#previous.keys()) {
      // The `#n`/`#d` suffix belongs to `ratio` and is not part of the caller's key.
      const base = key.endsWith("#n") || key.endsWith("#d") ? key.slice(0, -2) : key;
      if (!keep.has(base)) this.#previous.delete(key);
    }
  }

  /** Number of remembered readings — the leak assertion in the tests reads this. */
  get size(): number {
    return this.#previous.size;
  }
}
