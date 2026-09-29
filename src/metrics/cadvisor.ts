/**
 * Line filter for the kubelet's `/metrics/cadvisor`.
 *
 * ─── Why this endpoint is read at all, and why only five families of it ─────
 *
 * K3: the Summary API has no disk IO throughput and no CPU throttling. Both
 * exist only here. Throttling in particular is the most frequent answer to "why
 * is this slow", so the diagnostic story does not work without it.
 *
 * What is NOT built: a Prometheus parser. This endpoint emits thousands of
 * lines per node; a full parse would allocate an object for every one of them
 * so that five families survive. The filter below decides on the first
 * characters of a line and never allocates for the rest — K3's rule is "a line
 * whose prefix does not match is discarded" and the reason is the agent's CPU
 * budget (50m at 50 nodes, roof document section 8).
 *
 * The five families, and why exactly these:
 *
 *  · `container_fs_reads_bytes_total`  / `container_fs_writes_bytes_total`
 *      Disk IO throughput. Counters, per device; the agent divides.
 *  · `container_cpu_cfs_throttled_periods_total`
 *      Counter, per container. Times the period length and divided by the
 *      elapsed time, it is the share of WALL time the container sat at its
 *      quota (`cpu.throttledWall`; `counters.ts` → `wallShare` has the
 *      arithmetic and the measurement that retired the old ratio).
 *  · `container_spec_cpu_period` / `container_spec_cpu_quota`
 *      Gauges, per container, unstamped. The period is the length of one CFS
 *      slice (100 000 µs unless the kubelet runs with `--cpu-cfs-quota-period`)
 *      and is what turns a count of throttled periods into time. The quota over
 *      the period is the container's CPU limit in cores, which becomes the
 *      pod's `cpu.limit` attribute (see `podCpuLimit`).
 *
 * `container_cpu_cfs_periods_total` is NOT read any more. It was the
 * denominator of the retired ratio (`cpu.throttled`), and the kernel advances
 * it only in periods where the cgroup had runnable work — which is exactly why
 * that ratio answered "how often was it throttled while awake" instead of "how
 * much of the time was it held back". Nothing reads it, so it is not parsed.
 *
 * Shape, as read from a production kubelet (29.09.2026, k8s 1.31, systemd
 * cgroup driver): the throttling counters and `container_spec_cpu_quota` exist
 * ONLY for containers that have a CPU limit; `container_spec_cpu_period` exists
 * for every container, limited or not. The counters carry an exposition
 * timestamp and it DIFFERS between containers of one pod (cAdvisor stamps a
 * container with its own last housekeeping); the spec lines carry none.
 *
 * ─── The pause container, and a discrepancy that is written down rather ─────
 * ─── than smoothed over                                                 ─────
 *
 * K3 says: "eliminate the pause container: `container!=""` in the cAdvisor
 * reading". That rule names a mechanism AND a purpose, and the two only agree
 * if the pause container is emitted with an empty `container` label. In the
 * kubelet/cAdvisor versions where the pause container carries `container="POD"`
 * instead, `container != ""` keeps it and drops the POD-LEVEL roll-up (the
 * cgroup slice, which is the entry with the empty label).
 *
 * Both are excluded here, which satisfies the mechanism (`container != ""`) and
 * the stated purpose (no pause container) at the same time, and costs only the
 * pause container's own negligible IO. Naming the discrepancy is the point:
 * silently implementing one reading of the rule would leave the next reader
 * unable to tell a decision from an oversight.
 *
 * One shape has since been SEEN (29.09.2026, a production kubelet, k8s 1.31,
 * containerd, systemd cgroup driver): the pause container carries an EMPTY
 * `container` label there, told apart from the pod slice only by its `id` and
 * `image`. The `POD` shape was not seen and stays excluded for the kubelets
 * that emit it.
 *
 * ─── `id="/"` is the node ───────────────────────────────────────────────────
 *
 * The root cgroup carries no pod or container label; it is the whole machine,
 * which is exactly the node total K3 asks for. It is recognised by its `id` and
 * not by the ABSENCE of a pod label, because "absent" is also what a malformed
 * line looks like.
 */
import { CounterRates } from "./counters.js";
import { NO_READING, type Sample, float32 } from "./types.js";

const FS_READS = "container_fs_reads_bytes_total";
const FS_WRITES = "container_fs_writes_bytes_total";
const CFS_THROTTLED = "container_cpu_cfs_throttled_periods_total";
const SPEC_PERIOD = "container_spec_cpu_period";
const SPEC_QUOTA = "container_spec_cpu_quota";

/** The only prefixes that survive; everything else is dropped without parsing. */
const WANTED = new Set<string>([FS_READS, FS_WRITES, CFS_THROTTLED, SPEC_PERIOD, SPEC_QUOTA]);

/**
 * The CFS period when a container's `container_spec_cpu_period` line is absent:
 * the kernel's and Kubernetes' default, 100 ms. When the line is there it wins,
 * because `--cpu-cfs-quota-period` can change it per kubelet.
 */
export const DEFAULT_CFS_PERIOD_US = 100_000;

/**
 * Every family here starts with this. The check is a cheap first gate: on a
 * node with 30 pods the vast majority of lines are `container_*` too, so it
 * does not do the heavy lifting — what does is `WANTED`, on the exact name.
 */
const FAMILY_PREFIX = "container_";

interface ParsedLine {
  readonly name: string;
  readonly labels: ReadonlyMap<string, string>;
  readonly value: number;
  /** Exposition timestamp in ms when the endpoint carried one. */
  readonly timestamp?: number;
}

/**
 * Parses `name{a="1",b="2"} 12345 1690000000000`.
 *
 * Written by hand and not with one regular expression because label VALUES may
 * contain escaped quotes and commas — cAdvisor's `name` and `image` labels
 * routinely do. A regular expression that looks for `pod="` anywhere in the
 * line finds it inside another label's value and reports the wrong pod; that
 * failure is silent and produces a series attached to a pod that does not
 * exist.
 *
 * Returns `undefined` for a comment (`#`), a blank line, a family we do not
 * want, or a line the filter cannot make sense of. A malformed line is dropped,
 * never guessed at.
 */
export function parseLine(line: string): ParsedLine | undefined {
  if (line.length === 0 || line.charCodeAt(0) === 35 /* # */) return undefined;
  if (!line.startsWith(FAMILY_PREFIX)) return undefined;

  const brace = line.indexOf("{");
  if (brace < 0) return undefined;
  const name = line.slice(0, brace);
  if (!WANTED.has(name)) return undefined;

  const labels = new Map<string, string>();
  let i = brace + 1;
  for (;;) {
    if (i >= line.length) return undefined;
    if (line.charCodeAt(i) === 125 /* } */) {
      i += 1;
      break;
    }
    const equals = line.indexOf("=", i);
    if (equals < 0) return undefined;
    const key = line.slice(i, equals).trim();
    if (line.charCodeAt(equals + 1) !== 34 /* " */) return undefined;

    let value = "";
    let j = equals + 2;
    for (;;) {
      if (j >= line.length) return undefined;
      const code = line.charCodeAt(j);
      if (code === 92 /* \ */) {
        const next = line[j + 1];
        // The exposition format escapes exactly three characters.
        value += next === "n" ? "\n" : (next ?? "");
        j += 2;
        continue;
      }
      if (code === 34 /* " */) {
        j += 1;
        break;
      }
      value += line[j];
      j += 1;
    }
    labels.set(key, value);
    i = line.charCodeAt(j) === 44 /* , */ ? j + 1 : j;
  }

  const rest = line.slice(i).trim();
  if (rest.length === 0) return undefined;
  const space = rest.indexOf(" ");
  const rawValue = space < 0 ? rest : rest.slice(0, space);
  const value = Number(rawValue);
  if (!Number.isFinite(value)) return undefined;

  if (space < 0) return { name, labels, value };
  const stamp = Number(rest.slice(space + 1).trim());
  return Number.isFinite(stamp)
    ? { name, labels, value, timestamp: stamp }
    : { name, labels, value };
}

export interface CadvisorReading {
  readonly samples: readonly Sample[];
  readonly rateKeys: ReadonlySet<string>;
  /** True when at least one `container_fs_*_bytes_total` line was seen. */
  readonly ioCountersSeen: boolean;
  /** True when every IO counter seen in this reading was exactly zero. */
  readonly ioCountersAllZero: boolean;
  /**
   * Per pod entity: container name -> CPU limit in cores, for every container
   * of that pod that carried a POSITIVE `container_spec_cpu_quota` and a
   * positive `container_spec_cpu_period` in this reading.
   */
  readonly containerLimits: ReadonlyMap<string, ReadonlyMap<string, number>>;
  /**
   * Per pod entity: every real container name any wanted line mentioned —
   * limited or not (`container_spec_cpu_period` is emitted for all of them).
   * `podCpuLimit` uses it to catch a roster that is behind this reading.
   */
  readonly containersSeen: ReadonlyMap<string, ReadonlySet<string>>;
}

interface IoTotals {
  reads: number;
  writes: number;
}

/**
 * One container's CPU lines out of one reading. Every field starts as
 * `NO_READING`; the spec lines arrive AFTER the counters in the exposition
 * (families are sorted), so nothing is computed until the whole text is read.
 */
interface ContainerCpu {
  throttled: number;
  /** The counter line's own exposition timestamp, or `NO_READING`. */
  throttledAt: number;
  periodUs: number;
  quotaUs: number;
}

interface PodTotals extends IoTotals {
  readonly containers: Map<string, ContainerCpu>;
}

function emptyIo(): IoTotals {
  return { reads: NO_READING, writes: NO_READING };
}

function add(current: number, value: number): number {
  return Number.isNaN(current) ? value : current + value;
}

export interface CadvisorContext {
  readonly readAt: number;
  readonly rates: CounterRates;
  readonly nodeName: string;
  /**
   * `<namespace>/<podName>` -> entity id, built from the SAME tick's Summary
   * reading.
   *
   * cAdvisor labels a series with the pod's NAME; the entity key is its uid
   * (`types.ts` explains why). Resolving the two through the Summary rather
   * than through the pod watch is deliberate: the Summary describes what is
   * running on this node right now, at the same instant, so a pod that the
   * watch has not seen yet cannot produce a series attached to nothing — and a
   * pod that only the watch knows about cannot produce one either.
   */
  readonly podIdByName: ReadonlyMap<string, string>;
  /**
   * True while the IO zero probe is suppressing this node.
   *
   * When set, `io.readBps` / `io.writeBps` are written as `NO_READING` instead
   * of the zero the counters claim. The decision is made outside this function
   * (it needs the Summary's PSI), which keeps the reader free of the state that
   * the probe has to carry across ticks.
   */
  readonly suppressIo: boolean;
}

/**
 * Consumes the exposition text line by line and returns only what K3 asks for.
 *
 * The input is an async iterable so the caller can stream the response body:
 * the point of the filter is that the whole document is never in memory at
 * once. A synchronous iterable is accepted too, which is what the tests pass.
 */
export async function readCadvisor(
  lines: AsyncIterable<string> | Iterable<string>,
  context: CadvisorContext,
): Promise<CadvisorReading> {
  const { readAt, rates, nodeName, podIdByName, suppressIo } = context;
  const nodeTotals = emptyIo();
  const podTotals = new Map<string, PodTotals>();
  let latestStamp = NO_READING;
  let ioCountersSeen = false;
  let ioCountersAllZero = true;

  for await (const line of lines) {
    const parsed = parseLine(line);
    if (!parsed) continue;
    if (parsed.timestamp !== undefined) latestStamp = parsed.timestamp;

    const isIo = parsed.name === FS_READS || parsed.name === FS_WRITES;
    if (isIo) {
      ioCountersSeen = true;
      if (parsed.value !== 0) ioCountersAllZero = false;
    }

    const id = parsed.labels.get("id");
    if (id === "/") {
      // The machine root. Throttling is not collected at node level (K3's table
      // marks it pod-only): a node-wide throttling figure would average a
      // throttled container together with every idle one and read as "fine".
      if (parsed.name === FS_READS) nodeTotals.reads = add(nodeTotals.reads, parsed.value);
      else if (parsed.name === FS_WRITES) nodeTotals.writes = add(nodeTotals.writes, parsed.value);
      continue;
    }

    const container = parsed.labels.get("container");
    // Empty label = the pod-level cgroup slice (and, on some kubelets, the
    // pause container); `POD` = the pause container. See this file's header
    // for why both go. For the CPU lines this is also what keeps the pod
    // slice's OWN quota (the sum of its containers') out of the limit sum.
    if (!container || container === "POD") continue;

    const namespace = parsed.labels.get("namespace");
    const pod = parsed.labels.get("pod");
    if (!namespace || !pod) continue;
    const entity = podIdByName.get(`${namespace}/${pod}`);
    // A container whose pod the Summary did not report: it started between the
    // two reads, or it belongs to a pod the kubelet no longer lists. There is
    // no entity to attach it to, and inventing one would put a series under a
    // pod the control plane has never heard of.
    if (entity === undefined) continue;

    let totals = podTotals.get(entity);
    if (!totals) {
      totals = { ...emptyIo(), containers: new Map() };
      podTotals.set(entity, totals);
    }
    let cpu = totals.containers.get(container);
    if (!cpu) {
      cpu = { throttled: NO_READING, throttledAt: NO_READING, periodUs: NO_READING, quotaUs: NO_READING };
      totals.containers.set(container, cpu);
    }
    // IO: containers are summed into their pod, and every device of a
    // container is summed too: an operator asks "how much is this pod
    // writing", not "how much is it writing to /dev/sdb". CPU is NOT summed —
    // it is kept per container and folded with MAX below.
    switch (parsed.name) {
      case FS_READS:
        totals.reads = add(totals.reads, parsed.value);
        break;
      case FS_WRITES:
        totals.writes = add(totals.writes, parsed.value);
        break;
      case CFS_THROTTLED:
        cpu.throttled = parsed.value;
        cpu.throttledAt = parsed.timestamp ?? NO_READING;
        break;
      case SPEC_PERIOD:
        cpu.periodUs = parsed.value;
        break;
      case SPEC_QUOTA:
        cpu.quotaUs = parsed.value;
        break;
      default:
        break;
    }
  }

  const at = Number.isNaN(latestStamp) ? readAt : latestStamp;
  const samples: Sample[] = [];
  const rateKeys = new Set<string>();
  const containerLimits = new Map<string, Map<string, number>>();
  const containersSeen = new Map<string, Set<string>>();

  const writeIo = (entity: string, totals: IoTotals): void => {
    for (const [metric, value] of [
      ["io.readBps", totals.reads],
      ["io.writeBps", totals.writes],
    ] as const) {
      if (Number.isNaN(value)) continue;
      const key = `${entity}|${metric}`;
      rateKeys.add(key);
      // The probe wins over the counter: a flat zero next to disk pressure is
      // not a measurement of zero IO, it is the absence of a measurement (K3).
      const rate = suppressIo ? NO_READING : rates.rate(key, value, at);
      samples.push({ entity, metric, value: Number.isNaN(rate) ? NO_READING : float32(rate) });
    }
  };

  if (nodeName) writeIo(`node/${nodeName}`, nodeTotals);
  for (const [entity, totals] of podTotals) {
    writeIo(entity, totals);
    containersSeen.set(entity, new Set(totals.containers.keys()));

    // ─── cpu.throttledWall: the pod's WORST container ───────────────────────
    //
    // Each container has its own cgroup and counts its own periods, so the
    // shares are not additive: a SUM over containers can exceed 1 and answers
    // no question at all. An AVERAGE dilutes a throttled sidecar with an idle
    // main container and reads "fine" for a pod whose requests are stuck
    // behind that sidecar. The maximum is the same rule the screen already
    // applies one level up (a workload is as bad as its worst pod), taken one
    // level down.
    //
    // A container without the counter has no CPU limit and cannot be
    // throttled; it does not take part. A pod where NO container has the
    // counter gets no series at all — "unlimited" is not "zero throttling",
    // and a column of zeros would say the latter. A container whose own
    // interval produced no number (first reading, restart) is skipped; the
    // pod's value is the worst of the containers that DID produce one, and a
    // hole only when none did.
    let counted = false;
    let worst = NO_READING;
    const limits = new Map<string, number>();
    for (const [name, cpu] of totals.containers) {
      if (cpu.quotaUs > 0 && cpu.periodUs > 0) limits.set(name, cpu.quotaUs / cpu.periodUs);
      if (Number.isNaN(cpu.throttled)) continue;
      counted = true;
      const key = `${entity}|cpu.throttledWall|${name}`;
      rateKeys.add(key);
      const periodUs = cpu.periodUs > 0 ? cpu.periodUs : DEFAULT_CFS_PERIOD_US;
      // The counter's OWN stamp: cAdvisor stamps each container with its own
      // housekeeping instant, and in this ratio the elapsed time IS the
      // denominator — a node-wide stamp would be off by up to the housekeeping
      // spread (seen on a production node: 17 s between a container's stamp
      // and its own pod slice's in one reading).
      const stampedAt = Number.isNaN(cpu.throttledAt) ? readAt : cpu.throttledAt;
      const share = rates.wallShare(key, cpu.throttled, periodUs, stampedAt);
      if (Number.isNaN(share)) continue;
      if (Number.isNaN(worst) || share > worst) worst = share;
    }
    if (limits.size > 0) containerLimits.set(entity, limits);
    if (!counted) continue;
    samples.push({
      entity,
      metric: "cpu.throttledWall",
      value: Number.isNaN(worst) ? NO_READING : float32(worst),
    });
  }

  return { samples, rateKeys, ioCountersSeen, ioCountersAllZero, containerLimits, containersSeen };
}

/**
 * The pod's CPU limit in cores — `cpu.limit` (K2) — or `undefined` when the pod
 * has no finite limit or when this reading cannot tell.
 *
 * A pod's CPU ceiling is the SUM of its containers' limits, and it exists only
 * if EVERY container has one: a single container without a limit can use the
 * whole node, so the pod has no ceiling. That makes the answer depend on
 * knowing the full list of containers, including the ones cAdvisor has no
 * quota line for — and a list built from the quota lines alone would, by
 * construction, never contain a container without a limit. So the roster comes
 * from somewhere else:
 *
 *  · `roster` is the Summary's `pods[].containers[].name` for this pod — the
 *    kubelet's own list of the pod's running containers, which lists a
 *    container whether or not it has a limit (and never the pause container).
 *    It comes from the SAME tick, one request earlier.
 *  · `seen` is every real container any cAdvisor line named for this pod
 *    (`container_spec_cpu_period` is emitted for limited and unlimited
 *    containers alike). A name here that the roster lacks means the two reads
 *    straddled a container start: the roster is behind, and a sum over it
 *    could be missing a term.
 *
 * Every name in the union of the two (and of `limits`) must have a positive
 * limit, and the roster must be non-empty. Anything else — no roster, a
 * container without a quota, a container one side has not seen — returns
 * `undefined` and the attribute is not written. An absent limit reads as "not
 * known"; a wrong one would read as a ceiling the pod does not have.
 *
 * Rejected: counting the pod-level slice's own quota line (its `container`
 * label is empty). Its quota IS the sum of the containers' quotas when all are
 * limited, but whether the kubelet leaves the slice unlimited when one
 * container is unlimited was not measured, and the whole question here is that
 * case.
 */
export function podCpuLimit(
  roster: readonly string[] | undefined,
  limits: ReadonlyMap<string, number> | undefined,
  seen: ReadonlySet<string> | undefined,
): number | undefined {
  if (!roster || roster.length === 0 || !limits) return undefined;
  const names = new Set<string>(roster);
  for (const name of seen ?? []) names.add(name);
  for (const name of limits.keys()) names.add(name);
  let cores = 0;
  for (const name of names) {
    const limit = limits.get(name);
    if (limit === undefined || !(limit > 0)) return undefined;
    cores += limit;
  }
  return float32(cores);
}

/**
 * The IO zero probe (K3), one instance per node.
 *
 * ─── The two zeros ──────────────────────────────────────────────────────────
 *
 * On cgroup v2 the kubelet's embedded cAdvisor can report
 * `container_fs_*_bytes_total` as a permanent zero (cAdvisor #2881, k/k
 * #102285; the release that fixes it could not be established in the round that
 * took this decision). A node that does no disk IO reports the same zero. The
 * two are the same bytes on the wire and completely different sentences on a
 * screen: one is "nothing is happening", the other is "this cluster cannot tell
 * you what is happening".
 *
 * PSI separates them. `psi.io` measures time SPENT WAITING on IO, and it comes
 * from the kernel through a different path (the Summary API) than the counters.
 * Counters flat at zero while something is waiting on the disk is a
 * contradiction that only the broken-counter explanation resolves.
 *
 * ─── Why it takes more than one tick ────────────────────────────────────────
 *
 * A single round of zeros is ordinary: a quiet 30 seconds on an idle node with
 * a brief PSI blip would trip an instantaneous probe and the screen would blame
 * the cluster for a moment of calm. The claim being made is "these counters do
 * not work", which is a claim about the node and not about an interval, so it
 * is only made after it has held for three consecutive readings.
 *
 * It clears on the first non-zero counter, immediately: one real byte disproves
 * the whole claim, and there is no reason to make an operator wait 90 more
 * seconds for a chip to disappear after they fixed their kubelet.
 */
export class IoZeroProbe {
  #consecutiveZeroRounds = 0;
  #suppressing = false;
  readonly #rounds: number;

  constructor(options: { readonly rounds?: number } = {}) {
    this.#rounds = options.rounds ?? 3;
  }

  /** True while IO values for this node must be reported as "no reading". */
  get suppressing(): boolean {
    return this.#suppressing;
  }

  /**
   * Feeds one round's evidence and returns the state for the NEXT reading.
   *
   * The reading that produced the evidence has already been written with the
   * previous state, which is correct: the round in which the probe reaches its
   * threshold is the third round of zeros, and those zeros were already
   * suspect. It costs one tick of a zero reaching the control plane and saves
   * this class from having to re-run the reader.
   */
  observe(evidence: { readonly countersAllZero: boolean; readonly psiIo: number }): boolean {
    if (!evidence.countersAllZero) {
      this.#consecutiveZeroRounds = 0;
      this.#suppressing = false;
      return false;
    }
    // No PSI means no second opinion: the kernel or the kubelet is not
    // reporting pressure, so a zero counter cannot be contradicted and is taken
    // at face value. Suppressing here would turn "we do not know" into a chip
    // on every node of a cluster that simply has no PSI (K3: PSI is
    // conditional).
    if (Number.isNaN(evidence.psiIo) || evidence.psiIo <= 0) {
      this.#consecutiveZeroRounds = 0;
      this.#suppressing = false;
      return false;
    }
    this.#consecutiveZeroRounds += 1;
    this.#suppressing = this.#consecutiveZeroRounds >= this.#rounds;
    return this.#suppressing;
  }
}
