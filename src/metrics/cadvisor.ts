/**
 * Line filter for the kubelet's `/metrics/cadvisor`.
 *
 * ─── Why this endpoint is read at all, and why only four lines of it ────────
 *
 * K3: the Summary API has no disk IO throughput and no CPU throttling. Both
 * exist only here. Throttling in particular is the most frequent answer to "why
 * is this slow", so the diagnostic story does not work without it.
 *
 * What is NOT built: a Prometheus parser. This endpoint emits thousands of
 * lines per node; a full parse would allocate an object for every one of them
 * so that four families survive. The filter below decides on the first
 * characters of a line and never allocates for the rest — K3's rule is "a line
 * whose prefix does not match is discarded" and the reason is the agent's CPU
 * budget (50m at 50 nodes, roof document section 8).
 *
 * The four families, and why exactly these:
 *
 *  · `container_fs_reads_bytes_total`  / `container_fs_writes_bytes_total`
 *      Disk IO throughput. Counters, per device; the agent divides.
 *  · `container_cpu_cfs_throttled_periods_total` / `container_cpu_cfs_periods_total`
 *      A pair. Their DELTA ratio is the throttling share; the ratio of the
 *      totals would answer a question about the container's whole lifetime.
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
 * pause container's own negligible IO. Which of the two shapes a given kubelet
 * emits is UNMEASURED — no live kubelet was read in the round that wrote this
 * file. Naming the discrepancy is the point: silently implementing one reading
 * of the rule would leave the next reader unable to tell a decision from an
 * oversight.
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
const CFS_PERIODS = "container_cpu_cfs_periods_total";

/** The only prefixes that survive; everything else is dropped without parsing. */
const WANTED = new Set<string>([FS_READS, FS_WRITES, CFS_THROTTLED, CFS_PERIODS]);

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
}

interface Totals {
  reads: number;
  writes: number;
  throttled: number;
  periods: number;
}

function emptyTotals(): Totals {
  return { reads: NO_READING, writes: NO_READING, throttled: NO_READING, periods: NO_READING };
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
  const nodeTotals = emptyTotals();
  const podTotals = new Map<string, Totals>();
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
      // marks it pod-only): a node-wide throttling ratio would average a
      // throttled container together with every idle one and read as "fine".
      if (parsed.name === FS_READS) nodeTotals.reads = add(nodeTotals.reads, parsed.value);
      else if (parsed.name === FS_WRITES) nodeTotals.writes = add(nodeTotals.writes, parsed.value);
      continue;
    }

    const container = parsed.labels.get("container");
    // Empty label = the pod-level cgroup slice; `POD` = the pause container.
    // See this file's header for why both go.
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
      totals = emptyTotals();
      podTotals.set(entity, totals);
    }
    // Containers are summed into their pod, and every device of a container is
    // summed too: an operator asks "how much is this pod writing", not "how
    // much is it writing to /dev/sdb".
    switch (parsed.name) {
      case FS_READS:
        totals.reads = add(totals.reads, parsed.value);
        break;
      case FS_WRITES:
        totals.writes = add(totals.writes, parsed.value);
        break;
      case CFS_THROTTLED:
        totals.throttled = add(totals.throttled, parsed.value);
        break;
      case CFS_PERIODS:
        totals.periods = add(totals.periods, parsed.value);
        break;
      default:
        break;
    }
  }

  const at = Number.isNaN(latestStamp) ? readAt : latestStamp;
  const samples: Sample[] = [];
  const rateKeys = new Set<string>();

  const writeIo = (entity: string, totals: Totals): void => {
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
    if (Number.isNaN(totals.throttled) || Number.isNaN(totals.periods)) continue;
    const key = `${entity}|cpu.throttled`;
    rateKeys.add(key);
    const ratio = rates.ratio(key, totals.throttled, totals.periods, at);
    samples.push({
      entity,
      metric: "cpu.throttled",
      value: Number.isNaN(ratio) ? NO_READING : float32(ratio),
    });
  }

  return { samples, rateKeys, ioCountersSeen, ioCountersAllZero };
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
