/**
 * Reader for the kubelet's `/stats/summary`.
 *
 * ─── Why this endpoint is the primary source ────────────────────────────────
 *
 * K3: `/stats/summary` is typed JSON, it is the ONLY endpoint that carries
 * per-pod ephemeral storage and PVC fullness, and KEP-2371 commits to not
 * breaking its shape while its data source moves from cAdvisor to CRI. Two
 * things it does not have — disk IO throughput and CPU throttling — are read
 * from `/metrics/cadvisor` instead (`cadvisor.ts`), line-filtered.
 *
 * ─── The field names are Go's, not ours ─────────────────────────────────────
 *
 * Every field name below mirrors `k8s.io/kubelet/pkg/apis/stats/v1alpha1`
 * (`types.go`) exactly, including the two that break the camelCase pattern:
 * `ephemeral-storage` and `process_stats`. They look like typos and they are
 * not. Renaming them into something tidier at the boundary was rejected: the
 * mapping would then live in a translation table that has to be kept in step
 * with an upstream file nobody in this repository reads, and the first time it
 * drifted the symptom would be a metric that is silently absent rather than an
 * error.
 *
 * Every numeric field is a POINTER in Go (`*uint64`), so every one of them can
 * be legitimately absent — `undefined`, not zero. That is why the readers below
 * go through `numberOf()` instead of `?? 0`: a `?? 0` here is how a screen ends
 * up drawing a flat zero line for a metric the kubelet never reported.
 *
 * ─── What is NOT read, on purpose ───────────────────────────────────────────
 *
 *  · `containers[]`. K3: the container list is not summed; the pod-level field
 *    is used. Summing containers would double-count against the pod cgroup's
 *    own accounting and would silently include the pause container.
 *  · `systemContainers[]` (kubelet, runtime, pods). Node totals already contain
 *    them, and they are not entities the product has a screen for.
 *  · `swap`. Not in the Phase 1 metric set.
 *  · `volume[]` / `pvcRef`. Phase 2 (K3's table).
 */
import { CounterRates } from "./counters.js";
import {
  type AttributeName,
  type Entity,
  type MetricName,
  NO_READING,
  type Sample,
  float32,
} from "./types.js";

/* ─── The upstream shape (v1alpha1/types.go) ───────────────────────────────── */

interface PsiData {
  total?: number;
  avg10?: number;
  avg60?: number;
  avg300?: number;
}
interface PsiStats {
  full?: PsiData;
  some?: PsiData;
}
interface CpuStats {
  time?: string;
  usageNanoCores?: number;
  usageCoreNanoSeconds?: number;
  psi?: PsiStats;
}
interface MemoryStats {
  time?: string;
  availableBytes?: number;
  usageBytes?: number;
  workingSetBytes?: number;
  rssBytes?: number;
  psi?: PsiStats;
}
/** `IOStats` carries only a time and a PSI block — there is no throughput here (K3). */
interface IoStats {
  time?: string;
  psi?: PsiStats;
}
interface InterfaceStats {
  name?: string;
  rxBytes?: number;
  rxErrors?: number;
  txBytes?: number;
  txErrors?: number;
}
interface NetworkStats extends InterfaceStats {
  time?: string;
  interfaces?: InterfaceStats[];
}
interface FsStats {
  time?: string;
  availableBytes?: number;
  capacityBytes?: number;
  usedBytes?: number;
  inodesFree?: number;
  inodes?: number;
  inodesUsed?: number;
}
interface RuntimeStats {
  imageFs?: FsStats;
  containerFs?: FsStats;
}
interface RlimitStats {
  time?: string;
  maxpid?: number;
  curproc?: number;
}
interface NodeStats {
  nodeName?: string;
  startTime?: string;
  cpu?: CpuStats;
  memory?: MemoryStats;
  io?: IoStats;
  network?: NetworkStats;
  fs?: FsStats;
  runtime?: RuntimeStats;
  rlimit?: RlimitStats;
}
interface PodReference {
  name?: string;
  namespace?: string;
  uid?: string;
}
interface ProcessStats {
  process_count?: number;
}
interface PodStats {
  podRef?: PodReference;
  startTime?: string;
  cpu?: CpuStats;
  memory?: MemoryStats;
  io?: IoStats;
  network?: NetworkStats;
  "ephemeral-storage"?: FsStats;
  process_stats?: ProcessStats;
}
export interface SummaryDocument {
  node?: NodeStats;
  pods?: PodStats[];
}

/* ─── Reading ──────────────────────────────────────────────────────────────── */

export interface SummaryReading {
  readonly nodeName: string;
  readonly entities: readonly Entity[];
  readonly samples: readonly Sample[];
  /**
   * False when the kubelet reported no PSI field anywhere in this document.
   *
   * K3: "PSI is conditional: if the field is not in the Summary the series is
   * never born". The flag travels to the frame's `NodeState` so the screen can
   * leave the PSI block out entirely instead of drawing three empty charts.
   */
  readonly psiPresent: boolean;
  /**
   * The node's `psi.io` `some.avg60`, or `NO_READING`.
   *
   * The IO zero probe needs it: flat-zero IO counters mean "this node does no
   * disk IO" only if nothing is waiting on IO. Read here because PSI lives in
   * the Summary and the counters live in the cAdvisor text.
   */
  readonly psiIo: number;
  /** Rate keys this document produced; the caller uses them to expire the rest. */
  readonly rateKeys: ReadonlySet<string>;
}

/**
 * A Go `*uint64` reaches JSON as a number or not at all.
 *
 * Anything else (a string, a null, a NaN that survived a bad encoder) is
 * treated as absent rather than coerced. Coercion here would turn a malformed
 * document into a plausible-looking zero, which is the failure mode this
 * product spends the most effort refusing.
 */
function numberOf(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : NO_READING;
}

function has(value: number): boolean {
  return !Number.isNaN(value);
}

/** RFC3339 -> epoch ms, or the fallback when the kubelet did not stamp the block. */
function timeOf(stamp: string | undefined, fallback: number): number {
  if (!stamp) return fallback;
  const parsed = Date.parse(stamp);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/**
 * `some.avg60` — the pressure share of the last minute.
 *
 * `some` and not `full`: `some` means "at least one task was stalled", which is
 * the question an operator asks ("is anything waiting on the disk?"). `full`
 * means every task was stalled at once, which on a node with any idle process
 * is almost never true and would read as a permanent zero. `avg60` and not
 * `avg10` because the sampling period is 30 seconds: a 10-second average is
 * mostly describing an instant the collector did not see.
 */
function pressureOf(psi: PsiStats | undefined): number {
  return numberOf(psi?.some?.avg60);
}

/**
 * Network counters, summed across interfaces.
 *
 * `interfaces[]` is preferred over the inline (default-interface) fields: a pod
 * with a second interface from a CNI plugin would otherwise have half its
 * traffic invisible. The inline fields are the fallback for a kubelet that
 * reports no per-interface breakdown.
 *
 * `lo` is excluded. Loopback bytes are not network traffic in any question this
 * product answers, and a pod talking to its own sidecar would otherwise show
 * traffic it never put on a wire. Whether a kubelet ever reports `lo` in this
 * list is UNMEASURED here — no live kubelet was read in the round that wrote
 * this file — so the exclusion is cheap insurance rather than a fix for a
 * behaviour that was observed.
 */
function networkTotals(network: NetworkStats | undefined): {
  rx: number;
  tx: number;
  errors: number;
} {
  const totals = { rx: NO_READING, tx: NO_READING, errors: NO_READING };
  if (!network) return totals;

  const list =
    network.interfaces && network.interfaces.length > 0 ? network.interfaces : [network];
  for (const item of list) {
    if (item.name === "lo") continue;
    const rx = numberOf(item.rxBytes);
    const tx = numberOf(item.txBytes);
    const rxErrors = numberOf(item.rxErrors);
    const txErrors = numberOf(item.txErrors);
    if (has(rx)) totals.rx = (has(totals.rx) ? totals.rx : 0) + rx;
    if (has(tx)) totals.tx = (has(totals.tx) ? totals.tx : 0) + tx;
    // rx and tx errors are one series (`net.errors`): an operator asking "is
    // this interface dropping things" does not care which direction it was.
    if (has(rxErrors)) totals.errors = (has(totals.errors) ? totals.errors : 0) + rxErrors;
    if (has(txErrors)) totals.errors = (has(totals.errors) ? totals.errors : 0) + txErrors;
  }
  return totals;
}

class SampleWriter {
  readonly samples: Sample[] = [];

  /** Gauges are written only when there is something to write. */
  gauge(entity: string, metric: MetricName, value: number): void {
    if (!has(value)) return;
    this.samples.push({ entity, metric, value: float32(value) });
  }

  /**
   * Rates are written even when the value is `NO_READING`.
   *
   * The asymmetry is deliberate. An absent gauge means "the kubelet does not
   * report this at all" and the series should not exist. An absent rate means
   * "this interval produced no number" for a series that DOES exist — the first
   * reading, a counter reset, a suppressed IO probe. The control plane needs
   * that hole to be explicit, because a silently skipped sample is
   * indistinguishable from a frame that never arrived.
   */
  rate(entity: string, metric: MetricName, value: number): void {
    this.samples.push({ entity, metric, value: has(value) ? float32(value) : NO_READING });
  }
}

/**
 * Turns one Summary document into entities and samples.
 *
 * `rates` is owned by the caller and survives across ticks — that is where the
 * previous counter reading lives. `readAt` is the agent clock at the moment the
 * response was read, used only where the kubelet did not stamp a block itself.
 */
export function readSummary(
  document: SummaryDocument,
  context: { readonly readAt: number; readonly rates: CounterRates },
): SummaryReading {
  const { readAt, rates } = context;
  const nodeName = document.node?.nodeName ?? "";
  const entities: Entity[] = [];
  const writer = new SampleWriter();
  const rateKeys = new Set<string>();
  let psiPresent = false;
  let psiIo = NO_READING;

  const node = document.node;
  if (nodeName && node) {
    const id = `node/${nodeName}`;
    const attributes: Partial<Record<AttributeName, number>> = {};
    const rootCapacity = numberOf(node.fs?.capacityBytes);
    if (has(rootCapacity)) attributes["fs.capacity"] = float32(rootCapacity);
    entities.push({ id, kind: "node", name: nodeName, attributes });

    const cores = numberOf(node.cpu?.usageNanoCores);
    writer.gauge(id, "cpu.cores", has(cores) ? cores / 1e9 : NO_READING);
    writer.gauge(id, "mem.workingSet", numberOf(node.memory?.workingSetBytes));
    writer.gauge(id, "mem.available", numberOf(node.memory?.availableBytes));
    writer.gauge(id, "fs.rootUsed", numberOf(node.fs?.usedBytes));
    writer.gauge(id, "fs.imageUsed", numberOf(node.runtime?.imageFs?.usedBytes));
    // `rlimit.curproc` is the node's process count; the pod equivalent lives in
    // `process_stats` (two different upstream structs for the same question).
    writer.gauge(id, "procs", numberOf(node.rlimit?.curproc));

    const psiCpu = pressureOf(node.cpu?.psi);
    const psiMem = pressureOf(node.memory?.psi);
    psiIo = pressureOf(node.io?.psi);
    if (has(psiCpu) || has(psiMem) || has(psiIo)) psiPresent = true;
    writer.gauge(id, "psi.cpu", psiCpu);
    writer.gauge(id, "psi.mem", psiMem);
    writer.gauge(id, "psi.io", psiIo);

    writeNetwork(writer, rates, rateKeys, id, node.network, readAt);
  }

  for (const pod of document.pods ?? []) {
    const uid = pod.podRef?.uid;
    const name = pod.podRef?.name;
    const namespace = pod.podRef?.namespace;
    // Without a uid there is no stable key, and a pod keyed by name splices two
    // generations of a StatefulSet member into one series. Such an entry is
    // skipped rather than guessed at.
    if (!uid || !name || !namespace) continue;

    const id = `pod/${uid}`;
    entities.push({
      id,
      kind: "pod",
      name,
      namespace,
      uid,
      node: nodeName || undefined,
      attributes: {},
    });

    const cores = numberOf(pod.cpu?.usageNanoCores);
    writer.gauge(id, "cpu.cores", has(cores) ? cores / 1e9 : NO_READING);
    writer.gauge(id, "mem.workingSet", numberOf(pod.memory?.workingSetBytes));
    writer.gauge(id, "mem.available", numberOf(pod.memory?.availableBytes));
    writer.gauge(id, "fs.ephemeralUsed", numberOf(pod["ephemeral-storage"]?.usedBytes));
    writer.gauge(id, "procs", numberOf(pod.process_stats?.process_count));

    const psiCpu = pressureOf(pod.cpu?.psi);
    const psiMem = pressureOf(pod.memory?.psi);
    const podPsiIo = pressureOf(pod.io?.psi);
    if (has(psiCpu) || has(psiMem) || has(podPsiIo)) psiPresent = true;
    writer.gauge(id, "psi.cpu", psiCpu);
    writer.gauge(id, "psi.mem", psiMem);
    writer.gauge(id, "psi.io", podPsiIo);

    writeNetwork(writer, rates, rateKeys, id, pod.network, readAt);
  }

  return {
    nodeName,
    entities,
    samples: writer.samples,
    psiPresent,
    psiIo,
    rateKeys,
  };
}

/**
 * Network is a POD-level metric and there is no container-level equivalent.
 *
 * K3 records an open question here that this file cannot answer: a
 * `hostNetwork` pod reports the NODE's interface counters, so its traffic looks
 * identical to the node's. Whether that is what the kubelet actually does is to
 * be confirmed against a live cluster before the product says anything about it
 * on a screen; nothing here compensates for it, because compensating for an
 * unverified assumption is how a wrong number becomes permanent.
 */
function writeNetwork(
  writer: SampleWriter,
  rates: CounterRates,
  rateKeys: Set<string>,
  entity: string,
  network: NetworkStats | undefined,
  readAt: number,
): void {
  const totals = networkTotals(network);
  // The kubelet's own stamp for this block, not the moment we read the socket:
  // a late tick would otherwise inflate every rate on the node by the delay.
  const at = timeOf(network?.time, readAt);

  for (const [metric, value] of [
    ["net.rxBps", totals.rx],
    ["net.txBps", totals.tx],
    ["net.errors", totals.errors],
  ] as const) {
    if (!has(value)) continue;
    const key = `${entity}|${metric}`;
    rateKeys.add(key);
    writer.rate(entity, metric, rates.rate(key, value, at));
  }
}
