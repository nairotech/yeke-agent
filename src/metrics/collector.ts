/**
 * The metrics collector: timer, node discovery, two reads per node, one frame.
 *
 * ─── THE CONTRACT WITH THE CONTROL PLANE ────────────────────────────────────
 *
 * The collector runs ONLY when the negotiated tunnel protocol is >= 5.
 *
 * The `sample` message and its binary frame arrive with protocol v5. An older
 * control plane does not know the message; the tunnel contract says an unknown
 * message type is dropped silently, so an agent that collected anyway would
 * spend a customer's CPU and a customer's kubelet requests producing frames
 * that go into a bin. Worse, it would do so invisibly: nothing on either side
 * would report an error.
 *
 * The negotiated version arrives in `welcome.protocol`. The caller
 * (`tunnel-client.ts`, second wave) starts this class only after that
 * handshake, and `shouldCollect()` below is the mechanical form of the rule so
 * that it is a call site and not a remembered sentence. Until then the screen
 * shows the "no collector (agent older than v5)" state from K5's list, which is
 * the honest answer for an old agent as well as for an old control plane.
 *
 * ─── One tick ───────────────────────────────────────────────────────────────
 *
 *  1. For every ready node with an `InternalIP`: GET `/stats/summary`, then
 *     GET `/metrics/cadvisor`. Two requests per node per 30 seconds, and no
 *     more — the kubelet's own cAdvisor housekeeping runs every 10 seconds, so
 *     sampling faster buys no new information (K3, "freshness ceiling").
 *  2. Summary first, because the cAdvisor reading needs it: cAdvisor labels a
 *     series with a pod's NAME, the entity key is its uid, and the Summary is
 *     what maps one to the other for the pods running on this node right now.
 *  3. Counters become rates, gauges are copied, PSI decides whether the IO zero
 *     probe fires, and the whole node either produces data or produces a state.
 *  4. One frame goes into the ring. Then the ring drains, oldest first, for as
 *     long as the sink accepts.
 *
 * ─── Why the frame is built before it is known whether it can be sent ───────
 *
 * The alternative — skip the work when the tunnel is down — saves CPU exactly
 * when nothing else needs it and loses the half hour of history the ring exists
 * to keep. K5's buffer is only worth its memory if something fills it while the
 * wire is gone.
 */
import { IoZeroProbe, readCadvisor } from "./cadvisor.js";
import { CounterRates } from "./counters.js";
import { KubeletClient, type KubeletTarget } from "./kubelet-client.js";
import {
  type MetaRecord,
  type NodeRecord,
  ResourceWatch,
  decodeMeta,
  decodeNode,
  resolveOwner,
} from "./owners.js";
import { DEFAULT_RING_CAPACITY, SampleRing } from "./ring.js";
import { type SummaryDocument, mergePvcReadings, readSummary } from "./summary.js";
import {
  type Entity,
  type FrameLayout,
  type InternalFrame,
  type NodeState,
  type Sample,
  type SampleSink,
  packFrame,
} from "./types.js";
import type { KubeTarget } from "../kube.js";

/** The protocol version that carries the `sample` message (K5). */
export const MIN_CORE_PROTOCOL_FOR_METRICS = 5;

/** The rule above, as something a call site can execute. */
export function shouldCollect(negotiatedProtocol: number): boolean {
  return negotiatedProtocol >= MIN_CORE_PROTOCOL_FOR_METRICS;
}

/** K3: 30 seconds. Faster is wasted; the kubelet does not refresh faster. */
export const DEFAULT_PERIOD_MS = 30_000;

/**
 * How many kubelets are read at once.
 *
 * Not 50. Fifty simultaneous TLS handshakes is a burst of CPU in a component
 * with a 50m budget, and it arrives as a spike rather than as a load. Not 1
 * either: at 50 nodes and a 10 second timeout, a serial pass could take longer
 * than the period it belongs to. Eight keeps a full pass comfortably inside one
 * tick even when several nodes are timing out.
 */
const NODE_CONCURRENCY = 8;

export interface CollectorOptions {
  /** The apiserver connection, from `resolveKubeTarget` — nodes, pods, ReplicaSets. */
  readonly target: KubeTarget;
  readonly kubelet: KubeletClient;
  readonly sink: SampleSink;
  readonly periodMs?: number;
  readonly ringCapacity?: number;
  /**
   * The clock seam.
   *
   * Every timestamp in a frame is the AGENT's clock (K5: the receiver measures
   * its own skew against it). Injecting it is what lets a test assert a derived
   * rate without sleeping, and this repository has already paid for the version
   * of that lesson where a fixture read `Date.now()` through a back door.
   */
  readonly now?: () => number;
  /** Overridden by the tests; production takes the default. */
  readonly ioZeroProbeRounds?: number;
}

export interface CollectorStats {
  readonly ticks: number;
  readonly framesProduced: number;
  readonly framesSent: number;
  readonly ringSize: number;
  readonly droppedPending: number;
  readonly nodesKnown: number;
  readonly entitiesLastFrame: number;
  readonly samplesLastFrame: number;
  /** Failed LIST/WATCH attempts against the apiserver, across the three watches. */
  readonly watchFailures: number;
  /**
   * Which of `nodes`/`pods`/`replicasets` the apiserver most recently denied
   * with 403, right now. Empty in the common case. This is what turns into
   * `apiserverForbidden` on the frame and, from there, `state: "forbidden"`
   * on the wire (`collectorStatusOf`, `wire.ts`).
   */
  readonly apiserverForbidden: readonly string[];
  /** Bytes of sample data the ring is holding right now (exact). */
  readonly ringValueBytes: number;
  /** Distinct layout objects the ring is holding. One means the sharing works. */
  readonly ringLayouts: number;
}

export class Collector {
  readonly #options: CollectorOptions;
  readonly #periodMs: number;
  readonly #now: () => number;
  readonly #ring: SampleRing;
  readonly #rates = new CounterRates();
  readonly #probes = new Map<string, IoZeroProbe>();

  readonly #nodes = new Map<string, NodeRecord>();
  readonly #pods = new Map<string, MetaRecord>();
  /** Pods and ReplicaSets in one index: the owner walk crosses between them. */
  readonly #owners = new Map<string, MetaRecord>();

  #nodeWatch: ResourceWatch<NodeRecord> | undefined;
  #podWatch: ResourceWatch<MetaRecord> | undefined;
  #replicaSetWatch: ResourceWatch<MetaRecord> | undefined;

  /**
   * The previous frame's layout, offered to `packFrame` for reuse.
   *
   * On a cluster where no pod came or went, every frame in the ring points at
   * this one object. That is the difference between a 30-minute buffer costing
   * 5 MiB and costing 402 MiB (measured; see `FrameLayout`).
   */
  #lastLayout: FrameLayout | undefined;

  #timer: NodeJS.Timeout | undefined;
  #running = false;
  #ticking = false;
  #seq = 0;
  #ticks = 0;
  #framesProduced = 0;
  #framesSent = 0;
  #entitiesLastFrame = 0;
  #samplesLastFrame = 0;

  constructor(options: CollectorOptions) {
    this.#options = options;
    this.#periodMs = options.periodMs ?? DEFAULT_PERIOD_MS;
    this.#now = options.now ?? Date.now;
    this.#ring = new SampleRing({ capacity: options.ringCapacity ?? DEFAULT_RING_CAPACITY });
  }

  start(): void {
    if (this.#running) return;
    this.#running = true;

    this.#nodeWatch = new ResourceWatch<NodeRecord>({
      target: this.#options.target,
      path: "/api/v1/nodes",
      resource: "nodes",
      // K4 permits the full node object: addresses, allocatable, conditions.
      metadataOnly: false,
      decode: decodeNode,
      handlers: {
        applied: (node) => {
          this.#nodes.set(node.name, node);
        },
        deleted: (uid) => {
          for (const [name, node] of this.#nodes) if (node.uid === uid) this.#nodes.delete(name);
        },
        resynced: (uids) => {
          for (const [name, node] of this.#nodes) {
            if (node.uid && !uids.has(node.uid)) this.#nodes.delete(name);
          }
        },
      },
    });

    this.#podWatch = this.#metadataWatch("/api/v1/pods", "Pod", "pods", this.#pods);
    this.#replicaSetWatch = this.#metadataWatch(
      "/apis/apps/v1/replicasets",
      "ReplicaSet",
      "replicasets",
      undefined,
    );

    this.#nodeWatch.start();
    this.#podWatch.start();
    this.#replicaSetWatch.start();
    this.#schedule();
  }

  async stop(): Promise<void> {
    this.#running = false;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
    await Promise.all([
      this.#nodeWatch?.stop(),
      this.#podWatch?.stop(),
      this.#replicaSetWatch?.stop(),
    ]);
  }

  stats(): CollectorStats {
    const retained = this.#ring.retained();
    return {
      ticks: this.#ticks,
      framesProduced: this.#framesProduced,
      framesSent: this.#framesSent,
      ringSize: this.#ring.size,
      droppedPending: this.#ring.dropped,
      nodesKnown: this.#nodes.size,
      entitiesLastFrame: this.#entitiesLastFrame,
      samplesLastFrame: this.#samplesLastFrame,
      watchFailures:
        (this.#nodeWatch?.failures ?? 0) +
        (this.#podWatch?.failures ?? 0) +
        (this.#replicaSetWatch?.failures ?? 0),
      apiserverForbidden: this.#apiserverForbiddenResources(),
      ringValueBytes: retained.valueBytes,
      ringLayouts: retained.layouts,
    };
  }

  /**
   * Which of the three closed-list watches the apiserver most recently
   * refused with 403, right now. Empty when none is (the common case, and
   * every case before the manifest goes stale).
   */
  #apiserverForbiddenResources(): readonly string[] {
    const resources: string[] = [];
    if (this.#nodeWatch?.forbidden) resources.push("nodes");
    if (this.#podWatch?.forbidden) resources.push("pods");
    if (this.#replicaSetWatch?.forbidden) resources.push("replicasets");
    return resources;
  }

  /** Feeds the index directly. The measurement harness and the tests use it. */
  seedNode(node: NodeRecord): void {
    this.#nodes.set(node.name, node);
  }

  seedPod(record: MetaRecord): void {
    this.#pods.set(record.uid, record);
    this.#owners.set(record.uid, record);
  }

  seedOwner(record: MetaRecord): void {
    this.#owners.set(record.uid, record);
  }

  #metadataWatch(
    path: string,
    kind: string,
    resource: string,
    into: Map<string, MetaRecord> | undefined,
  ): ResourceWatch<MetaRecord> {
    return new ResourceWatch<MetaRecord>({
      target: this.#options.target,
      metadataOnly: true,
      path,
      resource,
      decode: (raw) => decodeMeta(raw, kind),
      handlers: {
        applied: (record) => {
          this.#owners.set(record.uid, record);
          into?.set(record.uid, record);
        },
        deleted: (uid) => {
          this.#owners.delete(uid);
          into?.delete(uid);
        },
        resynced: (uids) => {
          for (const [uid, record] of this.#owners) {
            if (record.kind === kind && !uids.has(uid)) {
              this.#owners.delete(uid);
              into?.delete(uid);
            }
          }
        },
      },
    });
  }

  #schedule(): void {
    if (!this.#running) return;
    this.#timer = setTimeout(() => {
      void this.tick().finally(() => this.#schedule());
    }, this.#periodMs);
    // The collector must never be the reason a process refuses to exit: the
    // agent's shutdown path is a signal handler, not a drained queue.
    this.#timer.unref?.();
  }

  /**
   * One pass. Public because the tests and the measurement harness drive it
   * directly instead of waiting for wall-clock time to pass.
   */
  async tick(): Promise<InternalFrame | undefined> {
    // A tick that overlaps its predecessor would read a counter twice against
    // one previous reading, and the rate arithmetic would divide by an interval
    // that never happened.
    if (this.#ticking) return undefined;
    this.#ticking = true;
    try {
      const frame = await this.#collect();
      this.#ring.push(frame);
      this.#framesProduced += 1;
      this.#ticks += 1;
      this.#drain();
      return frame;
    } finally {
      this.#ticking = false;
    }
  }

  /** Hands frames to the wire, oldest first, while it accepts them. */
  #drain(): void {
    const { sink } = this.#options;
    // `busy` is K5's priority rule: a queued user request goes first, and the
    // sample frame simply waits in the ring it is already in.
    while (sink.ready && !sink.busy) {
      const frame = this.#ring.peek();
      if (!frame) return;
      // The drop count is stamped at the moment of sending, not of production:
      // it has to describe everything lost up to the frame that carries it.
      const dropped = this.#ring.dropped;
      const stamped = dropped > 0 ? { ...frame, dropped } : frame;
      if (!sink.push(stamped)) return;
      this.#ring.shift();
      if (dropped > 0) this.#ring.takeDropped();
      this.#framesSent += 1;
    }
  }

  async #collect(): Promise<InternalFrame> {
    const capturedAt = this.#now();
    const entities: Entity[] = [];
    const samples: Sample[] = [];
    const nodeStates: NodeState[] = [];
    const liveRateKeys = new Set<string>();

    const targets: KubeletTarget[] = [];
    for (const node of this.#nodes.values()) {
      // A node with no InternalIP cannot be dialled at all (K4). It is reported
      // as unreachable rather than omitted: a node missing from the list looks
      // like a node that was deleted.
      if (!node.address) {
        nodeStates.push({
          node: node.name,
          state: "unreachable",
          detail: "no InternalIP",
          psi: false,
          ioUnmeasurable: false,
        });
        continue;
      }
      targets.push(
        node.port === undefined
          ? { node: node.name, address: node.address }
          : { node: node.name, address: node.address, port: node.port },
      );
    }

    const results = await mapWithConcurrency(targets, NODE_CONCURRENCY, (target) =>
      this.#readNode(target, capturedAt),
    );

    for (const result of results) {
      nodeStates.push(result.state);
      entities.push(...result.entities);
      samples.push(...result.samples);
      for (const key of result.rateKeys) liveRateKeys.add(key);
    }

    // Entities and rate memory follow the same rule: what nothing reported this
    // round is forgotten. Otherwise both grow with the cluster's pod churn and
    // never shrink, which on a busy cluster is a leak with a slow fuse.
    this.#rates.retain(liveRateKeys);

    // An RWX claim is mounted on several NODES at once, so it arrives once per
    // node in the lists just concatenated. `readSummary` already merged the
    // within-node duplicates; this second pass is the cross-node one, and it is
    // the same idempotent function rather than a second rule that could drift
    // from the first (`summary.ts`, `mergePvcReadings`).
    const merged = mergePvcReadings(entities, samples);

    this.#entitiesLastFrame = merged.entities.length;
    this.#samplesLastFrame = merged.samples.length;
    this.#seq += 1;
    const frame = packFrame({
      seq: this.#seq,
      capturedAt,
      entities: merged.entities,
      samples: merged.samples,
      nodes: nodeStates,
      previous: this.#lastLayout,
      apiserverForbidden: this.#apiserverForbiddenResources().length > 0,
    });
    this.#lastLayout = frame.layout;
    return frame;
  }

  async #readNode(
    target: KubeletTarget,
    capturedAt: number,
  ): Promise<{
    state: NodeState;
    entities: Entity[];
    samples: Sample[];
    rateKeys: Set<string>;
  }> {
    const empty = (state: NodeState) => ({
      state,
      entities: [] as Entity[],
      samples: [] as Sample[],
      rateKeys: new Set<string>(),
    });

    const summaryResult = await this.#options.kubelet.summary<SummaryDocument>(target);
    if (summaryResult.state !== "ok") {
      // K4: an unverifiable kubelet produces NO data. Not a partial reading,
      // not the last known values, not zeros.
      return empty({
        node: target.node,
        state: summaryResult.state,
        detail: summaryResult.detail,
        psi: false,
        ioUnmeasurable: false,
      });
    }

    const reading = readSummary(summaryResult.value, {
      readAt: capturedAt,
      rates: this.#rates,
    });

    const entities: Entity[] = [];
    const podIdByName = new Map<string, string>();
    const nodeRecord = this.#nodes.get(target.node);
    for (const entity of reading.entities) {
      if (entity.kind === "node") {
        entities.push({
          ...entity,
          uid: nodeRecord?.uid,
          // The denominators come from the node object, not from the wire (K3).
          attributes: { ...entity.attributes, ...(nodeRecord?.attributes ?? {}) },
        });
        continue;
      }
      // A PVC is namespaced too, and it must NOT enter this index: cAdvisor
      // labels its series with `namespace` + `pod`, so a claim that happens to
      // be named like a pod in the same namespace would hand the pod's disk
      // counters to a volume. It also gets no owner walk — a claim has no uid
      // in the Summary, and it is not a subordinate of a workload (`summary.ts`).
      if (entity.kind === "pvc") {
        entities.push(entity);
        continue;
      }
      if (entity.namespace) podIdByName.set(`${entity.namespace}/${entity.name}`, entity.id);
      const record = entity.uid ? this.#pods.get(entity.uid) : undefined;
      const owner = record ? resolveOwner(this.#owners, record) : undefined;
      entities.push(owner ? { ...entity, owner } : entity);
    }

    const probe = this.#probeFor(target.node);
    const cadvisorResult = await this.#options.kubelet.cadvisor(target, (lines) =>
      readCadvisor(lines, {
        readAt: capturedAt,
        rates: this.#rates,
        nodeName: reading.nodeName,
        podIdByName,
        suppressIo: probe.suppressing,
      }),
    );

    const rateKeys = new Set(reading.rateKeys);
    const samples: Sample[] = [...reading.samples];
    let ioUnmeasurable = probe.suppressing;

    if (cadvisorResult.state === "ok") {
      samples.push(...cadvisorResult.value.samples);
      for (const key of cadvisorResult.value.rateKeys) rateKeys.add(key);
      if (cadvisorResult.value.ioCountersSeen) {
        ioUnmeasurable = probe.observe({
          countersAllZero: cadvisorResult.value.ioCountersAllZero,
          psiIo: reading.psiIo,
        });
      }
    }
    // A cAdvisor read that failed while the Summary succeeded is NOT a node
    // failure: the node's CPU, memory, filesystem, network and pressure are all
    // in hand. Only IO and throttling are missing, and their series are simply
    // absent for this frame. Reporting the node as unreachable here would erase
    // data that was successfully collected.

    return {
      state: {
        node: target.node,
        state: "ok",
        psi: reading.psiPresent,
        ioUnmeasurable,
      },
      entities,
      samples,
      rateKeys,
    };
  }

  #probeFor(node: string): IoZeroProbe {
    let probe = this.#probes.get(node);
    if (!probe) {
      probe = new IoZeroProbe(
        this.#options.ioZeroProbeRounds === undefined
          ? {}
          : { rounds: this.#options.ioZeroProbeRounds },
      );
      this.#probes.set(node, probe);
    }
    return probe;
  }
}

/**
 * Runs `worker` over `items` with a fixed number in flight.
 *
 * Written here rather than pulled in: the boundary gate's rule is that the
 * agent's only YEKE dependency is the wire contract, and a five-line pool is
 * not a reason to widen the third-party surface of a component that runs with
 * elevated RBAC in someone else's cluster.
 */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      const item = items[index];
      if (item === undefined) return;
      results[index] = await worker(item);
    }
  });
  await Promise.all(runners);
  return results;
}
