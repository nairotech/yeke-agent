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
 *
 * ─── Why nothing here is allowed to be permanent ────────────────────────────
 *
 * Measured, 09.09.2026, on a local k3s: the collector went silent and stayed
 * silent, with the pod healthy, no restart and NOT ONE line in `kubectl logs`.
 * The cause was not a crash. `#drain` refused to hand a frame to the wire while
 * `sink.busy`, `busy` is "the control plane has a request in flight", and the
 * control plane keeps long-lived resource WATCHES open through the tunnel as
 * ordinary requests (CustomResourceDefinitions and APIServices are in the
 * agent's own ClusterRole for exactly that reason). So `busy` was true for
 * minutes at a stretch, the drain was attempted only once per 30-second tick,
 * and a frame reached the control plane only when a tick happened to land in
 * the gap between one watch closing and the next opening.
 *
 * Three rules come out of that morning, and each one is a call site below
 * rather than a remembered sentence:
 *
 *  1. K5's priority rule is a POSTPONEMENT, not a veto. `busy` may hold the
 *     ring back for `BUSY_YIELD_TICKS` ticks and not one more. Because the wire
 *     pairs two internal frames into one message anyway, yielding a single tick
 *     costs no throughput at all — it costs the user's request nothing to wait
 *     for, and it costs the cluster's monitoring nothing to give.
 *  2. Nothing in the tick chain may be able to stop it. `tick()` never rejects,
 *     a pass that hangs is abandoned after `TICK_STALL_TICKS` periods, and the
 *     timer is rescheduled from a chain that cannot reject.
 *  3. Silence is reported. A collector that produces nothing, or produces into
 *     a ring nothing drains, says so within three periods and says WHY — and
 *     one line every ten minutes says what it has been doing when nothing is
 *     wrong. The failure above cost a morning because both of those lines were
 *     missing.
 */
import { IoZeroProbe, readCadvisor } from "./cadvisor.js";
import { CounterRates } from "./counters.js";
import type { KubeletReader, KubeletTarget } from "./kubelet-client.js";
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
  type NodeStateCode,
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

/**
 * One liveness line every ten minutes.
 *
 * Long enough that `kubectl logs yeke-agent` is not a scrolling counter, short
 * enough that an operator opening the log an hour into a problem has six of
 * them to compare. The line is the answer to "is this thing doing anything",
 * which is the question that had no answer on 09.09.2026.
 */
export const DEFAULT_LIVENESS_MS = 600_000;

/**
 * How many ticks a queued user request may postpone the drain.
 *
 * One. K5 says a user request goes first, and one tick is the whole of what
 * that costs: the wire pairs two internal frames into one message
 * (`SAMPLES_PER_WIRE_FRAME`), so a ring drained every second tick puts exactly
 * as many messages on the wire as one drained every tick. Beyond that the rule
 * stops being a priority and becomes an off switch — which is precisely the
 * failure this constant exists to make impossible.
 */
const BUSY_YIELD_TICKS = 1;

/**
 * Periods of nothing reaching the control plane before the collector says so.
 *
 * Three: two consecutive misses are a slow kubelet or a busy tunnel, and
 * warning on those would train the operator to ignore the line.
 */
const SILENCE_TICKS = 3;

/**
 * Periods one collection pass may run before the next one starts without it.
 *
 * Every request inside a pass has its own 10-second ceiling, so four periods is
 * not a timeout for anything that can normally happen — it is the guard against
 * a pass that is not going to finish at all, which would otherwise hold the
 * `#ticking` lock and stop the collector for the life of the process.
 */
const TICK_STALL_TICKS = 4;

export interface CollectorOptions {
  /** The apiserver connection, from `resolveKubeTarget` — nodes, pods, ReplicaSets. */
  readonly target: KubeTarget;
  readonly kubelet: KubeletReader;
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
  /** How often the liveness line is written. Injected so a test need not wait ten minutes. */
  readonly livenessMs?: number;
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
  /**
   * Collection passes that ended in an exception.
   *
   * A pass that throws is COUNTED and dropped, never rethrown: the timer chain
   * is the only thing between a kubelet read and a process that stops
   * collecting, and it is rescheduled from a promise that cannot reject.
   */
  readonly tickErrors: number;
  /** Passes abandoned for running longer than `TICK_STALL_TICKS` periods. */
  readonly tickStalls: number;
  /** Frames the ring has dropped over the collector's whole life (K5's gap count). */
  readonly droppedTotal: number;
  /** What the wire can take right now: `ready`, `busy` (a user request is in flight) or `down`. */
  readonly sinkState: SinkState;
}

/** The three answers `SampleSink` can give, as one word for the log line. */
export type SinkState = "ready" | "busy" | "down";

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
  /**
   * The health timer, and why it is not the tick timer.
   *
   * If the liveness line were written by the tick chain, a dead tick chain
   * would take the report of its own death with it. This one runs on its own
   * interval and can therefore say `ticks=` with a number that has not moved.
   */
  #healthTimer: NodeJS.Timeout | undefined;
  #running = false;
  #ticking = false;
  /**
   * Which pass owns the `#ticking` lock.
   *
   * An abandoned pass eventually finishes, and without this it would release a
   * lock its successor is holding and push a frame captured minutes ago into
   * the middle of the ring.
   */
  #tickToken = 0;
  #tickStartedAt = 0;
  #seq = 0;
  #ticks = 0;
  #tickErrors = 0;
  #tickStalls = 0;
  #framesProduced = 0;
  #framesSent = 0;
  #droppedTotal = 0;
  #entitiesLastFrame = 0;
  #samplesLastFrame = 0;
  /** Consecutive ticks a busy sink has held the ring back. See `BUSY_YIELD_TICKS`. */
  #busySkips = 0;
  #lastFrameAt = 0;
  #lastSentAt = 0;
  #lastLivenessAt = 0;
  /** So the silence warning is written ONCE, on the change, not every period. */
  #warnedSilent = false;
  readonly #livenessMs: number;
  /**
   * Per-node state most recently WRITTEN to the log.
   *
   * Same guard as `ResourceWatch#loggedForbidden` ("yalnız değişince,
   * dakikada bir değil" -- `owners.ts`): without it, a node stuck
   * `tls-unverified` would log once per 30-second tick for as long as the
   * failure lasts, which is how F9 (09.09.2026, Kubespray cluster `c-10`)
   * ended up with a screen that said "TLS doğrulanamadı" and a `kubectl logs`
   * that said nothing at all -- the ONE thing the operator needed was never
   * given a line to live on. A node absent from this map has never been
   * reported as anything but `ok`, which is the correct starting point: a
   * node that is `tls-unverified` on its very FIRST tick is still a change
   * from that assumed-good baseline and must be logged on that first tick,
   * not held back until a second one repeats it.
   */
  readonly #loggedNodeState = new Map<string, NodeStateCode>();

  constructor(options: CollectorOptions) {
    this.#options = options;
    this.#periodMs = options.periodMs ?? DEFAULT_PERIOD_MS;
    this.#now = options.now ?? Date.now;
    this.#livenessMs = options.livenessMs ?? DEFAULT_LIVENESS_MS;
    this.#ring = new SampleRing({ capacity: options.ringCapacity ?? DEFAULT_RING_CAPACITY });
    // Not zero: a collector constructed at T would otherwise look, for the
    // first three periods, like one that has been silent since the epoch.
    const startedAt = this.#now();
    this.#lastFrameAt = startedAt;
    this.#lastSentAt = startedAt;
    this.#lastLivenessAt = startedAt;
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
    this.#startHealthTimer();
  }

  async stop(): Promise<void> {
    this.#running = false;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = undefined;
    if (this.#healthTimer) clearInterval(this.#healthTimer);
    this.#healthTimer = undefined;
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
      tickErrors: this.#tickErrors,
      tickStalls: this.#tickStalls,
      droppedTotal: this.#droppedTotal + this.#ring.dropped,
      sinkState: this.#sinkState(),
    };
  }

  /** Frames the ring is holding right now. The reconnect line reports it. */
  get queuedFrames(): number {
    return this.#ring.size;
  }

  /**
   * Hands the ring to the wire NOW, without waiting for the next tick.
   *
   * Called when the tunnel comes back (`TunnelClient`): K5 says the half hour
   * the ring kept during the outage drains when the wire returns, and "on the
   * next tick, if the control plane happens to be idle at that instant" is not
   * what that sentence means. `force` because the control plane re-opens its
   * watches within milliseconds of the handshake, so waiting for an unbusy
   * moment here is waiting for one that does not come.
   */
  flush(): void {
    this.#drain(true);
    this.#health();
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
      // `catch` BEFORE `finally`, so that the chain this `void` discards can no
      // longer be a rejected promise. `tick()` is written not to reject; this
      // is the second lock on the same door, because an unhandled rejection in
      // Node's default mode ends the process, and the process is the agent.
      void this.tick()
        .catch(() => undefined)
        .finally(() => this.#schedule());
    }, this.#periodMs);
    // The collector must never be the reason a process refuses to exit: the
    // agent's shutdown path is a signal handler, not a drained queue.
    this.#timer.unref?.();
  }

  #startHealthTimer(): void {
    this.#healthTimer = setInterval(() => this.#health(), this.#periodMs);
    this.#healthTimer.unref?.();
  }

  /**
   * One pass. Public because the tests and the measurement harness drive it
   * directly instead of waiting for wall-clock time to pass.
   *
   * It does not reject. A pass that throws is counted and dropped: the caller
   * is a timer chain whose only job is to run again, and there is no version of
   * "the kubelet answered something unparseable" that should end a cluster's
   * monitoring.
   */
  async tick(): Promise<InternalFrame | undefined> {
    const startedAt = this.#now();
    // A tick that overlaps its predecessor would read a counter twice against
    // one previous reading, and the rate arithmetic would divide by an interval
    // that never happened. That is worth yielding for — but not forever: a pass
    // that never settles would hold this lock and every later tick would return
    // here, quietly, for the life of the process.
    if (this.#ticking) {
      if (startedAt - this.#tickStartedAt < TICK_STALL_TICKS * this.#periodMs) return undefined;
      this.#tickStalls += 1;
      console.warn(
        `[metrics] a collection pass has been running for ${startedAt - this.#tickStartedAt} ms; abandoning it and starting a new one`,
      );
    }
    this.#ticking = true;
    this.#tickStartedAt = startedAt;
    this.#tickToken += 1;
    const token = this.#tickToken;
    try {
      const frame = await this.#collect();
      // An abandoned pass that finished late: its successor owns the lock and
      // its reading is minutes old. Dropping it is the point of the token — a
      // frame out of order in the ring is a gap on the receiver's screen.
      if (this.#tickToken !== token) return undefined;
      this.#ring.push(frame);
      this.#framesProduced += 1;
      this.#ticks += 1;
      this.#lastFrameAt = this.#now();
      this.#drain(false);
      return frame;
    } catch (err) {
      this.#tickErrors += 1;
      // Foreign text, verbatim; the operator reading `kubectl logs` is the
      // audience. Every pass that throws gets a line: unlike the retry loop in
      // `ResourceWatch`, this cannot repeat faster than once per period.
      console.warn(
        `[metrics] collection pass failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return undefined;
    } finally {
      if (this.#tickToken === token) this.#ticking = false;
      this.#health();
    }
  }

  /**
   * Hands frames to the wire, oldest first, while it accepts them.
   *
   * `busy` is K5's priority rule: a queued user request goes first, and the
   * sample frame simply waits in the ring it is already in. It waits for
   * `BUSY_YIELD_TICKS` ticks and then goes anyway — see the header for the
   * morning that rule cost when it had no bound.
   */
  #drain(force: boolean): void {
    const { sink } = this.#options;
    if (!sink.ready) return;
    if (sink.busy && !force) {
      this.#busySkips += 1;
      if (this.#busySkips <= BUSY_YIELD_TICKS) return;
    }
    this.#busySkips = 0;
    while (sink.ready) {
      const frame = this.#ring.peek();
      if (!frame) return;
      // The drop count is stamped at the moment of sending, not of production:
      // it has to describe everything lost up to the frame that carries it.
      const dropped = this.#ring.dropped;
      const stamped = dropped > 0 ? { ...frame, dropped } : frame;
      if (!sink.push(stamped)) return;
      this.#ring.shift();
      if (dropped > 0) this.#droppedTotal += this.#ring.takeDropped();
      this.#framesSent += 1;
      this.#lastSentAt = this.#now();
    }
  }

  #sinkState(): SinkState {
    const { sink } = this.#options;
    if (!sink.ready) return "down";
    return sink.busy ? "busy" : "ready";
  }

  /**
   * The two lines this collector writes about itself.
   *
   * Called from the end of every tick AND from its own interval, because the
   * two failures it has to describe are different: a drain that is blocked
   * (ticks still happening) and a tick chain that has stopped (no ticks at
   * all). Only the second one needs a timer of its own, and only the first one
   * can be reported from inside a tick.
   */
  #health(): void {
    const now = this.#now();
    const silenceMs = SILENCE_TICKS * this.#periodMs;
    const producedAgo = now - this.#lastFrameAt;
    const sentAgo = now - this.#lastSentAt;

    let reason: string | undefined;
    if (producedAgo > silenceMs) {
      reason = `no collection pass has completed for ${producedAgo} ms (ticks=${this.#ticks}, errors=${this.#tickErrors})`;
    } else if (this.#ring.size > 0 && sentAgo > silenceMs) {
      reason = `${this.#ring.size} frames have been waiting for ${sentAgo} ms, sink=${this.#sinkState()}`;
    }

    if (reason !== undefined) {
      if (!this.#warnedSilent) {
        this.#warnedSilent = true;
        console.warn(`[metrics] no sample frame is reaching the control plane: ${reason}`);
      }
    } else if (this.#warnedSilent) {
      this.#warnedSilent = false;
      console.warn("[metrics] sample frames are reaching the control plane again");
    }

    if (now - this.#lastLivenessAt < this.#livenessMs) return;
    this.#lastLivenessAt = now;
    console.log(
      `[metrics] ticks=${this.#ticks} frames=${this.#framesProduced} pushed=${this.#framesSent} dropped=${this.#droppedTotal + this.#ring.dropped} sink=${this.#sinkState()}`,
    );
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
        const state: NodeState = {
          node: node.name,
          state: "unreachable",
          detail: "no InternalIP",
          psi: false,
          ioUnmeasurable: false,
        };
        nodeStates.push(state);
        this.#logNodeState(node.name, undefined, state);
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
    const empty = (state: NodeState) => {
      this.#logNodeState(target.node, target.address, state);
      return {
        state,
        entities: [] as Entity[],
        samples: [] as Sample[],
        rateKeys: new Set<string>(),
      };
    };

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

    const state: NodeState = {
      node: target.node,
      state: "ok",
      psi: reading.psiPresent,
      ioUnmeasurable,
    };
    this.#logNodeState(target.node, target.address, state);
    return { state, entities, samples, rateKeys };
  }

  /**
   * Logs a node's TLS or connectivity failure once, on the state CHANGE only
   * -- the same guard as `ResourceWatch#setForbidden` in `owners.ts`
   * ("yalnız değişince, dakikada bir değil"). At the default 30-second
   * period, logging every tick would mean a line every 30 seconds for as
   * long as the failure lasts; the change guard makes it exactly one line per
   * transition regardless of how many ticks the node spends in that state.
   *
   * `tls-unverified` and `unreachable` are the two states this method
   * covers, because they are the two states F9 found completely silent in
   * `kubectl logs` (09.09.2026, Kubespray cluster `c-10`, agent 0.37.0): the
   * screen said "TLS doğrulanamadı" and the log said nothing at all, with no
   * hint of the OpenSSL code, the node's address, or what to do about it.
   * `forbidden` and `unauthorized` are not touched here: `forbidden` on the
   * kubelet path already has no per-node log line before this fix either, and
   * widening this fix's scope to cover it is not what F9 asked for.
   */
  #logNodeState(node: string, address: string | undefined, state: NodeState): void {
    const previous = this.#loggedNodeState.get(node) ?? "ok";
    this.#loggedNodeState.set(node, state.state);
    if (state.state === previous) return;

    const at = address ? `(${address})` : "(no address)";
    if (state.state === "tls-unverified") {
      console.warn(
        `[metrics] kubelet ${node} ${at}: TLS verification failed: ${state.detail}; ` +
          "set YEKE_KUBELET_INSECURE_TLS=true to collect over unverified TLS, or enable kubelet " +
          "serving certificate rotation (kubeadm: serverTLSBootstrap; kubespray: kubelet_rotate_server_certificates)",
      );
      return;
    }
    if (state.state === "unreachable") {
      console.warn(`[metrics] kubelet ${node} ${at}: unreachable: ${state.detail ?? "unknown reason"}`);
      return;
    }
    if (state.state === "ok" && (previous === "tls-unverified" || previous === "unreachable")) {
      console.warn(`[metrics] kubelet ${node} ${at}: recovered from ${previous}, reporting normally again`);
    }
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
