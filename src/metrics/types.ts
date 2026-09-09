/**
 * The collector's INTERNAL sample model.
 *
 * This file fixes two vocabularies — entity attributes and metric names — and
 * nothing else. It is deliberately free of IO so that both readers (the typed
 * Summary JSON and the line-filtered cAdvisor text) and every consumer (the ring
 * buffer, the encoder that will live behind `SampleSink`) agree on one shape.
 *
 * ─── Internal, not the wire ─────────────────────────────────────────────────
 *
 * The wire frame is defined by the tunnel contract (`@nairotech/yeke-tunnel`,
 * protocol v5): a JSON control message plus a binary frame of `Float32` values
 * in entity x metric order. That encoding is NOT built here. The collector
 * writes `InternalFrame` into a `SampleSink` and the encoder behind that
 * interface is a separate piece of work, published with the contract package.
 * Keeping the two apart is what lets the collector be finished, measured and
 * merged while the wire package is still being written.
 *
 * ─── Why the values are Float32 already ─────────────────────────────────────
 *
 * The wire carries `Float32`. If the collector reasoned in `Float64` and the
 * encoder narrowed at the last moment, every test that compares a derived rate
 * against an expected number would be comparing a value the wire never carries.
 * `Math.fround` is applied at the moment the sample is produced, so what is
 * asserted in a test is byte-identical to what the customer's control plane
 * receives.
 *
 * ─── Why missing is NaN and not zero, and not `null` ────────────────────────
 *
 * "0" and "not measurable" are different sentences, and the product rule is
 * that a screen never draws a lone zero for a number nobody measured
 * (`2026-08-05-yeke-node-metrik-panosu.md`, and the IO zero probe in
 * `2026-09-09-yeke-izleme-toplayici-ve-tel.md` K3). `NaN` is the only value a
 * `Float32Array` slot can hold that says "no reading"; `null` would need a
 * second, parallel channel and would arrive at the same screen through a
 * different door.
 *
 * There is exactly ONE meaning of NaN here — "this interval produced no
 * reading" — and it is reached from three roads that a reader must not have to
 * tell apart: the field is absent, the counter reset inside the interval, or
 * the IO zero probe fired. What the screen needs in order to say WHY is carried
 * beside the values, in `NodeState`, and not inside the number.
 */

/**
 * Entity kinds the collector can produce.
 *
 * `pvc` is not a fourth READ: it falls out of the Summary the collector
 * already fetches, from the `volume[]` entries of every pod that carry a
 * `pvcRef`. An entry without one (emptyDir, configMap, the projected service
 * account token) is measured by the same kubelet and is NOT an entity here —
 * it has no name an operator can look up and no lifetime of its own.
 */
export type EntityKind = "node" | "pod" | "pvc";

/**
 * Metric names, Phase 1 (K3's table).
 *
 * The names are FIXED here and nowhere else: the control plane stores them, the
 * screen labels them and the model reads them, so a rename is a wire change.
 * Reading order of the parts is `family.measure`; the family is the thing an
 * operator groups by when a node is in trouble (cpu, mem, fs, net, io, psi).
 *
 * Units, because a name cannot carry them:
 *
 *  · `cpu.cores`        cores (Summary `usageNanoCores` / 1e9), gauge
 *  · `mem.workingSet`   bytes, gauge
 *  · `mem.available`    bytes, gauge
 *  · `fs.rootUsed`      bytes, gauge — node rootfs
 *  · `fs.imageUsed`     bytes, gauge — node image filesystem
 *  · `fs.ephemeralUsed` bytes, gauge — pod ephemeral-storage
 *  · `fs.used`          bytes, gauge — a PVC's used bytes
 *  · `fs.inodesUsed`    count, gauge — a PVC's used inodes
 *  · `net.rxBps`        bytes per second, DERIVED from a counter
 *  · `net.txBps`        bytes per second, DERIVED from a counter
 *  · `net.errors`       errors per second, DERIVED from a counter (rx+tx)
 *  · `psi.cpu`          `some.avg60`, percent of wall time, gauge
 *  · `psi.mem`          `some.avg60`, percent of wall time, gauge
 *  · `psi.io`           `some.avg60`, percent of wall time, gauge
 *  · `procs`            count, gauge
 *  · `io.readBps`       bytes per second, DERIVED from a counter
 *  · `io.writeBps`      bytes per second, DERIVED from a counter
 *  · `cpu.throttled`    ratio in [0,1], DERIVED from two counters
 *  · `restarts`         count — DECLARED, NOT PRODUCED IN PHASE 1, see below
 *
 * `fs.used` is the PVC's used bytes and it is deliberately NOT `fs.rootUsed`,
 * which already means something else (a node's root filesystem). One name for
 * two filesystems would make "which disk is this" unanswerable from a chart,
 * and the two are never on the same entity, so nothing forces them to share a
 * name. Its denominator (`capacityBytes`) is an ATTRIBUTE, not a series —
 * `fs.capacity`, below.
 *
 * Three of these carry a `Bps` suffix and one does not (`net.errors`) even
 * though both are rates. The suffix is kept where the underlying counter is a
 * BYTE counter, because "rx" alone reads as a packet count to half the people
 * who see it; "errors" has no such ambiguity and `net.errorsPerSecond` would be
 * the longest name in the table for the least confusion removed.
 *
 * `restarts` IS in the K3 table and IS NOT produced by this collector. The
 * count lives in a pod's `status`, `status` is part of the object body, and the
 * identity invariant says these jobs read no object bodies
 * (`2026-09-09-yeke-izleme-kimlik-degismezi.md` K1). The name stays in the
 * vocabulary because the wire dictionary is versioned and a later phase that
 * finds a body-free road must not need a protocol bump to use it; that it is
 * never emitted today is asserted mechanically in `collector.test.ts` rather
 * than left to this comment. The full reasoning, including the two roads that
 * were measured and rejected, is in `owners.ts`.
 */
export const METRIC_NAMES = [
  "cpu.cores",
  "mem.workingSet",
  "mem.available",
  "fs.rootUsed",
  "fs.imageUsed",
  "fs.ephemeralUsed",
  "fs.used",
  "fs.inodesUsed",
  "net.rxBps",
  "net.txBps",
  "net.errors",
  "psi.cpu",
  "psi.mem",
  "psi.io",
  "procs",
  "io.readBps",
  "io.writeBps",
  "cpu.throttled",
  "restarts",
] as const;

export type MetricName = (typeof METRIC_NAMES)[number];

/**
 * Entity attributes — the DENOMINATORS.
 *
 * K3: "a denominator does not travel on the wire as a series, it is an
 * attribute of the entity". Allocatable and capacity change on the timescale of
 * a node joining a cluster; sending them 2880 times a day as a flat line would
 * cost more than every rate put together and would still be the same number.
 *
 * What is NOT here, and why: a pod's `resources.requests` / `resources.limits`.
 * K3 names them as attributes, and the source it names is "the object itself".
 * The collector cannot read that object — a pod's spec is a body, and the
 * closed list of jobs the agent does under its own identity forbids bodies
 * (`2026-09-09-yeke-izleme-kimlik-degismezi.md` K1). The control plane already
 * has that number from a read made under the USER's identity (the existing
 * `PodMetrics` path), which is also the only identity allowed to decide whether
 * that user may see it. So the denominator is joined on the control plane, and
 * the collector's silence here is the invariant working, not a gap.
 */
export const ATTRIBUTE_NAMES = [
  /** node: cores schedulable by the scheduler (`status.allocatable.cpu`). */
  "cpu.allocatable",
  /** node: bytes (`status.allocatable.memory`). */
  "mem.allocatable",
  /** node: bytes (`status.allocatable.ephemeral-storage`). */
  "fs.allocatable",
  /** node: pod slots (`status.allocatable.pods`). */
  "pods.allocatable",
  /** node: cores physically present (`status.capacity.cpu`). */
  "cpu.capacity",
  /** node: bytes (`status.capacity.memory`). */
  "mem.capacity",
  /**
   * bytes — a node's rootfs capacity, or a PVC's `capacityBytes`.
   *
   * One name for two entity kinds, unlike `fs.rootUsed` / `fs.used` above,
   * and the asymmetry is on purpose: a denominator is read as "capacity of
   * the thing this row is about", so it is never ambiguous on a row. A metric
   * is read on a CHART, next to other charts, where the entity's kind is not
   * in front of the reader.
   *
   * ABSENT is a real case, not a defect: some CSI drivers report only
   * `usedBytes` for a volume. The consequence is carried all the way to the
   * screen — no capacity, no ratio, no invented denominator.
   */
  "fs.capacity",
  /** count — a PVC's total inodes (`inodes`); the denominator of `fs.inodesUsed`. */
  "fs.inodes",
] as const;

export type AttributeName = (typeof ATTRIBUTE_NAMES)[number];

/** The controller of an entity after the owner chain has been walked. */
export interface EntityOwner {
  /** `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `ReplicaSet`. */
  readonly kind: string;
  readonly name: string;
  readonly uid?: string;
}

/**
 * One thing the control plane keeps a series for.
 *
 * `id` is the join key on both sides of the wire, and it is built from what the
 * KUBELET reading can produce on its own:
 *
 *  · node -> `node/<nodeName>`   (`NodeStats.nodeName`; the node object supplies
 *                                 the uid as a field, not as the key)
 *  · pod  -> `pod/<uid>`         (`PodStats.podRef.uid`)
 *  · pvc  -> `pvc/<ns>/<name>`   (`VolumeStats.pvcRef`)
 *
 * The PVC key is a NAME and not a uid because the Summary does not carry a
 * PVC's uid, and — unlike a pod — a PersistentVolumeClaim's name is not
 * recycled behind an operator's back: deleting one and creating another with
 * the same name in the same namespace is a deliberate act on a durable
 * object, not the routine churn a rollout produces every day.
 *
 * The rejected alternative was to key everything by uid. It fails for nodes,
 * because the Summary never carries a node uid; the collector would then be
 * unable to name the entity it just measured until the node watch had caught
 * up, and a node that cannot be named cannot be reported as unreachable — which
 * is exactly the moment the operator needs it. Pods go the other way: a name is
 * REUSED after a delete/recreate (a StatefulSet member keeps its name forever),
 * so a name key would silently splice two different pods into one series.
 */
export interface Entity {
  readonly id: string;
  readonly kind: EntityKind;
  readonly name: string;
  readonly namespace?: string;
  readonly uid?: string;
  /** The node this entity lives on; absent for the node entity itself. */
  readonly node?: string;
  readonly owner?: EntityOwner;
  readonly attributes: Readonly<Partial<Record<AttributeName, number>>>;
}

/** One measured value. `value` is `Math.fround`ed; `NaN` means "no reading". */
export interface Sample {
  readonly entity: string;
  readonly metric: MetricName;
  readonly value: number;
}

/**
 * Per-node collection state.
 *
 * These are CODES, not sentences: the control plane and its user interface
 * compose the sentence in the reader's own language (README, "Conventions").
 * The codes are the per-node half of the state list in K5.
 *
 *  · `ok`              both reads succeeded
 *  · `tls-unverified`  the kubelet's server certificate is not signed by the
 *                      cluster CA and `YEKE_KUBELET_INSECURE_TLS` is not set;
 *                      NO data is produced for this node (K4)
 *  · `unauthorized`    401 after the token was re-read and the request retried
 *  · `forbidden`       403 — the ClusterRole lacks `nodes/stats` or
 *                      `nodes/metrics`; the manifest needs re-applying
 *  · `unreachable`     connection refused, DNS, timeout, 5xx
 */
export type NodeStateCode = "ok" | "tls-unverified" | "unauthorized" | "forbidden" | "unreachable";

export interface NodeState {
  readonly node: string;
  readonly state: NodeStateCode;
  /**
   * Foreign text (Node's, undici's) passed through verbatim, never translated
   * and never composed into a sentence by us.
   */
  readonly detail?: string;
  /** False when the kubelet reports no PSI at all: K3 says the series is then never born. */
  readonly psi: boolean;
  /** True when the IO zero probe fired: flat-zero counters while `psi.io` > 0. */
  readonly ioUnmeasurable: boolean;
}

/**
 * The layout of a frame: which entity and which metric each value belongs to.
 *
 * ─── Why a frame is packed and not a list of objects ────────────────────────
 *
 * MEASURED (09.09.2026, `measure.ts`, 50 nodes x 30 pods on this machine): a
 * frame carries 1550 entities and 21 700 values. Held as JavaScript objects --
 * one `Sample` per value, one `Entity` per entity -- a full 60-frame ring cost
 * **402 MiB above baseline**, against the roof document's 64 MiB target. The
 * same 60 frames as `Float32Array`s cost 60 x 87 KiB, about 5 MiB.
 *
 * The 400 MiB was not an accounting subtlety. A `{entity, metric, value}`
 * object is roughly eighty bytes of V8 bookkeeping around four bytes of number,
 * and the ring's whole job is to hold half an hour of them while the tunnel is
 * down -- that is, to hold the maximum for as long as possible. The first
 * version of this file stored the object graph, the harness said 402 MiB, and
 * the design was wrong rather than the target.
 *
 * So a frame is a `Float32Array` plus a LAYOUT, which is exactly the shape K5
 * puts on the wire (values in entity x metric order, `Float32`, missing value
 * `NaN`). The layout is shared: on a cluster where nothing came or went, all 60
 * frames in the ring point at ONE layout object, so the entity dictionary is
 * paid for once instead of sixty times. That sharing is also what makes K5's
 * "dictionary deltas" implementable -- an encoder can tell whether the layout
 * changed by comparing one reference.
 *
 * `signatures` is what makes the sharing safe. Two layouts are the same only if
 * their entities are the same AND those entities' mutable parts (owner,
 * attributes) are unchanged; comparing ids alone would freeze a Deployment's
 * name at whatever it was when the pod set last changed.
 */
export interface FrameLayout {
  readonly entities: readonly Entity[];
  /** Per value index: the entity id. */
  readonly entityIds: readonly string[];
  /** Per value index: the metric. */
  readonly metrics: readonly MetricName[];
  /** Per entity: a cheap comparison key over its mutable parts. */
  readonly signatures: readonly string[];
}

/**
 * One tick's output.
 *
 * `dropped` is the number of frames the ring threw away since the last frame
 * that reached the wire. K5: data loss is never silent -- the count rides on
 * the next frame that gets through, and the control plane turns it into a gap
 * in the series plus a chip on the screen.
 */
export interface InternalFrame {
  readonly seq: number;
  /** Agent clock, milliseconds. The receiver measures its own skew against this. */
  readonly capturedAt: number;
  readonly layout: FrameLayout;
  /** Values in layout order. `NaN` means "no reading". */
  readonly values: Float32Array;
  readonly nodes: readonly NodeState[];
  readonly dropped: number;
  /**
   * True when the apiserver denied one of the three closed-list watches
   * (`nodes`, `pods`, `apps/replicasets`) with 403 on the most recent attempt.
   *
   * This is NOT the same signal as a per-node `forbidden` in `nodes` above:
   * that one is the KUBELET refusing `nodes/stats`/`nodes/metrics` for one
   * node, reported per node because it can be an RBAC boundary inside the
   * fleet. This one is the APISERVER refusing node/pod/ReplicaSet discovery
   * itself — without it the collector cannot even enumerate what to read, so
   * it is a whole-collector fact, not a per-node one, and `collectorStatusOf`
   * turns it into `state: "forbidden"` regardless of what `nodes` says (a node
   * watch denied by RBAC typically means `nodes` is empty anyway, but a
   * mid-session revocation can leave stale, still-answering entries in it).
   */
  readonly apiserverForbidden: boolean;
}

/** A frame's entities. Named so call sites do not reach through the layout. */
export function entitiesOf(frame: InternalFrame): readonly Entity[] {
  return frame.layout.entities;
}

/**
 * Unpacks a frame back into samples.
 *
 * For readers and tests, never on the collector's own path: materialising
 * 21 700 objects is the thing this representation exists to avoid.
 */
export function samplesOf(frame: InternalFrame): Sample[] {
  const samples: Sample[] = [];
  for (let index = 0; index < frame.values.length; index += 1) {
    samples.push({
      entity: frame.layout.entityIds[index]!,
      metric: frame.layout.metrics[index]!,
      value: frame.values[index]!,
    });
  }
  return samples;
}

/** One value out of a frame, or `undefined` when the series is not in it. */
export function frameValue(
  frame: InternalFrame,
  entity: string,
  metric: MetricName,
): number | undefined {
  const { entityIds, metrics } = frame.layout;
  for (let index = 0; index < entityIds.length; index += 1) {
    if (entityIds[index] === entity && metrics[index] === metric) return frame.values[index];
  }
  return undefined;
}

/**
 * A comparison key over the parts of an entity that can change while the entity
 * stays the same: its owner and its denominators. The id and the kind are
 * already compared separately.
 */
function signatureOf(entity: Entity): string {
  const attributes = Object.entries(entity.attributes)
    .sort(([left], [right]) => (left < right ? -1 : 1))
    .map(([key, value]) => `${key}=${value}`)
    .join(",");
  return `${entity.id}\u0000${entity.owner?.kind ?? ""}/${entity.owner?.name ?? ""}\u0000${attributes}`;
}

/**
 * Builds a frame, reusing `previous` when nothing about the layout changed.
 *
 * The reuse is the whole point (see `FrameLayout`): a ring full of frames that
 * each carry their own copy of 1550 entities is the 402 MiB this design
 * replaced.
 */
export function packFrame(input: {
  readonly seq: number;
  readonly capturedAt: number;
  readonly entities: readonly Entity[];
  readonly samples: readonly Sample[];
  readonly nodes: readonly NodeState[];
  readonly previous?: FrameLayout | undefined;
  /** Defaults to `false`: most callers (every existing fixture) do not care. */
  readonly apiserverForbidden?: boolean;
}): InternalFrame {
  const entityIds: string[] = [];
  const metrics: MetricName[] = [];
  const values = new Float32Array(input.samples.length);
  for (let index = 0; index < input.samples.length; index += 1) {
    const sample = input.samples[index]!;
    entityIds.push(sample.entity);
    metrics.push(sample.metric);
    values[index] = sample.value;
  }
  const signatures = input.entities.map(signatureOf);

  const previous = input.previous;
  const unchanged =
    previous !== undefined &&
    previous.entityIds.length === entityIds.length &&
    previous.signatures.length === signatures.length &&
    previous.signatures.every((value, index) => value === signatures[index]) &&
    previous.entityIds.every((value, index) => value === entityIds[index]) &&
    previous.metrics.every((value, index) => value === metrics[index]);

  return {
    seq: input.seq,
    capturedAt: input.capturedAt,
    layout: unchanged ? previous : { entities: input.entities, entityIds, metrics, signatures },
    values,
    nodes: input.nodes,
    dropped: 0,
    apiserverForbidden: input.apiserverForbidden ?? false,
  };
}

/**
 * Where the collector writes.
 *
 * This is the seam between the collector and the wire, and it exists because
 * the two are being built at the same time: `@nairotech/yeke-tunnel` 5.0.0
 * (which carries the `sample` message) is not published yet. The collector is
 * finished, measured and merged against this interface; the encoder that binds
 * it to `tunnel-client.ts` is the second wave.
 *
 * TWO flags, not one, and the distinction is the point:
 *
 *  · `ready` — is there a wire at all? False while the tunnel is down. Frames
 *    accumulate in the ring (K5's 30-minute buffer).
 *  · `busy`  — is a USER request in flight? K5 gives a queued `req` priority
 *    over a sample frame. The collector does not send THIS tick; the ring
 *    already holds the frame, so one tick of yielding costs nothing and needs
 *    no second queue.
 *
 * Collapsing them into one boolean was rejected: the same `false` would then
 * mean "disconnected" and "wait your turn", and every reader downstream would
 * have to guess which. A flag with two meanings is a bug waiting for its
 * second reader.
 *
 * ─── `busy` is bounded on the READER's side, and why that is written here ───
 *
 * "Yielding costs nothing" is true of one tick and false of a hundred. The
 * sentence above was read as a veto, and the veto silenced a cluster for
 * eleven minutes on 09.09.2026 (`collector.ts`, header): the control plane
 * holds long-lived apiserver watches open through the tunnel, so `busy` is not
 * a brief queue — it is the normal state of a control plane with a screen
 * open. The bound lives in `Collector.#drain`, and it is named here because
 * this is the doc comment a future implementer of the sink will read before
 * deciding what `busy` is allowed to mean.
 */
export interface SampleSink {
  readonly ready: boolean;
  readonly busy: boolean;
  /**
   * Hands one frame to the wire.
   *
   * Returns false when the frame was NOT accepted; the collector keeps it in
   * the ring and retries on the next tick. An implementation must not throw —
   * and since 09.09.2026 the collector does not rely on that: a pass that
   * throws is counted and the timer chain runs again either way. The rule
   * stands as a rule; it is no longer the only thing holding the door shut.
   */
  push(frame: InternalFrame): boolean;
}

/** What the wire will carry: `Float32`, applied where the sample is born. */
export function float32(value: number): number {
  return Math.fround(value);
}

/** "No reading." Named so the intent is greppable and never a bare `NaN`. */
export const NO_READING = Number.NaN;
