/**
 * The wire encoder: internal frames become the v5 `sample` message and its
 * binary matrix.
 *
 * This file is the second half of the seam `types.ts` opened with `SampleSink`.
 * The collector produces `InternalFrame`s — a sparse list of
 * `(entity id, metric, value)` triples keyed by NATURAL keys (`node/<name>`,
 * `pod/<uid>`) — and the wire wants something else entirely: a DENSE
 * `entities x samples x metrics` matrix of `Float32`, addressed by small
 * connection-local integers. Everything that turns one into the other lives
 * here, and nothing here touches a socket, a clock or a timer.
 *
 * ─── Why the aliases are connection-local ───────────────────────────────────
 *
 * The natural key is the honest identity of an entity and it is 40 to 60 bytes
 * of text. `entityIds` is written IN FULL on every frame (the contract says so:
 * a frame must be decodable without the frames before it), so at 12 700
 * entities the natural keys alone would be over half a megabyte per minute
 * against a matrix of 51 KB. So the agent hands out integers and the receiver
 * maps them back to its own persistent identity through the dictionary.
 *
 * The dictionary is scoped to the CONNECTION, not to the agent's lifetime, and
 * that is a deliberate narrowing. An alias table that outlived the socket would
 * be a piece of state two processes have to agree on across a network partition
 * they did not observe together: the control plane restarts, forgets the table,
 * and every frame that follows names entities it cannot resolve — silently, and
 * only for the entities that did not change afterwards. Restarting at 1 on
 * every connection costs one full dictionary per reconnect (a few hundred
 * kilobytes on the largest cluster in the roof document) and makes the
 * agreement unnecessary: the first frame of a session always carries
 * everything the frames after it refer to.
 *
 * `seq` does the opposite and does NOT reset, because it answers a different
 * question. A receiver that sees `seq` jump from 412 to 414 knows one frame was
 * lost; a receiver that sees it fall back to 1 knows the AGENT restarted (a new
 * process, an empty ring, no history). Resetting it per connection would fold a
 * reconnect and a restart into the same signal, and only one of the two means
 * the half hour in the ring is gone.
 *
 * ─── What "delta" means here, exactly ───────────────────────────────────────
 *
 * `entities.added` carries an entity when the record the receiver would build
 * from it DIFFERS from the last record we sent for that alias — not merely when
 * the entity is new. A pod that gets adopted by a renamed Deployment, or a node
 * whose allocatable memory changes, keeps its alias and is re-declared. The
 * comparison is over the wire record itself rather than over a summary of it,
 * so a field that starts travelling one day cannot quietly stop triggering a
 * re-declaration (`FrameLayout.signatures` makes the same argument for the
 * layout, and this is its wire-side twin).
 *
 * ─── Why the caller splits and this file decides where ──────────────────────
 *
 * `MAX_SAMPLE_PAYLOAD_BYTES` belongs to the encoder in the contract package and
 * exceeding it is an error there, deliberately: "where to split" is a question
 * about the collection, not about the matrix. The answer is here, and it is
 * "at an entity boundary". Splitting on the time axis instead would produce two
 * frames that each carry the full entity dictionary for half the samples, and
 * the dictionary is the expensive half. Each part carries its OWN `seq` — parts
 * are not fragments of one frame, they are frames over disjoint slices of the
 * cluster, and a receiver that loses one of them loses those entities for that
 * minute rather than the whole minute.
 */
import {
  MAX_SAMPLE_PAYLOAD_BYTES,
  SAMPLE_VALUE_BYTES,
  encodeSampleFrame,
  type SampleCollectorNodeState,
  type SampleCollectorStatus,
  type SampleEntityRecord,
  type SampleFrameInput,
  type SampleMessage,
} from "@nairotech/yeke-tunnel";
import {
  ATTRIBUTE_NAMES,
  METRIC_NAMES,
  type Entity,
  type InternalFrame,
  type MetricName,
  type NodeState,
  type NodeStateCode,
} from "./types.js";

/** One frame ready for the wire: the control message, then the binary payload. */
export interface EncodedSampleFrame {
  readonly message: SampleMessage;
  readonly payload: Uint8Array;
}

export interface SampleEncoderOptions {
  /**
   * The payload ceiling, for the tests that exercise splitting without building
   * a 12 000-pod cluster. Clamped to the contract's own ceiling: a caller
   * cannot widen a limit the receiver also enforces.
   */
  readonly maxPayloadBytes?: number;
}

export interface EncodeOptions {
  /**
   * Frames the CALLER lost after they left the ring.
   *
   * The ring stamps its own drops onto the frame it hands over
   * (`InternalFrame.dropped`), which covers everything lost before the wire.
   * What it cannot see is a frame the wire itself accepted and then could not
   * send — the tunnel client holds one frame back to pair it with the next one,
   * and a disconnect in that window destroys it. Counting it here is what keeps
   * "data loss is never silent" true for that one frame; without it the gap
   * would show up in the control plane's series with nothing explaining it.
   */
  readonly droppedBeforeWire?: number;
}

/** What the dictionary remembers per natural key. */
interface AliasEntry {
  readonly alias: number;
  /** The last record we sent for this alias, serialized; see "What delta means". */
  readonly declaration: string;
}

/**
 * The connection-local encoder.
 *
 * One instance per tunnel client, `reset()` per connection. It is a class and
 * not a function because the dictionary and `seq` are exactly the state a pure
 * function would have to receive and return on every call, and a caller that
 * has to thread that state through by hand is a caller that will one day thread
 * a stale copy.
 */
export class SampleEncoder {
  readonly #maxPayloadBytes: number;
  #aliases = new Map<string, AliasEntry>();
  #nextAlias = 1;
  #seq = 0;

  constructor(options: SampleEncoderOptions = {}) {
    this.#maxPayloadBytes = Math.min(
      options.maxPayloadBytes ?? MAX_SAMPLE_PAYLOAD_BYTES,
      MAX_SAMPLE_PAYLOAD_BYTES,
    );
  }

  /** The `seq` of the last frame handed out. Diagnostic, and asserted by the tests. */
  get seq(): number {
    return this.#seq;
  }

  /** Aliases currently held. Zero right after `reset()`. */
  get dictionarySize(): number {
    return this.#aliases.size;
  }

  /**
   * A new connection: the aliases start again at 1.
   *
   * `seq` is deliberately untouched (see the file header). Calling this while
   * frames are in flight is not a hazard: the sink stops accepting frames the
   * moment the socket closes, so nothing can be encoded between the reset and
   * the next session's first frame.
   */
  reset(): void {
    this.#aliases = new Map();
    this.#nextAlias = 1;
  }

  /**
   * Encodes one wire frame per entity slice.
   *
   * `frames` are the internal frames that share a wire frame, OLDEST FIRST:
   * their `capturedAt` becomes `sampleTimesMs` in the same order, and the
   * matrix's sample axis follows it. Two of them is the normal case (K5: 30
   * second sampling, a frame on the wire every 60 seconds).
   *
   * Returns an empty array only when handed no frames at all. Everything else —
   * a cluster with no entities, a collector that is forbidden, a kubelet fleet
   * that is entirely unreachable — produces ONE empty frame, because the state
   * has to keep flowing when the data cannot (see `collectorStatusOf`).
   */
  encode(frames: readonly InternalFrame[], options: EncodeOptions = {}): EncodedSampleFrame[] {
    const newest = frames[frames.length - 1];
    if (!newest) return [];

    const collector = collectorStatusOf(newest.nodes);
    const dropped =
      frames.reduce((total, frame) => total + frame.dropped, 0) + (options.droppedBeforeWire ?? 0);

    // The entity union, in first-seen order; the NEWEST record for an entity
    // wins, because a re-declaration should carry the fresher owner chain.
    const order: string[] = [];
    const entityById = new Map<string, Entity>();
    for (const frame of frames) {
      for (const entity of frame.layout.entities) {
        if (!entityById.has(entity.id)) order.push(entity.id);
        entityById.set(entity.id, entity);
      }
    }

    // Columns are the metrics that actually appear, in the vocabulary's own
    // order — not `METRIC_NAMES` wholesale. A column nothing wrote is a column
    // of NaN on every row, and `restarts` (declared, never produced in Phase 1)
    // would be exactly that column, 2880 times a day.
    const present = new Set<MetricName>();
    for (const frame of frames) for (const metric of frame.layout.metrics) present.add(metric);
    const metrics = METRIC_NAMES.filter((name) => present.has(name));

    if (order.length === 0 || metrics.length === 0) {
      return [this.#emit(this.#emptyFrame(newest.capturedAt, dropped, collector))];
    }

    const samplesPerEntity = frames.length;
    const columns = metrics.length;
    const columnOf = new Map<MetricName, number>(metrics.map((metric, index) => [metric, index]));
    const rowOf = new Map<string, number>(order.map((id, index) => [id, index]));

    // Row-major `entity x sample x metric`, prefilled with "no reading": the
    // internal frame is SPARSE (a pod has no `psi.cpu`, a node has no
    // `fs.ephemeralUsed`) and every cell nothing writes must say so rather than
    // inherit a zero.
    const cellsPerEntity = samplesPerEntity * columns;
    const values = new Float32Array(order.length * cellsPerEntity).fill(Number.NaN);
    for (let sample = 0; sample < frames.length; sample += 1) {
      const frame = frames[sample]!;
      const { entityIds, metrics: frameMetrics } = frame.layout;
      for (let index = 0; index < frame.values.length; index += 1) {
        const row = rowOf.get(entityIds[index]!);
        const column = columnOf.get(frameMetrics[index]!);
        // A value whose entity is not in the layout's entity list cannot be
        // placed. It should not exist (`packFrame` builds both from the same
        // tick) and it is skipped rather than thrown on: a malformed row must
        // not cost the cluster its whole minute.
        if (row === undefined || column === undefined) continue;
        values[(row * samplesPerEntity + sample) * columns + column] = frame.values[index]!;
      }
    }

    const rows = order.map((id) => this.#alias(entityById.get(id)!));
    const removed = this.#forgetAbsent(rowOf);

    const bytesPerEntity = cellsPerEntity * SAMPLE_VALUE_BYTES;
    const perFrame = Math.max(1, Math.floor(this.#maxPayloadBytes / bytesPerEntity));

    const encoded: EncodedSampleFrame[] = [];
    for (let start = 0; start < rows.length; start += perFrame) {
      const end = Math.min(start + perFrame, rows.length);
      const slice = rows.slice(start, end);
      const first = start === 0;
      encoded.push(
        this.#emit({
          agentTimeMs: newest.capturedAt,
          metrics,
          entities: {
            added: slice.flatMap((row) => (row.declare ? [row.declare] : [])),
            // Removals ride the first part only. They are not tied to a slice —
            // a departed entity has no row anywhere — and repeating them would
            // make the receiver's "forget this alias" idempotent by luck.
            removed: first ? removed : [],
          },
          entityIds: slice.map((row) => row.alias),
          sampleTimesMs: frames.map((frame) => frame.capturedAt),
          values: values.subarray(start * cellsPerEntity, end * cellsPerEntity),
          // Same rule as removals, and for a stronger reason: `dropped` is a
          // COUNTER. On every part it would multiply the outage by the number of
          // parts. `collector` below goes on every part instead, because it is a
          // declaration and re-stating it costs nothing but makes each part
          // independently readable.
          dropped: first ? dropped : 0,
          collector,
        }),
      );
    }
    return encoded;
  }

  /**
   * The frame that carries no data.
   *
   * Its whole reason to exist is the `collector` field (the contract's "the
   * state has to flow when the samples cannot"): a forbidden collector produces
   * nothing and must SAY so, or the receiver cannot tell it apart from an agent
   * that is too old to collect at all. One sample time, no columns, no bytes.
   */
  #emptyFrame(
    capturedAt: number,
    dropped: number,
    collector: SampleCollectorStatus,
  ): Omit<SampleFrameInput, "seq"> {
    return {
      agentTimeMs: capturedAt,
      metrics: [],
      entities: { added: [], removed: this.#forgetAbsent(new Map()) },
      entityIds: [],
      sampleTimesMs: [capturedAt],
      values: new Float32Array(0),
      dropped,
      collector,
    };
  }

  #emit(input: Omit<SampleFrameInput, "seq">): EncodedSampleFrame {
    this.#seq += 1;
    return encodeSampleFrame({ seq: this.#seq, ...input });
  }

  /**
   * The alias for one entity, plus the record to declare when the receiver's
   * copy would be stale.
   */
  #alias(entity: Entity): { alias: number; declare?: SampleEntityRecord } {
    const record = recordOf(entity);
    const declaration = JSON.stringify(record);
    const existing = this.#aliases.get(entity.id);
    if (existing && existing.declaration === declaration) return { alias: existing.alias };

    // An entity that changed keeps its alias: the receiver joins on the natural
    // key anyway, and a new integer would look like a different thing to every
    // reader that only sees the matrix.
    const alias = existing?.alias ?? this.#nextAlias++;
    this.#aliases.set(entity.id, { alias, declaration });
    return { alias, declare: { id: alias, ...record } };
  }

  /** Drops every alias the frame did not mention and returns their ids. */
  #forgetAbsent(present: ReadonlyMap<string, number>): number[] {
    const removed: number[] = [];
    for (const [id, entry] of this.#aliases) {
      if (present.has(id)) continue;
      removed.push(entry.alias);
      this.#aliases.delete(id);
    }
    return removed;
  }
}

/**
 * One entity as the wire declares it — everything except the alias.
 *
 * Built field by field rather than spread from the `Entity`, for two reasons.
 * The order of the keys is what `JSON.stringify` compares in `#alias`, so it
 * has to be fixed rather than inherited from whatever order the collector
 * happened to build the object in. And `owner` is NARROWED: the internal owner
 * carries a uid the wire schema does not declare, which zod would strip on
 * arrival — sending it would be bytes nobody reads.
 *
 * `attrs` is the denominators, and what is NOT in it is documented where it is
 * decided (`ATTRIBUTE_NAMES` in `types.ts`): a pod's requests and limits live in
 * an object body, the agent reads no bodies under its own identity, and the
 * control plane joins them from a read made under the user's identity.
 */
function recordOf(entity: Entity): Omit<SampleEntityRecord, "id"> {
  const attrs: Record<string, number> = {};
  for (const name of ATTRIBUTE_NAMES) {
    const value = entity.attributes[name];
    if (value !== undefined) attrs[name] = value;
  }
  return {
    kind: entity.kind,
    name: entity.name,
    ...(entity.namespace === undefined ? {} : { namespace: entity.namespace }),
    ...(entity.uid === undefined ? {} : { uid: entity.uid }),
    ...(entity.node === undefined ? {} : { node: entity.node }),
    ...(entity.owner === undefined
      ? {}
      : { owner: { kind: entity.owner.kind, name: entity.owner.name } }),
    ...(Object.keys(attrs).length === 0 ? {} : { attrs }),
  };
}

/**
 * The internal per-node code as the wire says it.
 *
 * `unauthorized` has no wire code of its own and is reported as `forbidden`.
 * The two are different HTTP answers (401: this token is not an identity; 403:
 * this identity may not read `nodes/stats`) and they are the SAME sentence for
 * the person who has to fix it — re-apply the manifest, the agent's own
 * credentials are not being accepted by the kubelet. The alternative,
 * `unreachable`, would send that person to the network, which is the one place
 * the fault is not.
 */
function wireNodeState(code: NodeStateCode): SampleCollectorNodeState {
  switch (code) {
    case "ok":
      return "ok";
    case "tls-unverified":
      return "tls-unverified";
    case "unreachable":
      return "unreachable";
    default:
      return "forbidden";
  }
}

/**
 * The collector's declaration about itself, from the per-node states of one
 * tick.
 *
 * ─── Why `active` is the narrow case and not the default ────────────────────
 *
 * The three states are a claim the receiver draws a sentence from, so the
 * question each of them answers has to be exact:
 *
 *  · `forbidden` — nothing answered and everything that refused, refused on
 *    authorization. That is the only shape where "re-apply the manifest" is the
 *    right advice for the whole cluster; one forbidden node among fifty is an
 *    RBAC boundary inside the fleet, not a broken install, and it is reported
 *    per node instead.
 *  · `active` — every known node answered, PSI is readable on all of them and
 *    the IO counters are measurable. Anything less is `degraded`, INCLUDING a
 *    fleet where the kernel supplies no pressure at all: the contract lists
 *    "no IO counter, no PSI" among the reasons for degraded, and a screen that
 *    draws pressure cards has to know the cards will stay empty.
 *  · `degraded` — everything else, including the case where the agent knows of
 *    no node at all. That last one deserves its own sentence: `active` would
 *    claim data is flowing when none is, and the enum has no "I do not know"
 *    (by design — the agent cannot be unsure about its own state, and the
 *    receiver's "I do not know" is the absence of the message). "I have a node
 *    list and it is empty" is a degradation of the collector, whatever the
 *    cause.
 *
 * ─── Why `nodes` carries only the nodes that are NOT ok ─────────────────────
 *
 * The ok ones are already on the wire: each of them is an entity in the
 * dictionary with a full row of values. Repeating 700 names every minute to say
 * "still fine" would cost more than the state field it belongs to. What cannot
 * be inferred is the node that produced NO row, and that is exactly the list.
 *
 * ─── Why `ioMeasurable`/`psiAvailable` are omitted when nothing answered ────
 *
 * The contract separates `false` ("measured, absent") from an absent field
 * ("did not look"), and with no node answering, the honest answer is the second
 * one. A `false` there would be a measurement the agent never made.
 */
export function collectorStatusOf(nodes: readonly NodeState[]): SampleCollectorStatus {
  const answering = nodes.filter((node) => node.state === "ok");
  const failing = nodes
    .filter((node) => node.state !== "ok")
    .map((node) => ({ name: node.node, state: wireNodeState(node.state) }));

  const psiAvailable =
    answering.length === 0 ? undefined : answering.every((node) => node.psi);
  const ioMeasurable =
    answering.length === 0 ? undefined : answering.every((node) => !node.ioUnmeasurable);

  const refused =
    nodes.length > 0 &&
    answering.length === 0 &&
    nodes.every((node) => node.state === "forbidden" || node.state === "unauthorized");
  const healthy =
    answering.length > 0 && failing.length === 0 && psiAvailable === true && ioMeasurable === true;

  return {
    state: refused ? "forbidden" : healthy ? "active" : "degraded",
    ...(failing.length === 0 ? {} : { nodes: failing }),
    ...(ioMeasurable === undefined ? {} : { ioMeasurable }),
    ...(psiAvailable === undefined ? {} : { psiAvailable }),
  };
}
