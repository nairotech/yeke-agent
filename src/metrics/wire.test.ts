/**
 * The wire encoder, measured against the CONTRACT'S OWN decoder.
 *
 * Every assertion about the matrix goes through `decodeSampleFrame` from
 * `@nairotech/yeke-tunnel` rather than through this repository's idea of what
 * the bytes mean. That is the whole point of these tests: the control plane
 * runs that decoder, and a test that re-implemented the indexing here would
 * agree with the encoder about a shape the receiver reads differently — the
 * silent failure the contract's four gates exist to prevent.
 *
 * Nothing here sleeps, opens a socket or reads a clock: the encoder is pure and
 * every timestamp is a number this file chose.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_SAMPLE_PAYLOAD_BYTES,
  SAMPLE_MIN_PROTOCOL_VERSION,
  decodeSampleFrame,
} from "@nairotech/yeke-tunnel";
import { MIN_CORE_PROTOCOL_FOR_METRICS } from "./collector.js";
import {
  type Entity,
  type InternalFrame,
  type MetricName,
  type NodeState,
  type Sample,
  packFrame,
} from "./types.js";
import { SampleEncoder, collectorStatusOf } from "./wire.js";

const START_MS = Date.parse("2026-09-09T00:00:00.000Z");
const PERIOD_MS = 30_000;

const okNode = (name: string): NodeState => ({
  node: name,
  state: "ok",
  psi: true,
  ioUnmeasurable: false,
});

function nodeEntity(name: string, attributes: Entity["attributes"] = {}): Entity {
  return { id: `node/${name}`, kind: "node", name, attributes };
}

function podEntity(uid: string, name: string, options: Partial<Entity> = {}): Entity {
  return {
    id: `pod/${uid}`,
    kind: "pod",
    name,
    namespace: "default",
    uid,
    node: "node-a",
    attributes: {},
    ...options,
  };
}

let sequence = 0;

/** One internal frame, the way `Collector.#collect` builds them. */
function internalFrame(input: {
  readonly capturedAt: number;
  readonly entities: readonly Entity[];
  readonly values: ReadonlyArray<readonly [Entity, MetricName, number]>;
  readonly nodes?: readonly NodeState[];
  readonly dropped?: number;
}): InternalFrame {
  sequence += 1;
  const samples: Sample[] = input.values.map(([entity, metric, value]) => ({
    entity: entity.id,
    metric,
    value: Math.fround(value),
  }));
  const frame = packFrame({
    seq: sequence,
    capturedAt: input.capturedAt,
    entities: input.entities,
    samples,
    nodes: input.nodes ?? [okNode("node-a")],
  });
  return input.dropped ? { ...frame, dropped: input.dropped } : frame;
}

/** One cell out of a decoded frame, by alias and metric name. */
function cell(
  decoded: ReturnType<typeof decodeSampleFrame>,
  alias: number,
  sample: number,
  metric: MetricName,
): number {
  const row = decoded.entityIds.indexOf(alias);
  const column = decoded.metrics.indexOf(metric);
  assert.ok(row >= 0, `alias ${alias} is not in the frame`);
  assert.ok(column >= 0, `${metric} is not a column of this frame`);
  const samplesPerEntity = decoded.sampleTimesMs.length;
  return decoded.values[(row * samplesPerEntity + sample) * decoded.metrics.length + column]!;
}

function decodeAll(
  frames: ReturnType<SampleEncoder["encode"]>,
): ReturnType<typeof decodeSampleFrame>[] {
  return frames.map(({ message, payload }) => decodeSampleFrame(message, payload));
}

test("the threshold the collector uses IS the one the contract declares", () => {
  // Two constants, two questions — "may this collector run" and "may this
  // socket carry a sample" — and one number. They are allowed to be written
  // twice; they are not allowed to differ, and nothing but this line would
  // notice the day one of them moved.
  assert.equal(MIN_CORE_PROTOCOL_FOR_METRICS, SAMPLE_MIN_PROTOCOL_VERSION);
});

test("two internal frames become one wire frame, and every value lands in its own cell", () => {
  const node = nodeEntity("node-a", { "cpu.allocatable": 4 });
  const pod = podEntity("uid-1", "web-1");
  const encoder = new SampleEncoder();

  const encoded = encoder.encode([
    internalFrame({
      capturedAt: START_MS,
      entities: [node, pod],
      values: [
        [node, "cpu.cores", 1.5],
        [node, "mem.workingSet", 1024],
        [pod, "cpu.cores", 0.25],
      ],
    }),
    internalFrame({
      capturedAt: START_MS + PERIOD_MS,
      entities: [node, pod],
      values: [
        [node, "cpu.cores", 2.5],
        [node, "mem.workingSet", 2048],
        [pod, "cpu.cores", 0.5],
      ],
    }),
  ]);

  assert.equal(encoded.length, 1);
  const [decoded] = decodeAll(encoded);
  assert.ok(decoded);
  assert.deepEqual(decoded.sampleTimesMs, [START_MS, START_MS + PERIOD_MS]);
  // Column order is the vocabulary's, not the order the samples arrived in.
  assert.deepEqual(decoded.metrics, ["cpu.cores", "mem.workingSet"]);

  const nodeAlias = decoded.entities.added.find((entry) => entry.kind === "node")!.id;
  const podAlias = decoded.entities.added.find((entry) => entry.kind === "pod")!.id;
  assert.equal(cell(decoded, nodeAlias, 0, "cpu.cores"), 1.5);
  assert.equal(cell(decoded, nodeAlias, 1, "cpu.cores"), 2.5);
  assert.equal(cell(decoded, nodeAlias, 1, "mem.workingSet"), 2048);
  assert.equal(cell(decoded, podAlias, 0, "cpu.cores"), 0.25);
  assert.equal(cell(decoded, podAlias, 1, "cpu.cores"), 0.5);
});

test("a series an entity does not have is NaN in its row, never a zero", () => {
  const node = nodeEntity("node-a");
  const pod = podEntity("uid-1", "web-1");
  const encoder = new SampleEncoder();
  const [decoded] = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS,
        entities: [node, pod],
        // Only the node has pressure; only the pod has ephemeral storage.
        values: [
          [node, "psi.cpu", 12],
          [pod, "fs.ephemeralUsed", 4096],
        ],
      }),
    ]),
  );
  assert.ok(decoded);
  const nodeAlias = decoded.entities.added.find((entry) => entry.kind === "node")!.id;
  const podAlias = decoded.entities.added.find((entry) => entry.kind === "pod")!.id;
  assert.equal(cell(decoded, nodeAlias, 0, "psi.cpu"), 12);
  assert.ok(Number.isNaN(cell(decoded, nodeAlias, 0, "fs.ephemeralUsed")));
  assert.ok(Number.isNaN(cell(decoded, podAlias, 0, "psi.cpu")));
  assert.equal(cell(decoded, podAlias, 0, "fs.ephemeralUsed"), 4096);
});

test("a metric nobody produced is not a column of NaN", () => {
  // `restarts` is in the vocabulary and Phase 1 never emits it (K1: no object
  // bodies). It must not cost 4 bytes per entity per frame for saying nothing.
  const node = nodeEntity("node-a");
  const encoder = new SampleEncoder();
  const [decoded] = decodeAll(
    encoder.encode([
      internalFrame({ capturedAt: START_MS, entities: [node], values: [[node, "cpu.cores", 1]] }),
    ]),
  );
  assert.ok(decoded);
  assert.deepEqual(decoded.metrics, ["cpu.cores"]);
});

test("the first frame declares the whole dictionary and the next declares nothing", () => {
  const node = nodeEntity("node-a", { "cpu.allocatable": 8 });
  const pod = podEntity("uid-1", "web-1", { owner: { kind: "Deployment", name: "web" } });
  const encoder = new SampleEncoder();

  const first = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS,
        entities: [node, pod],
        values: [[node, "cpu.cores", 1]],
      }),
    ]),
  )[0]!;

  assert.equal(first.entities.added.length, 2);
  assert.deepEqual(first.entities.removed, []);
  const declared = first.entities.added.find((entry) => entry.kind === "pod")!;
  assert.deepEqual(declared, {
    id: declared.id,
    kind: "pod",
    name: "web-1",
    namespace: "default",
    uid: "uid-1",
    node: "node-a",
    owner: { kind: "Deployment", name: "web" },
  });
  assert.deepEqual(first.entities.added.find((entry) => entry.kind === "node")!.attrs, {
    "cpu.allocatable": 8,
  });

  const second = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS + PERIOD_MS,
        entities: [node, pod],
        values: [[node, "cpu.cores", 2]],
      }),
    ]),
  )[0]!;

  // Nothing changed, so the dictionary is silent — but the row order is still
  // written in full, because a frame must be decodable on its own.
  assert.deepEqual(second.entities.added, []);
  assert.deepEqual(second.entities.removed, []);
  assert.deepEqual(second.entityIds, first.entityIds);
});

test("a pod that left is removed once, and a new one takes the next alias", () => {
  const node = nodeEntity("node-a");
  const first = podEntity("uid-1", "web-1");
  const second = podEntity("uid-2", "web-2");
  const encoder = new SampleEncoder();

  const before = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS,
        entities: [node, first],
        values: [[node, "cpu.cores", 1]],
      }),
    ]),
  )[0]!;
  const goneAlias = before.entities.added.find((entry) => entry.uid === "uid-1")!.id;

  const after = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS + PERIOD_MS,
        entities: [node, second],
        values: [[node, "cpu.cores", 2]],
      }),
    ]),
  )[0]!;

  assert.deepEqual(after.entities.removed, [goneAlias]);
  const born = after.entities.added.find((entry) => entry.uid === "uid-2")!;
  assert.equal(born.id, 3, "the third entity of this connection is alias 3");
  assert.ok(!after.entityIds.includes(goneAlias));

  const later = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS + 2 * PERIOD_MS,
        entities: [node, second],
        values: [[node, "cpu.cores", 3]],
      }),
    ]),
  )[0]!;
  // Removal is stated once. Repeating it would make the receiver's "forget this
  // alias" idempotent by accident rather than by contract.
  assert.deepEqual(later.entities.removed, []);
});

test("an entity whose owner or denominator changed is re-declared under the SAME alias", () => {
  const node = nodeEntity("node-a", { "mem.allocatable": 16 });
  const pod = podEntity("uid-1", "web-1", { owner: { kind: "Deployment", name: "web" } });
  const encoder = new SampleEncoder();

  const first = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS,
        entities: [node, pod],
        values: [[node, "cpu.cores", 1]],
      }),
    ]),
  )[0]!;
  const podAlias = first.entities.added.find((entry) => entry.uid === "uid-1")!.id;
  const nodeAlias = first.entities.added.find((entry) => entry.kind === "node")!.id;

  const adopted = podEntity("uid-1", "web-1", { owner: { kind: "Deployment", name: "web-v2" } });
  const grown = nodeEntity("node-a", { "mem.allocatable": 32 });
  const second = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS + PERIOD_MS,
        entities: [grown, adopted],
        values: [[grown, "cpu.cores", 2]],
      }),
    ]),
  )[0]!;

  assert.equal(second.entities.added.length, 2);
  assert.deepEqual(
    second.entities.added.find((entry) => entry.uid === "uid-1"),
    {
      id: podAlias,
      kind: "pod",
      name: "web-1",
      namespace: "default",
      uid: "uid-1",
      node: "node-a",
      owner: { kind: "Deployment", name: "web-v2" },
    },
  );
  assert.deepEqual(second.entities.added.find((entry) => entry.kind === "node")!.attrs, {
    "mem.allocatable": 32,
  });
  assert.deepEqual(second.entities.removed, []);
  assert.deepEqual(second.entityIds, [nodeAlias, podAlias]);
});

test("a frame over the ceiling is split at entity boundaries, each part with its own seq", () => {
  const node = nodeEntity("node-a");
  const pods = Array.from({ length: 7 }, (_, index) => podEntity(`uid-${index}`, `web-${index}`));
  const entities = [node, ...pods];
  // Two samples x one metric x 4 bytes = 8 bytes per entity; 24 bytes holds
  // three entities per frame, so eight entities need three parts.
  const encoder = new SampleEncoder({ maxPayloadBytes: 24 });

  const encoded = encoder.encode([
    internalFrame({
      capturedAt: START_MS,
      entities,
      values: entities.map((entity) => [entity, "cpu.cores", 1] as const),
      dropped: 4,
    }),
    internalFrame({
      capturedAt: START_MS + PERIOD_MS,
      entities,
      values: entities.map((entity) => [entity, "cpu.cores", 2] as const),
    }),
  ]);

  assert.equal(encoded.length, 3);
  assert.deepEqual(
    encoded.map((frame) => frame.message.seq),
    [1, 2, 3],
  );
  const decoded = decodeAll(encoded);
  assert.deepEqual(
    decoded.map((frame) => frame.entityIds.length),
    [3, 3, 2],
  );
  for (const { payload } of encoded) {
    assert.ok(payload.byteLength <= 24, `a part carries ${payload.byteLength} bytes`);
    assert.ok(payload.byteLength <= MAX_SAMPLE_PAYLOAD_BYTES);
  }

  // The slices are disjoint and together they are the cluster.
  const seen = decoded.flatMap((frame) => frame.entityIds);
  assert.equal(new Set(seen).size, 8);
  assert.equal(seen.length, 8);
  // Each part declares the entities in ITS OWN slice, and only those.
  for (const frame of decoded) {
    assert.deepEqual(
      frame.entities.added.map((entry) => entry.id),
      frame.entityIds,
    );
  }
  // The drop count is a COUNTER: on every part it would multiply the outage.
  assert.deepEqual(
    decoded.map((frame) => frame.dropped),
    [4, 0, 0],
  );
  // The collector state is a DECLARATION: every part carries it, so a part that
  // arrives alone is still readable.
  assert.equal(decoded.every((frame) => frame.collector?.state === "active"), true);
  // And the values still land where they belong after the split.
  const last = decoded[2]!;
  assert.equal(cell(last, last.entityIds[1]!, 1, "cpu.cores"), 2);
});

test("when nothing could be sampled, an EMPTY frame still carries the state", () => {
  const encoder = new SampleEncoder();
  const forbidden: NodeState[] = [
    { node: "node-a", state: "forbidden", psi: false, ioUnmeasurable: false },
    { node: "node-b", state: "forbidden", psi: false, ioUnmeasurable: false },
  ];
  const encoded = encoder.encode([
    internalFrame({ capturedAt: START_MS, entities: [], values: [], nodes: forbidden }),
    internalFrame({
      capturedAt: START_MS + PERIOD_MS,
      entities: [],
      values: [],
      nodes: forbidden,
    }),
  ]);

  assert.equal(encoded.length, 1);
  const only = encoded[0];
  assert.ok(only);
  const { message, payload } = only;
  assert.equal(message.columns, 0);
  assert.deepEqual(message.entityIds, []);
  assert.deepEqual(message.metrics, []);
  assert.equal(message.payloadBytes, 0);
  assert.equal(payload.byteLength, 0);
  // One sample time, not two: there is no matrix for a second one to index.
  assert.deepEqual(message.sampleTimesMs, [START_MS + PERIOD_MS]);
  assert.deepEqual(message.collector, {
    state: "forbidden",
    nodes: [
      { name: "node-a", state: "forbidden" },
      { name: "node-b", state: "forbidden" },
    ],
  });
  // The empty frame decodes like any other: the receiver has one code path.
  const decoded = decodeSampleFrame(message, payload);
  assert.equal(decoded.values.length, 0);
});

test("a fleet that goes silent has its dictionary withdrawn, not left dangling", () => {
  const node = nodeEntity("node-a");
  const encoder = new SampleEncoder();
  const alias = decodeAll(
    encoder.encode([
      internalFrame({ capturedAt: START_MS, entities: [node], values: [[node, "cpu.cores", 1]] }),
    ]),
  )[0]!.entityIds[0]!;

  const [silent] = encoder.encode([
    internalFrame({
      capturedAt: START_MS + PERIOD_MS,
      entities: [],
      values: [],
      nodes: [{ node: "node-a", state: "unreachable", psi: false, ioUnmeasurable: false }],
    }),
  ]);
  assert.deepEqual(silent!.message.entities.removed, [alias]);
  assert.equal(encoder.dictionarySize, 0);
});

test("what the ring dropped and what the wire lost are ONE number on the frame", () => {
  const node = nodeEntity("node-a");
  const encoder = new SampleEncoder();
  const [frame] = encoder.encode(
    [
      internalFrame({
        capturedAt: START_MS,
        entities: [node],
        values: [[node, "cpu.cores", 1]],
        dropped: 12,
      }),
      internalFrame({
        capturedAt: START_MS + PERIOD_MS,
        entities: [node],
        values: [[node, "cpu.cores", 2]],
      }),
    ],
    { droppedBeforeWire: 3 },
  );
  assert.equal(frame!.message.dropped, 15);
});

test("a new connection restarts the aliases at 1 and re-declares everything; seq does not go back", () => {
  const node = nodeEntity("node-a");
  const pod = podEntity("uid-1", "web-1");
  const encoder = new SampleEncoder();

  const before = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS,
        entities: [node, pod],
        values: [[node, "cpu.cores", 1]],
      }),
    ]),
  )[0]!;
  assert.deepEqual(before.entityIds, [1, 2]);
  const seqBefore = encoder.seq;

  encoder.reset();
  assert.equal(encoder.dictionarySize, 0);

  const after = decodeAll(
    encoder.encode([
      internalFrame({
        capturedAt: START_MS + PERIOD_MS,
        entities: [node, pod],
        values: [[node, "cpu.cores", 2]],
      }),
    ]),
  )[0]!;

  // The aliases are the session's, so they start again...
  assert.deepEqual(after.entityIds, [1, 2]);
  assert.equal(after.entities.added.length, 2);
  // ...and no alias is "removed": the receiver dropped the whole table with the
  // session, and a removal of an id that means something else now would be a lie.
  assert.deepEqual(after.entities.removed, []);
  // ...while `seq` keeps counting, so a receiver can still tell a reconnect
  // (seq continues) from an agent restart (seq back to 1).
  assert.ok(after.seq > seqBefore, `${after.seq} should follow ${seqBefore}`);
});

test("handed no frames at all, the encoder says nothing", () => {
  const encoder = new SampleEncoder();
  assert.deepEqual(encoder.encode([]), []);
  assert.equal(encoder.seq, 0);
});

test("the collector's state is a claim about the whole cluster, per node where it can be", () => {
  assert.deepEqual(collectorStatusOf([okNode("node-a"), okNode("node-b")]), {
    state: "active",
    ioMeasurable: true,
    psiAvailable: true,
  });

  // One node blind: the fleet is degraded and the blind one is NAMED. The ok
  // ones are not repeated — they are already on the wire as entities.
  assert.deepEqual(
    collectorStatusOf([
      okNode("node-a"),
      { node: "node-b", state: "tls-unverified", psi: false, ioUnmeasurable: false },
    ]),
    {
      state: "degraded",
      nodes: [{ name: "node-b", state: "tls-unverified" }],
      ioMeasurable: true,
      psiAvailable: true,
    },
  );

  // 401 has no wire code of its own: it is the same sentence as 403 for the
  // person who has to fix it, and `unreachable` would send them to the network.
  assert.deepEqual(
    collectorStatusOf([{ node: "node-a", state: "unauthorized", psi: false, ioUnmeasurable: false }]),
    { state: "forbidden", nodes: [{ name: "node-a", state: "forbidden" }] },
  );

  // Nothing answered: the two capability fields are ABSENT, because "did not
  // look" and "looked and found none" are different sentences.
  const nothing = collectorStatusOf([
    { node: "node-a", state: "unreachable", psi: false, ioUnmeasurable: false },
  ]);
  assert.equal(nothing.state, "degraded");
  assert.equal("ioMeasurable" in nothing, false);
  assert.equal("psiAvailable" in nothing, false);

  // No node at all is not "active": nothing is flowing, and `active` would
  // claim it is.
  assert.deepEqual(collectorStatusOf([]), { state: "degraded" });

  // A kernel with no pressure, and counters the zero probe silenced: the fleet
  // answers, so the fields are stated, and the state says the picture is partial.
  assert.deepEqual(
    collectorStatusOf([{ node: "node-a", state: "ok", psi: false, ioUnmeasurable: true }]),
    { state: "degraded", ioMeasurable: false, psiAvailable: false },
  );
});
