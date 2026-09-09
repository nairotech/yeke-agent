/**
 * The sample path from the agent's side, against a REAL socket.
 *
 * What is measured here is everything `wire.test.ts` cannot see, because all of
 * it is about a connection: whether the collector is started at all, what the
 * control plane receives and in which order, what a reconnect does to the
 * dictionary, and what happens to the frame that was waiting for its partner
 * when the socket died.
 *
 * The control plane is a `ws` server in this process. It is not a stub of the
 * agent's expectations: it speaks the same `welcome` the real one does and it
 * records the bytes as they arrive, in arrival ORDER — which is the one thing a
 * message/payload pair depends on and the one thing a mock built out of method
 * calls would silently get right.
 *
 * The apiserver, on the other hand, is deliberately unreachable (a kubeconfig
 * pointing at a closed port). Nothing here needs it, and the `/version` line the
 * agent logs on connect is that fact being reported rather than hidden.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { WebSocketServer, type WebSocket as CoreSocket } from "ws";
import {
  SAMPLE_FRAME_REQUEST_ID,
  decodeBodyFrame,
  decodeSampleFrame,
  parseControlMessage,
  serializeControlMessage,
  type ControlMessage,
  type SampleMessage,
} from "@nairotech/yeke-tunnel";
import type { AgentConfig } from "./config.js";
import {
  TunnelClient,
  type CollectorFactory,
  type MetricsCollector,
} from "./tunnel-client.js";
import {
  type Entity,
  type InternalFrame,
  type MetricName,
  type Sample,
  type SampleSink,
  packFrame,
} from "./metrics/types.js";

const START_MS = Date.parse("2026-09-09T00:00:00.000Z");
const PERIOD_MS = 30_000;

/**
 * Waits for a condition, not for a duration.
 *
 * The things this file waits on are all events in another process's socket
 * (a connection, a message, a reconnect), and a fixed sleep long enough for a
 * slow machine is a test that measures the machine. The deadline exists only so
 * a broken build fails with a sentence instead of hanging.
 */
async function until(what: string, predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting until ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/**
 * Gives the agent room to do the WRONG thing.
 *
 * Used only by the negative probes ("no frame is sent", "no collector starts").
 * A negative assertion made in the same turn as the trigger would pass even if
 * the code were about to violate it on the next tick.
 */
async function settle(): Promise<void> {
  for (let turn = 0; turn < 20; turn += 1) await new Promise((resolve) => setTimeout(resolve, 5));
}

interface Received {
  readonly control?: ControlMessage;
  readonly binary?: Buffer;
}

interface FakeCore {
  readonly url: string;
  readonly received: Received[];
  /** Connections accepted so far; a reconnect is this number going up. */
  readonly sessions: number;
  samples(): { message: SampleMessage; payload: Buffer }[];
  send(message: ControlMessage): void;
  /** Drops the current session the way a control plane restart does. */
  drop(): void;
  close(): Promise<void>;
}

async function fakeCore(protocol: number | undefined): Promise<FakeCore> {
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  const received: Received[] = [];
  let socket: CoreSocket | undefined;
  let sessions = 0;

  server.on("connection", (connection) => {
    sessions += 1;
    socket = connection;
    connection.on("message", (data, isBinary) => {
      if (isBinary) {
        received.push({ binary: Buffer.from(data as Buffer) });
        return;
      }
      received.push({ control: parseControlMessage(data.toString()) });
    });
    connection.send(
      serializeControlMessage({
        t: "welcome",
        clusterId: "cluster-1",
        sessionId: `session-${sessions}`,
        ...(protocol === undefined ? {} : { protocol }),
      }),
    );
  });
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `ws://127.0.0.1:${port}/tunnel`,
    received,
    get sessions() {
      return sessions;
    },
    samples() {
      const found: { message: SampleMessage; payload: Buffer }[] = [];
      for (let index = 0; index < received.length; index += 1) {
        const message = received[index]?.control;
        if (message?.t !== "sample") continue;
        // The pairing rule, asserted rather than assumed: the binary frame is
        // the NEXT thing on the socket, and its reserved request id is what
        // tells a receiver it is not somebody's response body.
        const next = received[index + 1]?.binary;
        assert.ok(next, `the sample message at ${index} was not followed by a binary frame`);
        const decoded = decodeBodyFrame(next);
        assert.equal(decoded?.requestId, SAMPLE_FRAME_REQUEST_ID);
        found.push({ message, payload: Buffer.from(decoded!.payload) });
      }
      return found;
    },
    send(message) {
      socket?.send(serializeControlMessage(message));
    },
    drop() {
      socket?.terminate();
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const client of server.clients) client.terminate();
        server.close(() => resolve());
      }),
  };
}

let kubeconfigDirectory: string | undefined;

/** A kubeconfig that resolves and points at a closed port; see the file header. */
async function kubeconfig(): Promise<string> {
  if (!kubeconfigDirectory) {
    kubeconfigDirectory = await mkdtemp(join(tmpdir(), "yeke-agent-kubeconfig-"));
    await writeFile(
      join(kubeconfigDirectory, "config"),
      [
        "apiVersion: v1",
        "kind: Config",
        "clusters:",
        "  - name: unreachable",
        "    cluster:",
        "      server: https://127.0.0.1:1",
        "contexts:",
        "  - name: unreachable",
        "    context:",
        "      cluster: unreachable",
        "      user: unreachable",
        "current-context: unreachable",
        "users:",
        "  - name: unreachable",
        "    user:",
        "      token: not-used",
        "",
      ].join("\n"),
    );
  }
  return join(kubeconfigDirectory, "config");
}

let entityCounter = 0;

function podEntity(name: string): Entity {
  entityCounter += 1;
  return {
    id: `pod/uid-${entityCounter}`,
    kind: "pod",
    name,
    namespace: "default",
    uid: `uid-${entityCounter}`,
    node: "node-a",
    attributes: {},
  };
}

let frameCounter = 0;

function frameOf(entities: readonly Entity[], capturedAt: number, metric: MetricName): InternalFrame {
  frameCounter += 1;
  const samples: Sample[] = entities.map((entity) => ({
    entity: entity.id,
    metric,
    value: Math.fround(entity.id.length),
  }));
  return packFrame({
    seq: frameCounter,
    capturedAt,
    entities,
    samples,
    nodes:
      entities.length > 0
        ? [{ node: "node-a", state: "ok", psi: true, ioUnmeasurable: false }]
        : [{ node: "node-a", state: "forbidden", psi: false, ioUnmeasurable: false }],
  });
}

interface Harness {
  readonly core: FakeCore;
  readonly client: TunnelClient;
  /** The sink the collector was handed, once the factory ran. */
  sink: SampleSink | undefined;
  starts: number;
  stops: number;
  close(): Promise<void>;
}

async function harness(
  options: { protocol?: number | undefined; metricsEnabled?: boolean } = {},
): Promise<Harness> {
  process.env.KUBECONFIG = await kubeconfig();
  const core = await fakeCore("protocol" in options ? options.protocol : 5);
  const config: AgentConfig = {
    coreUrl: core.url,
    clusterId: "cluster-1",
    token: "agent-token",
    kubeMode: "kubeconfig",
    reconnectMinMs: 10,
    reconnectMaxMs: 50,
    kubeletInsecureTls: false,
    metricsEnabled: options.metricsEnabled ?? true,
  };

  const state = { sink: undefined as SampleSink | undefined, starts: 0, stops: 0 };
  const createCollector: CollectorFactory = async (context) => {
    state.sink = context.sink;
    const collector: MetricsCollector = {
      start: () => {
        state.starts += 1;
      },
      stop: async () => {
        state.stops += 1;
      },
    };
    return collector;
  };

  const client = new TunnelClient(config, { createCollector });
  await client.start();
  await until("the control plane has a session", () => core.sessions > 0);

  return {
    core,
    client,
    get sink() {
      return state.sink;
    },
    get starts() {
      return state.starts;
    },
    get stops() {
      return state.stops;
    },
    async close() {
      await client.stop();
      await core.close();
    },
  };
}

test.after(async () => {
  if (kubeconfigDirectory) await rm(kubeconfigDirectory, { recursive: true, force: true });
});

test("a control plane that cannot read samples gets no collector at all", async () => {
  const h = await harness({ protocol: 4 });
  try {
    await settle();
    assert.equal(h.starts, 0, "the collector started against a v4 control plane");
    assert.equal(h.sink, undefined, "the collector was even built");
    assert.deepEqual(h.core.samples(), []);
    // The rest of the tunnel is unaffected: v4 is a supported peer, not a fault.
    assert.equal(h.client.protocolVersion, 4);
  } finally {
    await h.close();
  }
});

test("a v3 control plane (no `protocol` field at all) gets no collector either", async () => {
  const h = await harness({ protocol: undefined });
  try {
    await settle();
    assert.equal(h.client.protocolVersion, 3, "an absent field must read as v3, not as v5");
    assert.equal(h.starts, 0);
  } finally {
    await h.close();
  }
});

test("YEKE_METRICS_ENABLED=false stops the collector before it reads anything", async () => {
  const h = await harness({ metricsEnabled: false });
  try {
    await settle();
    assert.equal(h.client.protocolVersion, 5, "the switch must not affect the handshake");
    assert.equal(h.starts, 0);
    assert.equal(h.sink, undefined, "the factory ran despite the switch");
  } finally {
    await h.close();
  }
});

test("on v5 the collector starts and its first frame carries the whole dictionary", async () => {
  const h = await harness();
  try {
    await until("the collector has started", () => h.starts === 1);
    const sink = h.sink!;
    assert.equal(sink.ready, true);

    const pods = [podEntity("web-1"), podEntity("web-2")];
    // The first frame is held back for its partner: one wire frame per 60
    // seconds carries two samples per entity.
    assert.equal(sink.push(frameOf(pods, START_MS, "cpu.cores")), true);
    await settle();
    assert.deepEqual(h.core.samples(), []);

    assert.equal(sink.push(frameOf(pods, START_MS + PERIOD_MS, "cpu.cores")), true);
    await until("the sample frame arrived", () => h.core.samples().length === 1);

    const [sample] = h.core.samples();
    const decoded = decodeSampleFrame(sample!.message, sample!.payload);
    assert.equal(decoded.seq, 1);
    assert.deepEqual(decoded.sampleTimesMs, [START_MS, START_MS + PERIOD_MS]);
    assert.deepEqual(
      decoded.entities.added.map((entry) => entry.name),
      ["web-1", "web-2"],
    );
    assert.deepEqual(decoded.entityIds, [1, 2]);
    assert.equal(decoded.collector?.state, "active");
    assert.equal(h.client.metricsStats.framesSent, 1);
  } finally {
    await h.close();
  }
});

test("a frame too big for one payload reaches the wire as several, each under the ceiling", async () => {
  const h = await harness();
  try {
    await until("the collector has started", () => h.starts === 1);
    const sink = h.sink!;

    // One metric, two samples: 8 bytes per entity. 9000 entities is 72 000
    // bytes, above the 64 KiB ceiling and below twice it.
    const pods = Array.from({ length: 9000 }, (_, index) => podEntity(`web-${index}`));
    sink.push(frameOf(pods, START_MS, "cpu.cores"));
    sink.push(frameOf(pods, START_MS + PERIOD_MS, "cpu.cores"));
    await until("both parts arrived", () => h.core.samples().length === 2);

    const parts = h.core.samples();
    assert.deepEqual(
      parts.map((part) => part.message.seq),
      [1, 2],
    );
    let entities = 0;
    for (const part of parts) {
      assert.ok(part.payload.byteLength <= 64 * 1024, `a part carries ${part.payload.byteLength}`);
      // Every part decodes on its own — that is what a separate `seq` means.
      entities += decodeSampleFrame(part.message, part.payload).entityIds.length;
    }
    assert.equal(entities, 9000);
  } finally {
    await h.close();
  }
});

test("a collector that can measure nothing still says so, every round", async () => {
  const h = await harness();
  try {
    await until("the collector has started", () => h.starts === 1);
    const sink = h.sink!;

    sink.push(frameOf([], START_MS, "cpu.cores"));
    sink.push(frameOf([], START_MS + PERIOD_MS, "cpu.cores"));
    await until("the empty frame arrived", () => h.core.samples().length === 1);

    const [sample] = h.core.samples();
    assert.equal(sample!.message.columns, 0);
    assert.deepEqual(sample!.message.entityIds, []);
    assert.equal(sample!.message.payloadBytes, 0);
    // A zero-length binary frame is still a frame on the wire, and the receiver
    // pairs it with the message the same way.
    assert.equal(sample!.payload.byteLength, 0);
    assert.deepEqual(sample!.message.collector, {
      state: "forbidden",
      nodes: [{ name: "node-a", state: "forbidden" }],
    });
  } finally {
    await h.close();
  }
});

test("a user request in the queue makes the sink BUSY, and cancelling it frees the queue", async () => {
  const h = await harness();
  try {
    await until("the collector has started", () => h.starts === 1);
    const sink = h.sink!;
    assert.equal(sink.busy, false);

    // A request with a body and no `reqend` stays in flight: the handler is
    // waiting for bytes the control plane has not sent. That is the shape of a
    // queued user request, without needing an apiserver to answer it.
    h.core.send({
      t: "req",
      id: 7,
      method: "GET",
      path: "/api/v1/pods",
      headers: {},
      hasBody: true,
    });
    await until("the request is in flight", () => h.client.inFlightCount === 1);
    assert.equal(sink.busy, true, "a queued user request must delay the sample frame");
    // `ready` is a different question and must not move with it.
    assert.equal(sink.ready, true);

    h.core.send({ t: "cancel", id: 7 });
    await until("the request is gone", () => h.client.inFlightCount === 0);
    assert.equal(sink.busy, false);
  } finally {
    await h.close();
  }
});

test("a reconnect restarts the dictionary, keeps counting seq, and counts the frame it lost", async () => {
  const h = await harness();
  try {
    await until("the collector has started", () => h.starts === 1);
    const sink = h.sink!;
    const pods = [podEntity("web-1"), podEntity("web-2")];

    sink.push(frameOf(pods, START_MS, "cpu.cores"));
    sink.push(frameOf(pods, START_MS + PERIOD_MS, "cpu.cores"));
    await until("the first frame arrived", () => h.core.samples().length === 1);

    // A third frame is now held, waiting for a partner that will never come.
    sink.push(frameOf(pods, START_MS + 2 * PERIOD_MS, "cpu.cores"));

    h.core.drop();
    await until("the socket is down", () => sink.ready === false);
    // While there is no wire, the sink refuses and the collector keeps its
    // frames in the ring.
    assert.equal(sink.push(frameOf(pods, START_MS + 3 * PERIOD_MS, "cpu.cores")), false);

    await until("the agent reconnected", () => h.core.sessions === 2 && sink.ready);
    // One collector for the life of the agent: the ring is the history, and a
    // reconnect must not throw it away.
    assert.equal(h.starts, 1);

    sink.push(frameOf(pods, START_MS + 4 * PERIOD_MS, "cpu.cores"));
    sink.push(frameOf(pods, START_MS + 5 * PERIOD_MS, "cpu.cores"));
    await until("the second frame arrived", () => h.core.samples().length === 2);

    const second = h.core.samples()[1]!;
    const decoded = decodeSampleFrame(second.message, second.payload);
    // The new session knows nothing, so the dictionary is sent in full again,
    // from alias 1.
    assert.deepEqual(
      decoded.entities.added.map((entry) => entry.name),
      ["web-1", "web-2"],
    );
    assert.deepEqual(decoded.entityIds, [1, 2]);
    assert.deepEqual(decoded.entities.removed, []);
    // `seq` is the agent's, not the session's: it keeps going up, so a receiver
    // can tell this reconnect from an agent restart.
    assert.equal(decoded.seq, 2);
    // And the frame that was waiting for a partner when the socket died is
    // reported as lost rather than quietly forgotten.
    assert.equal(decoded.dropped, 1);
  } finally {
    await h.close();
  }
});

test("shutdown stops the collector", async () => {
  const h = await harness();
  try {
    await until("the collector has started", () => h.starts === 1);
    await h.client.stop();
    assert.equal(h.stops, 1, "the collector kept its watches and its timer after shutdown");
  } finally {
    await h.core.close();
  }
});

/**
 * NOT MEASURED, and named rather than left blank: calling `stop()` TWICE.
 *
 * The client already survives the second collector stop (the reference is
 * cleared), but `KubeTarget.close()` is not idempotent — undici's Agent throws
 * `UND_ERR_DESTROYED` on a second `close()`, which was measured here on
 * 09.09.2026 and is older than the collector. `index.ts` can reach it: SIGTERM
 * and SIGINT are two handlers on one shutdown. Fixing it is a change to the
 * shutdown path rather than to the sample path, so it is written down here
 * instead of being silently absorbed into this round.
 */

