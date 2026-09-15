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
import { execFile, execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
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
  type ChainTlsFixture,
  createChainTlsFixture,
  createExpiredRootCert,
  createRootCert,
  opensslAvailable,
} from "./core-ca-fixture.js";

const run = promisify(execFile);
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
  /**
   * The exact bytes a control message arrived as, before `parseControlMessage`
   * ran it through the installed `@nairotech/yeke-tunnel` zod schema and
   * STRIPPED whatever field that schema does not know about.
   *
   * K15's `hello.coreCaRoots` is exactly such a field while this repository
   * is pinned to tunnel 5.0.0 (see `tunnel-client.ts`'s comment at the send
   * site): `.control` alone can never show it, because by the time a test
   * reads `.control` the stripping has already happened. Undefined for a
   * binary frame.
   */
  readonly raw?: string;
}

/** The raw `hello` this fake core received, parsed WITHOUT the schema's stripping — see `Received.raw`. */
function rawHello(core: FakeCore): { readonly coreCaRoots?: unknown } {
  const entry = core.received.find((received) => received.control?.t === "hello");
  assert.ok(entry?.raw, "no `hello` control message was received");
  return JSON.parse(entry.raw) as { coreCaRoots?: unknown };
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
      const raw = data.toString();
      received.push({ control: parseControlMessage(raw), raw });
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
  /** How many times the reconnect path asked the collector to drain its ring. */
  flushes: number;
  /** What the ring is pretending to hold, for the `resumed` line. */
  queued: number;
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

  const state = { sink: undefined as SampleSink | undefined, starts: 0, stops: 0, queued: 0, flushes: 0 };
  const createCollector: CollectorFactory = async (context) => {
    state.sink = context.sink;
    const collector: MetricsCollector = {
      start: () => {
        state.starts += 1;
      },
      stop: async () => {
        state.stops += 1;
      },
      get queuedFrames() {
        return state.queued;
      },
      flush: () => {
        state.flushes += 1;
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
    get flushes() {
      return state.flushes;
    },
    set queued(value: number) {
      state.queued = value;
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

test("a reconnect resumes the collector and drains what the outage produced", async () => {
  const h = await harness();
  const originalLog = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => void lines.push(args.join(" "));
  try {
    await until("the collector has started", () => h.starts === 1);
    // Fourteen frames is seven minutes of a cluster nobody could see.
    h.queued = 14;

    h.core.drop();
    await until("the agent reconnected", () => h.core.sessions === 2);
    await until("the collector was resumed", () => h.flushes === 1);

    // Started once in the life of the pod; resumed on every reconnect, saying
    // how much history is on its way. Both lines matter to the operator, and
    // the absence of the second one is what made 09.09.2026 unreadable.
    assert.equal(h.starts, 1, "the reconnect rebuilt the collector and threw the ring away");
    assert.ok(
      lines.some((line) => line.includes("[metrics] collector resumed, 14 frames queued")),
      JSON.stringify(lines),
    );
  } finally {
    console.log = originalLog;
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

/**
 * ─── `YEKE_CORE_CA_FILE`: core signed by an organization's own CA ───────────
 *
 * Everything above connects to `fakeCore` over plain `ws://`; the tests below
 * are the one place in this repository that measures the combination the
 * architecture decision's corporate-CA design rests on —
 * `ca: [...defaultCoreCaCertificates(), ...bundle]` handed to `ws`, against a
 * REAL TLS handshake, on a control plane whose certificate chains through an
 * intermediate to a root Node does not carry by default. The baseline
 * measurement behind that decision (docs/architecture/2026-09-15-yeke-kurum-ca-guveni.md,
 * §8.3) only exercised `NODE_EXTRA_CA_CERTS`; this is the first measurement of
 * the `ws`-`ca`-option path itself.
 *
 * `secureFakeCore` is `fakeCore` with one difference: an `https.Server`
 * underneath the `WebSocketServer`, built with whatever certificate chain a
 * test hands it. `createChainTlsFixture` (`core-ca-fixture.ts`) is what
 * supplies a root → intermediate → leaf chain rather than the CA+leaf pair
 * `metrics/fixture.ts` builds for the collector — the point being measured
 * here is specifically that Node refuses to anchor trust on the intermediate
 * alone, and a leaf-only server could never exercise that.
 */

let cachedChainA: { fixture: ChainTlsFixture; directory: string } | undefined;
let cachedChainB: { fixture: ChainTlsFixture; directory: string } | undefined;

/** One root → intermediate → leaf chain, generated once and reused. */
async function chainA(): Promise<ChainTlsFixture> {
  if (cachedChainA) return cachedChainA.fixture;
  assert.ok(
    await opensslAvailable(),
    "NOT MEASURED: openssl is not on PATH, so the corporate-CA claims of the tunnel client were not " +
      "checked on this machine. Install openssl and run the gate again.",
  );
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-a-"));
  cachedChainA = { fixture: await createChainTlsFixture(directory, { commonName: "core-a" }), directory };
  return cachedChainA.fixture;
}

/** A SECOND, unrelated chain — for the "wrong root, then the right one" test. */
async function chainB(): Promise<ChainTlsFixture> {
  if (cachedChainB) return cachedChainB.fixture;
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-b-"));
  cachedChainB = { fixture: await createChainTlsFixture(directory, { commonName: "core-b" }), directory };
  return cachedChainB.fixture;
}

test.after(async () => {
  if (cachedChainA) await rm(cachedChainA.directory, { recursive: true, force: true });
  if (cachedChainB) await rm(cachedChainB.directory, { recursive: true, force: true });
});

/**
 * `fakeCore`, TLS-wrapped: identical wire behaviour (same `welcome`, same
 * message recording in arrival order), but the transport is a real
 * `https.Server` presenting whatever chain the test supplies, so a client
 * with the wrong (or no) trust anchor genuinely fails the handshake rather
 * than a mock pretending it would have.
 */
async function secureFakeCore(options: {
  readonly cert: Buffer;
  readonly key: Buffer;
  readonly protocol: number | undefined;
}): Promise<FakeCore> {
  const received: Received[] = [];
  let socket: CoreSocket | undefined;
  let sessions = 0;

  const httpsServer: HttpsServer = createHttpsServer({ cert: options.cert, key: options.key });
  const wss = new WebSocketServer({ server: httpsServer });
  wss.on("connection", (connection) => {
    sessions += 1;
    socket = connection;
    connection.on("message", (data, isBinary) => {
      if (isBinary) {
        received.push({ binary: Buffer.from(data as Buffer) });
        return;
      }
      const raw = data.toString();
      received.push({ control: parseControlMessage(raw), raw });
    });
    connection.send(
      serializeControlMessage({
        t: "welcome",
        clusterId: "cluster-1",
        sessionId: `session-${sessions}`,
        ...(options.protocol === undefined ? {} : { protocol: options.protocol }),
      }),
    );
  });
  await new Promise<void>((resolve) => httpsServer.listen(0, "127.0.0.1", resolve));
  const { port } = httpsServer.address() as AddressInfo;

  return {
    url: `wss://127.0.0.1:${port}/tunnel`,
    received,
    get sessions() {
      return sessions;
    },
    samples() {
      const found: { message: SampleMessage; payload: Buffer }[] = [];
      for (let index = 0; index < received.length; index += 1) {
        const message = received[index]?.control;
        if (message?.t !== "sample") continue;
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
        for (const client of wss.clients) client.terminate();
        wss.close();
        httpsServer.close(() => resolve());
      }),
  };
}

/** The parts of `AgentConfig` every CA test shares; only `coreUrl` and `coreCaFile` vary. */
function caTestConfig(coreUrl: string, coreCaFile?: string): AgentConfig {
  return {
    coreUrl,
    clusterId: "cluster-1",
    token: "agent-token",
    kubeMode: "kubeconfig",
    // Short and bounded, so a negative probe's "it never connects" assertion
    // does not have to wait out a realistic production backoff.
    reconnectMinMs: 30,
    reconnectMaxMs: 60,
    kubeletInsecureTls: false,
    // The collector is irrelevant to what these tests measure and would only
    // add an unreachable-apiserver's worth of noise to the log assertions.
    metricsEnabled: false,
    ...(coreCaFile ? { coreCaFile } : {}),
  };
}

test("YEKE_CORE_CA_FILE naming the root trusts a server presenting leaf+intermediate (Node cannot anchor on the intermediate alone)", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-"));
  const caFile = join(directory, "ca.crt");
  await writeFile(caFile, fixture.rootCert);

  const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  try {
    await client.start();
    await until("the agent trusts core's certificate and completes the handshake", () => client.protocolVersion === 5);
    assert.equal(core.sessions, 1);
  } finally {
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("K15: hello reports the sha256 fingerprint of the loaded root, matching openssl's own fingerprint", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-hello-"));
  const caFile = join(directory, "ca.crt");
  await writeFile(caFile, fixture.rootCert);

  const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  try {
    await client.start();
    await until("the handshake completes", () => client.protocolVersion === 5);
    await until("the hello control message arrived", () => core.received.some((r) => r.control?.t === "hello"));

    const { stdout } = await run("openssl", ["x509", "-in", caFile, "-fingerprint", "-sha256", "-noout"]);
    const opensslFingerprint = stdout.trim().split("=")[1];

    assert.deepEqual(rawHello(core).coreCaRoots, [opensslFingerprint]);
  } finally {
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("K15: hello reports an empty coreCaRoots array when no corporate CA is configured", async () => {
  process.env.KUBECONFIG = await kubeconfig();
  const core = await fakeCore(5);
  const client = new TunnelClient(caTestConfig(core.url));
  try {
    await client.start();
    await until("the handshake completes", () => client.protocolVersion === 5);
    await until("the hello control message arrived", () => core.received.some((r) => r.control?.t === "hello"));

    assert.deepEqual(rawHello(core).coreCaRoots, []);
  } finally {
    await client.stop();
    await core.close();
  }
});

test("without YEKE_CORE_CA_FILE the same server is untrusted, and the error line names the remedy", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
  const originalError = console.error;
  const lines: string[] = [];
  console.error = (...args: unknown[]) => void lines.push(args.join(" "));
  const client = new TunnelClient(caTestConfig(core.url));
  try {
    await client.start();
    await settle();
    assert.equal(client.protocolVersion, 0, "the handshake must never complete against an untrusted certificate");
    assert.equal(core.sessions, 0, "the TLS handshake itself must fail, before any WebSocket upgrade");
    assert.ok(
      lines.some((line) => line.includes("YEKE_CORE_CA_FILE") && line.includes("not trusted")),
      `no connection-error line named the remedy:\n${JSON.stringify(lines, null, 2)}`,
    );
  } finally {
    console.error = originalError;
    await client.stop();
    await core.close();
  }
});

test("the file is re-read on every connection attempt: a wrong root fails, and fixing the file makes the very next reconnect succeed (rotation)", async () => {
  const fixtureA = await chainA();
  const fixtureB = await chainB();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-"));
  const caFile = join(directory, "ca.crt");
  // The server speaks chain B; the file starts out with chain A's (unrelated)
  // root, so the very first attempt must fail — proving the second success
  // below comes from a fresh read, not a cached one from `start()`.
  await writeFile(caFile, fixtureA.rootCert);

  const core = await secureFakeCore({ cert: fixtureB.serverChainPem, key: fixtureB.leafKey, protocol: 5 });
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  try {
    await client.start();
    await settle();
    assert.equal(client.protocolVersion, 0, "chain A's root must not verify chain B's certificate");
    assert.equal(core.sessions, 0);

    await writeFile(caFile, fixtureB.rootCert);

    await until("the reconnect re-read the file and picked up the corrected root", () => client.protocolVersion === 5);
    assert.equal(core.sessions, 1, "exactly the reconnect that followed the fix reached the server");

    // K15 addendum: the hello that follows the fix must carry fixture B's
    // root — the fresh read this test's title is about, not a value cached
    // from the failed first attempt (which never got far enough to send a
    // hello at all: `open` never fires on a TLS handshake that fails).
    await until("the hello control message arrived", () => core.received.some((r) => r.control?.t === "hello"));
    const rootB = new X509Certificate(fixtureB.rootCert);
    assert.deepEqual(rawHello(core).coreCaRoots, [rootB.fingerprint256]);
  } finally {
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("when the CA file becomes unreadable, the last known good set is kept and the tunnel survives", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-"));
  const caFile = join(directory, "ca.crt");
  await writeFile(caFile, fixture.rootCert);

  const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
  const originalWarn = console.warn;
  const lines: string[] = [];
  console.warn = (...args: unknown[]) => void lines.push(args.join(" "));
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  try {
    await client.start();
    await until("the first connection succeeds with the correct root", () => client.protocolVersion === 5);
    assert.equal(core.sessions, 1);

    // Corrupt the file in place: the next `#connect` must fail to re-read it.
    await writeFile(caFile, "not a certificate\n");
    core.drop();

    await until(
      "the agent reconnected using the LAST KNOWN GOOD set, not a broken fresh read",
      () => core.sessions === 2 && client.protocolVersion === 5,
    );
    assert.ok(
      lines.some((line) => line.includes("core CA file could not be re-read") && line.includes("last known set")),
      `no warning line reported the unreadable file:\n${JSON.stringify(lines, null, 2)}`,
    );
  } finally {
    console.warn = originalWarn;
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("the startup CA log line is written once, on the first successful load, naming the file and the root's fingerprint", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-"));
  const caFile = join(directory, "ca.crt");
  await writeFile(caFile, fixture.rootCert);

  const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
  const originalLog = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => void lines.push(args.join(" "));
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  try {
    await client.start();
    await until("the first connection succeeds", () => client.protocolVersion === 5);

    const caLines = lines.filter((line) => line.startsWith("[agent] core CA:"));
    assert.equal(caLines.length, 1, `expected exactly one startup CA line:\n${JSON.stringify(lines, null, 2)}`);
    assert.ok(caLines[0]?.includes(caFile));
    assert.ok(caLines[0]?.includes("1 root(s)"));

    // A reconnect (the file unchanged) must NOT repeat the line — it is a
    // startup announcement, not a per-attempt one.
    core.drop();
    await until("the agent reconnected", () => core.sessions === 2);
    assert.equal(
      lines.filter((line) => line.startsWith("[agent] core CA:")).length,
      1,
      "a routine reconnect must not repeat the startup CA line",
    );
  } finally {
    console.log = originalLog;
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("K16: an expired root alongside a valid one does not stop the agent from starting or connecting; the expired one is skipped with a warning", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-expired-"));
  const caFile = join(directory, "ca.crt");
  // Before K16, ANY expired certificate in this file — even alongside a
  // perfectly good root — made `loadCoreCa` throw on the very first load,
  // and that first load's failure is the one `#loadCoreCaForConnect` lets
  // propagate out of `start()` (see its own comment): the agent would never
  // have come up at all. This is the regression that decision would be.
  const expiredRoot = await createExpiredRootCert(directory);
  await writeFile(caFile, Buffer.concat([expiredRoot, fixture.rootCert]));

  const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
  const originalWarn = console.warn;
  const lines: string[] = [];
  console.warn = (...args: unknown[]) => void lines.push(args.join(" "));
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  try {
    await client.start();
    await until("the agent connects using the still-valid root, despite the expired one in the file", () => client.protocolVersion === 5);
    assert.equal(core.sessions, 1);
    assert.ok(
      lines.some((line) => line.includes("skipping expired certificate")),
      `no warning line reported the skipped expired root:\n${JSON.stringify(lines, null, 2)}`,
    );
  } finally {
    console.warn = originalWarn;
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

/**
 * ─── Independent finding, 15.09.2026: `NODE_EXTRA_CA_CERTS` / the system CA
 * store must not be dropped by `YEKE_CORE_CA_FILE` ────────────────────────
 *
 * `NODE_EXTRA_CA_CERTS` is read once, at process startup — this repository's
 * other tests all run inside ONE `tsx --test` process, so none of them could
 * ever set it and see an effect. The only honest way to measure it is a
 * SEPARATE process started with the variable already in its environment,
 * which is what this test does (`execFileSync`, the same pattern
 * `apps/cli/src/ca.test.ts`'s equivalent measurement uses in the product
 * monorepo).
 */
test("the agent's own CA addition does not drop the operator's NODE_EXTRA_CA_CERTS root: a server signed ONLY by it, with YEKE_CORE_CA_FILE naming an unrelated root, still connects", async () => {
  assert.ok(
    await opensslAvailable(),
    "NOT MEASURED: openssl is not on PATH, so this finding was not checked on this machine. Install openssl and run the gate again.",
  );

  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-extra-ca-"));
  try {
    // Two UNRELATED chains: `extra` is what the server is actually signed by
    // (reachable only through `NODE_EXTRA_CA_CERTS`) and `given` is what
    // `YEKE_CORE_CA_FILE` names — a root that cannot verify this server at
    // all. If the connection succeeds, it can only be because
    // `defaultCoreCaCertificates()` picked up `extra` from the process's own
    // default trust store; `given`'s root plays no part in it.
    const extra = await createChainTlsFixture(directory, { commonName: "extra-root" });
    const given = await createChainTlsFixture(directory, { commonName: "given-root" });

    const extraRootFile = join(directory, "extra-root.crt");
    await writeFile(extraRootFile, extra.rootCert);
    const givenCaFile = join(directory, "given-ca.crt");
    await writeFile(givenCaFile, given.rootCert);
    const kubeconfigFile = join(directory, "kubeconfig");
    await writeFile(
      kubeconfigFile,
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

    // A minimal control plane and a `TunnelClient`, both built from THIS
    // repository's real source (`./src/tunnel-client.ts`, resolved relative
    // to `cwd` below — the same reason `ca.test.ts`'s equivalent measurement
    // uses a relative specifier rather than a package name): the server
    // presents `extra`'s chain and never even sees `given`.
    const script = `
      import { createServer as createHttpsServer } from "node:https";
      import { WebSocketServer } from "ws";
      import { serializeControlMessage } from "@nairotech/yeke-tunnel";
      import { TunnelClient } from "./src/tunnel-client.ts";

      const cert = Buffer.from(process.env.SERVER_CERT_PEM, "utf8");
      const key = Buffer.from(process.env.SERVER_KEY_PEM, "utf8");

      const httpsServer = createHttpsServer({ cert, key });
      const wss = new WebSocketServer({ server: httpsServer });
      let sessions = 0;
      wss.on("connection", (connection) => {
        sessions += 1;
        connection.send(
          serializeControlMessage({ t: "welcome", clusterId: "cluster-1", sessionId: "session-1", protocol: 5 }),
        );
      });
      await new Promise((resolve) => httpsServer.listen(0, "127.0.0.1", resolve));
      const { port } = httpsServer.address();

      process.env.KUBECONFIG = process.env.PROBE_KUBECONFIG;

      const client = new TunnelClient({
        coreUrl: \`wss://127.0.0.1:\${port}/tunnel\`,
        clusterId: "cluster-1",
        token: "agent-token",
        kubeMode: "kubeconfig",
        reconnectMinMs: 30,
        reconnectMaxMs: 60,
        kubeletInsecureTls: false,
        metricsEnabled: false,
        coreCaFile: process.env.GIVEN_CA_FILE,
      });

      await client.start();
      const deadline = Date.now() + 5000;
      while (client.protocolVersion !== 5 && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      const ok = client.protocolVersion === 5 && sessions === 1;
      await client.stop();
      httpsServer.close();
      process.stdout.write(ok ? "true" : "false");
    `;

    const projectRoot = join(import.meta.dirname, "..");
    const out = execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
      cwd: projectRoot,
      env: {
        ...process.env,
        // The one thing that makes this a SEPARATE-process test: read only at
        // startup, so it must already be set before this child's Node begins.
        NODE_EXTRA_CA_CERTS: extraRootFile,
        GIVEN_CA_FILE: givenCaFile,
        PROBE_KUBECONFIG: kubeconfigFile,
        SERVER_CERT_PEM: extra.serverChainPem.toString("utf8"),
        SERVER_KEY_PEM: extra.leafKey.toString("utf8"),
      },
      encoding: "utf8",
      timeout: 15_000,
    });
    // The child is a real `TunnelClient`, so its own `[agent] ...` log lines
    // (kubeconfig identity, the CA startup line, `core connection opened`,
    // `registered`) share stdout with the one line this probe cares about —
    // only the LAST line is the verdict.
    const verdict = out.trim().split("\n").at(-1);
    assert.equal(
      verdict,
      "true",
      "the child process must connect using the NODE_EXTRA_CA_CERTS root, which YEKE_CORE_CA_FILE's own bundle cannot verify:\n" +
        out,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

/**
 * ─── Independent finding, 15.09.2026: the startup CA line goes stale across
 * a rotation ────────────────────────────────────────────────────────────
 *
 * "The startup CA log line is written once, on the first successful load"
 * (the test above this section) measured exactly that — once, ever — and a
 * full rotation (architecture decision §3.10) changes the loaded root SET
 * *twice* while the pod is never restarted. Measured directly: the file
 * changed from one root to two, six reconnects later there was still no
 * second line, and the one line that existed still said "1 root(s)". §3.14
 * claims this line is what makes "which CA is distributed" auditable; that
 * claim does not survive a rotation under the old rule.
 */
test("the startup CA line is re-printed once when the loaded root SET changes (rotation), and stays silent on a reconnect that re-reads an UNCHANGED file", async () => {
  const fixtureA = await chainA();
  const fixtureB = await chainB();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-rotation-log-"));
  const caFile = join(directory, "ca.crt");
  await writeFile(caFile, fixtureA.rootCert);

  // The server keeps presenting fixture A's certificate for the whole test:
  // this measures whether the agent NOTICES its loaded root set changing,
  // not whether TLS trust changes — rotation step 1 (§3.10) adds a new root
  // without core's own certificate moving yet, for exactly this reason.
  const core = await secureFakeCore({ cert: fixtureA.serverChainPem, key: fixtureA.leafKey, protocol: 5 });
  const originalLog = console.log;
  const lines: string[] = [];
  console.log = (...args: unknown[]) => void lines.push(args.join(" "));
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  const caLines = () => lines.filter((line) => line.startsWith("[agent] core CA:"));
  try {
    await client.start();
    await until("the first connection succeeds", () => client.protocolVersion === 5);
    assert.equal(
      caLines().length,
      1,
      `expected exactly one startup CA line after the first load:\n${JSON.stringify(lines, null, 2)}`,
    );
    assert.ok(caLines()[0]?.includes("1 root(s)"));

    // Rotation step 1: the OLD root stays, a NEW (unrelated) one is added.
    await writeFile(caFile, Buffer.concat([fixtureA.rootCert, fixtureB.rootCert]));
    core.drop();
    await until(
      "the reconnect re-read the two-root file and re-trusted fixture A's certificate",
      () => core.sessions === 2 && client.protocolVersion === 5,
    );
    assert.equal(
      caLines().length,
      2,
      `expected a SECOND startup CA line once the loaded root set changed:\n${JSON.stringify(lines, null, 2)}`,
    );
    assert.ok(
      caLines()[1]?.includes("2 root(s)"),
      `the new line must report the new set, not repeat the old one:\n${JSON.stringify(lines, null, 2)}`,
    );

    // A routine reconnect with the file UNCHANGED (still the two-root set)
    // must stay silent — the "not on every reconnect" half of the rule,
    // undisturbed by this fix.
    core.drop();
    await until(
      "the second reconnect re-read the same two-root file",
      () => core.sessions === 3 && client.protocolVersion === 5,
    );
    assert.equal(
      caLines().length,
      2,
      `a reconnect against an UNCHANGED file must not repeat the startup CA line:\n${JSON.stringify(lines, null, 2)}`,
    );
  } finally {
    console.log = originalLog;
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

/**
 * ─── Independent finding, 15.09.2026: more than 16 roots leaves the tunnel
 * half-open ───────────────────────────────────────────────────────────────
 *
 * `HelloMessage.coreCaRoots` (K15) is capped at 16 items on the wire
 * (`packages/tunnel/src/tunnel.ts`, architecture decision §3.15). Measured:
 * with 17 roots loaded, the agent sent an over-the-cap array, core rejected
 * the `hello`, and the tunnel never finished negotiating — the agent's own
 * log showed nothing past `[agent] core connection opened`; no `welcome`
 * ever arrived, so the metrics collector never started either. Core's own
 * fix (rejecting an oversized `hello` explicitly, with a line naming why)
 * is a separate change; this is the agent's half — leave the field out
 * entirely once the loaded set will not fit, the same "absent means
 * unknown or unreportable" shape an agent that predates the field already
 * produces.
 */
test("with more than 16 valid roots, hello.coreCaRoots is left OUT entirely and a limit warning is logged once (not on every reconnect)", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-oversized-"));
  const caFile = join(directory, "ca.crt");
  try {
    // fixture.rootCert (the one that actually verifies the server) plus 16
    // more distinct, unrelated roots: 17 in total, one over the wire's cap.
    const extraRoots = await Promise.all(
      Array.from({ length: 16 }, (_, index) => createRootCert(directory, { commonName: `oversized-root-${index}` })),
    );
    await writeFile(caFile, Buffer.concat([fixture.rootCert, ...extraRoots]));

    const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
    const originalWarn = console.warn;
    const lines: string[] = [];
    console.warn = (...args: unknown[]) => void lines.push(args.join(" "));
    const client = new TunnelClient(caTestConfig(core.url, caFile));
    const limitLines = () => lines.filter((line) => line.includes("more than hello.coreCaRoots can report"));
    try {
      await client.start();
      // The handshake itself does not depend on hello at all (core replies
      // with `welcome` unconditionally in this fake); what matters is what
      // hello CARRIED, which is why the assertion below reads the raw wire
      // bytes rather than trusting the connection succeeding.
      await until("the handshake completes despite 17 loaded roots", () => client.protocolVersion === 5);
      await until("the hello control message arrived", () => core.received.some((r) => r.control?.t === "hello"));

      const entry = core.received.find((r) => r.control?.t === "hello")!;
      const raw = JSON.parse(entry.raw!) as Record<string, unknown>;
      assert.equal(
        "coreCaRoots" in raw,
        false,
        `hello must not carry coreCaRoots at all past the wire limit:\n${JSON.stringify(raw, null, 2)}`,
      );
      assert.equal(
        limitLines().length,
        1,
        `expected exactly one over-limit warning:\n${JSON.stringify(lines, null, 2)}`,
      );

      // A routine reconnect against the SAME (still 17-root) file must not
      // repeat the warning.
      core.drop();
      await until("the agent reconnected", () => core.sessions === 2 && client.protocolVersion === 5);
      assert.equal(
        limitLines().length,
        1,
        `a reconnect against an UNCHANGED file must not repeat the over-limit warning:\n${JSON.stringify(lines, null, 2)}`,
      );
    } finally {
      console.warn = originalWarn;
      await client.stop();
      await core.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a duplicated root does not count twice toward the 16-root wire limit: 16 distinct roots plus one repeat still reports hello.coreCaRoots", async () => {
  const fixture = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-dedup-"));
  const caFile = join(directory, "ca.crt");
  try {
    // fixture.rootCert once more (so the count would read 17 if a duplicate
    // PEM block were naively counted) plus 15 other distinct roots: 16
    // DISTINCT roots in total, at the limit rather than over it.
    const extraRoots = await Promise.all(
      Array.from({ length: 15 }, (_, index) => createRootCert(directory, { commonName: `dedup-root-${index}` })),
    );
    await writeFile(caFile, Buffer.concat([fixture.rootCert, fixture.rootCert, ...extraRoots]));

    const core = await secureFakeCore({ cert: fixture.serverChainPem, key: fixture.leafKey, protocol: 5 });
    const client = new TunnelClient(caTestConfig(core.url, caFile));
    try {
      await client.start();
      await until("the handshake completes", () => client.protocolVersion === 5);
      await until("the hello control message arrived", () => core.received.some((r) => r.control?.t === "hello"));

      const entry = core.received.find((r) => r.control?.t === "hello")!;
      const raw = JSON.parse(entry.raw!) as { coreCaRoots?: readonly string[] };
      assert.ok(raw.coreCaRoots, "hello must carry coreCaRoots: the duplicate must not have pushed the count over 16");
      assert.equal(raw.coreCaRoots.length, 16);
      assert.equal(new Set(raw.coreCaRoots).size, 16, "every reported fingerprint must be distinct");
    } finally {
      await client.stop();
      await core.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

/**
 * ─── Independent finding, 15.09.2026: the K16 skip warning repeated on
 * every reconnect ────────────────────────────────────────────────────────
 *
 * Measured: 10 reconnects against an unchanged file with one expired root
 * in it produced 10 identical `[agent] core CA: skipping expired
 * certificate ...` lines. `loadCoreCa` used to print that line itself, and
 * `#loadCoreCaForConnect` calls it fresh on every attempt (§3.10); the
 * architecture decision's own K6b live-measurement criterion says "one
 * line", the same rate the K15 root-set line already follows. `loadCoreCa`
 * now only reports what it skipped (`CoreCaBundle.skippedExpired`); this
 * test measures that `TunnelClient` prints it at the K6b rate.
 */
test("K16 finding: the 'skipping expired certificate(s)' warning is printed once per distinct skipped SET, not on every reconnect", async () => {
  const fixtureA = await chainA();
  process.env.KUBECONFIG = await kubeconfig();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-tunnel-ca-skip-log-"));
  const caFile = join(directory, "ca.crt");
  const expiredX = await createExpiredRootCert(directory, { commonName: "expired-x" });
  await writeFile(caFile, Buffer.concat([expiredX, fixtureA.rootCert]));

  const core = await secureFakeCore({ cert: fixtureA.serverChainPem, key: fixtureA.leafKey, protocol: 5 });
  const originalWarn = console.warn;
  const lines: string[] = [];
  console.warn = (...args: unknown[]) => void lines.push(args.join(" "));
  const client = new TunnelClient(caTestConfig(core.url, caFile));
  const skipLines = () => lines.filter((line) => line.includes("skipping expired certificate"));
  try {
    await client.start();
    await until("the first connection succeeds", () => client.protocolVersion === 5);
    assert.equal(
      skipLines().length,
      1,
      `expected exactly one skip warning after the first load:\n${JSON.stringify(lines, null, 2)}`,
    );

    // Two routine reconnects against the SAME (unchanged) file must not
    // repeat it — this is the 10-reconnects-10-lines regression, shortened.
    core.drop();
    await until("the second connection succeeds", () => core.sessions === 2 && client.protocolVersion === 5);
    core.drop();
    await until("the third connection succeeds", () => core.sessions === 3 && client.protocolVersion === 5);
    assert.equal(
      skipLines().length,
      1,
      `reconnects against an UNCHANGED file must not repeat the skip warning:\n${JSON.stringify(lines, null, 2)}`,
    );

    // The skipped SET changes (a second, DIFFERENT expired root joins the
    // file): the warning must fire again, exactly once, for the new set.
    const expiredY = await createExpiredRootCert(directory, { commonName: "expired-y" });
    await writeFile(caFile, Buffer.concat([expiredX, expiredY, fixtureA.rootCert]));
    core.drop();
    await until(
      "the fourth connection re-read the changed file",
      () => core.sessions === 4 && client.protocolVersion === 5,
    );
    assert.equal(
      skipLines().length,
      2,
      `expected a SECOND skip warning once the skipped set changed:\n${JSON.stringify(lines, null, 2)}`,
    );

    // Another reconnect against THIS (now unchanged) two-cert file stays
    // silent again.
    core.drop();
    await until("the fifth connection succeeds", () => core.sessions === 5 && client.protocolVersion === 5);
    assert.equal(
      skipLines().length,
      2,
      `a reconnect against the unchanged two-cert file must not repeat the warning:\n${JSON.stringify(lines, null, 2)}`,
    );
  } finally {
    console.warn = originalWarn;
    await client.stop();
    await core.close();
    await rm(directory, { recursive: true, force: true });
  }
});

/**
 * ─── Independent finding, 15.09.2026: `hello` rejected with 1008 reconnects
 * once a second forever ─────────────────────────────────────────────────
 *
 * Measured against a real `TunnelClient`: a control plane that closes every
 * `hello` with 1008 (`PROTOCOL_UNSUPPORTED` — core's real code for a `hello`
 * it will not accept) never let the backoff climb past its floor — 11
 * connection attempts in 10 seconds against `reconnectMinMs: 1000`. The
 * cause was `#backoff`'s reset living in the socket's `open` handler:
 * `open` only proves the TCP+TLS handshake succeeded, and `hello` goes out
 * from that same handler — core can still refuse it and close with no
 * `welcome` ever sent. Every such attempt's `open` re-armed the SAME floor
 * the immediately-following rejection should have been backing off from. A
 * full TLS handshake, a token check on core's side, and a log line on each
 * end, on a one-second clock, indefinitely — roughly 86,000 times a day for
 * one misbehaving or out-of-date agent.
 *
 * The two tests below share the shape of `#backoff`'s own file-header
 * comment: one server that never sends `welcome` (this one) must show the
 * delay CLIMBING; one that does send it (the next test) must show the delay
 * staying at the floor every time, proving the fix did not turn every
 * reconnect slow. Real elapsed time is measured (`Date.now()` between
 * connections) — there is no injectable clock for `setTimeout` here — so
 * the assertions compare the LAST gap against the FIRST by a wide margin
 * rather than checking exact doubling, to stay robust against scheduler
 * jitter on a loaded machine.
 */
test("a control plane that closes every hello with 1008 (never sending welcome) makes the reconnect delay CLIMB, not sit at the floor", async () => {
  process.env.KUBECONFIG = await kubeconfig();
  const server = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  const connectTimes: number[] = [];
  server.on("connection", (connection) => {
    connectTimes.push(Date.now());
    // No `welcome`, ever — this is core's real rejection path (measured
    // finding): the agent's `hello` is read and refused, not ignored.
    connection.on("message", () => {
      connection.close(1008, "protocol unsupported");
    });
  });
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;

  const client = new TunnelClient({
    coreUrl: `ws://127.0.0.1:${port}/tunnel`,
    clusterId: "cluster-1",
    token: "agent-token",
    kubeMode: "kubeconfig",
    reconnectMinMs: 15,
    reconnectMaxMs: 2_000,
    kubeletInsecureTls: false,
    metricsEnabled: false,
  });
  try {
    await client.start();
    await until("at least six rejected connection attempts", () => connectTimes.length >= 6);

    const gaps = connectTimes.slice(1).map((t, i) => t - connectTimes[i]!);
    assert.ok(
      gaps.at(-1)! >= gaps[0]! * 4,
      `expected the delay to climb well past the floor (gaps: ${JSON.stringify(gaps)})`,
    );
  } finally {
    await client.stop();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("a session that DID register (received welcome) and later drops keeps reconnecting from reconnectMinMs, every time — not an accumulated backoff", async () => {
  const core = await fakeCore(5);
  process.env.KUBECONFIG = await kubeconfig();
  const client = new TunnelClient({
    coreUrl: core.url,
    clusterId: "cluster-1",
    token: "agent-token",
    kubeMode: "kubeconfig",
    reconnectMinMs: 15,
    reconnectMaxMs: 2_000,
    kubeletInsecureTls: false,
    metricsEnabled: false,
  });
  const gaps: number[] = [];
  try {
    await client.start();
    await until("the first session registers", () => client.protocolVersion === 5);

    let last = Date.now();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      core.drop();
      await until(
        `reconnect ${attempt + 2} registers`,
        () => core.sessions === attempt + 2 && client.protocolVersion === 5,
      );
      const now = Date.now();
      gaps.push(now - last);
      last = now;
    }

    // Every gap stays near the floor: if the reset had NOT happened on each
    // `welcome`, later gaps would climb the same way the previous test's
    // do. A generous ceiling — well under one doubling of the 15ms floor —
    // is enough to tell the two shapes apart without being timing-brittle.
    for (const [index, gap] of gaps.entries()) {
      assert.ok(gap < 60, `reconnect ${index + 2} took ${gap}ms, expected near the 15ms floor: ${JSON.stringify(gaps)}`);
    }
  } finally {
    await client.stop();
    await core.close();
  }
});

