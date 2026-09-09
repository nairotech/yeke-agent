/**
 * The collector, end to end against real TLS kubelets on the loopback
 * interface.
 *
 * These tests drive `tick()` by hand instead of waiting for the timer. That is
 * not a convenience: a gate whose assertion depends on wall-clock time measures
 * the machine it runs on rather than the product, and this repository has paid
 * for that lesson twice (the monorepo's CLAUDE.md, section 2, "the gates are
 * written assuming they run alone"). The clock is injected, the period is
 * irrelevant, and nothing here sleeps.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:https";
import { createServer as createHttpServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { Agent } from "undici";
import { Collector, MIN_CORE_PROTOCOL_FOR_METRICS, shouldCollect } from "./collector.js";
import {
  type FixturePod,
  type SummaryFixtureOptions,
  type TlsFixture,
  cadvisorFixture,
  createTlsFixture,
  fixturePods,
  opensslAvailable,
  summaryFixture,
} from "./fixture.js";
import { KubeletClient, type KubeletReader, type KubeletResult, type KubeletTarget } from "./kubelet-client.js";
import {
  type InternalFrame,
  type MetricName,
  type NodeStateCode,
  type SampleSink,
  entitiesOf,
  frameValue,
  samplesOf,
} from "./types.js";
import type { NodeRecord } from "./owners.js";
import type { KubeTarget } from "../kube.js";

const PERIOD_MS = 30_000;
const START_MS = Date.parse("2026-09-09T00:00:00.000Z");

let cached: { fixture: TlsFixture; directory: string } | undefined;
async function tls(): Promise<TlsFixture> {
  if (cached) return cached.fixture;
  assert.ok(
    await opensslAvailable(),
    "NOT MEASURED: openssl is not on PATH; the collector's TLS path was not exercised.",
  );
  const directory = await mkdtemp(join(tmpdir(), "yeke-collector-tls-"));
  cached = { fixture: await createTlsFixture(directory), directory };
  return cached.fixture;
}

/**
 * The apiserver connection is required by the type and never used by these
 * tests: the watches are not started, the index is seeded directly. A stub that
 * points at a closed port makes an accidental use fail loudly instead of
 * reaching something real.
 */
const NO_APISERVER: KubeTarget = {
  baseUrl: "https://127.0.0.1:1",
  authHeaders: async () => ({}),
  dispatcher: undefined as never,
  tlsOptions: () => ({ rejectUnauthorized: true }),
  invalidateCredential: () => undefined,
  close: async () => undefined,
};

/**
 * A fake apiserver that answers every LIST/WATCH with one HTTP status — for
 * exercising `ResourceWatch`'s classification of that status through the real
 * `Collector.start()` path, not just the wire's `collectorStatusOf` math.
 * Plain `http`, not TLS: the point is the status code, not the transport.
 */
async function fakeApiserver(status: number): Promise<{ target: KubeTarget; close(): Promise<void> }> {
  const server = createHttpServer((_req, res) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify({ kind: "Status", status: "Failure", code: status }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    target: {
      baseUrl: `http://127.0.0.1:${port}`,
      authHeaders: async () => ({}),
      dispatcher: new Agent(),
      tlsOptions: () => ({ rejectUnauthorized: true }),
      invalidateCredential: () => undefined,
      close: async () => undefined,
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

async function waitUntil(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) throw new Error("timed out waiting for the condition");
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

interface FakeNode {
  readonly name: string;
  readonly port: number;
  readonly pods: FixturePod[];
  tick: number;
  io: "normal" | "zero";
  psiIo: number;
  close(): Promise<void>;
}

/** The PVC knobs the fixture takes, threaded through a fake node unchanged. */
type PvcOptions = Pick<SummaryFixtureOptions, "pvcEvery" | "sharedPvc">;

async function fakeKubeletNode(
  name: string,
  options: {
    cert: Buffer;
    key: Buffer;
    pods: number;
    rogue?: boolean;
    status?: number;
  } & PvcOptions,
): Promise<FakeNode> {
  const pods = fixturePods(name, options.pods);
  const state = { tick: 0, io: "normal" as "normal" | "zero", psiIo: 0.1 };

  const server: Server = createServer({ cert: options.cert, key: options.key }, (req, res) => {
    if (options.status && options.status >= 300) {
      res.writeHead(options.status);
      res.end("no");
      return;
    }
    if (req.url === "/stats/summary") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          summaryFixture({
            node: name,
            pods,
            tick: state.tick,
            periodMs: PERIOD_MS,
            startMs: START_MS,
            psiIo: state.psiIo,
            ...(options.pvcEvery === undefined ? {} : { pvcEvery: options.pvcEvery }),
            ...(options.sharedPvc === undefined ? {} : { sharedPvc: options.sharedPvc }),
          }),
        ),
      );
      return;
    }
    if (req.url === "/metrics/cadvisor") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(
        cadvisorFixture({
          node: name,
          pods,
          tick: state.tick,
          periodMs: PERIOD_MS,
          startMs: START_MS,
          io: state.io,
        }),
      );
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    name,
    port: (server.address() as AddressInfo).port,
    pods,
    get tick() {
      return state.tick;
    },
    set tick(value: number) {
      state.tick = value;
    },
    get io() {
      return state.io;
    },
    set io(value: "normal" | "zero") {
      state.io = value;
    },
    get psiIo() {
      return state.psiIo;
    },
    set psiIo(value: number) {
      state.psiIo = value;
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

class RecordingSink implements SampleSink {
  ready = true;
  busy = false;
  readonly frames: InternalFrame[] = [];
  push(frame: InternalFrame): boolean {
    if (!this.ready) return false;
    this.frames.push(frame);
    return true;
  }
}

function valueOf(frame: InternalFrame, entity: string, metric: MetricName): number | undefined {
  return frameValue(frame, entity, metric);
}

async function harness(
  options: { pods?: number; rogue?: boolean; status?: number } & PvcOptions = {},
) {
  const fixture = await tls();
  const node = await fakeKubeletNode("node-a", {
    cert: options.rogue ? fixture.rogueCert : fixture.serverCert,
    key: options.rogue ? fixture.rogueKey : fixture.serverKey,
    pods: options.pods ?? 3,
    ...(options.status === undefined ? {} : { status: options.status }),
    ...(options.pvcEvery === undefined ? {} : { pvcEvery: options.pvcEvery }),
    ...(options.sharedPvc === undefined ? {} : { sharedPvc: options.sharedPvc }),
  });
  const kubelet = new KubeletClient({
    token: { read: async () => "tok", invalidate: () => undefined },
    ca: fixture.ca,
    insecureTls: false,
  });
  const sink = new RecordingSink();
  let clock = START_MS;
  const collector = new Collector({
    target: NO_APISERVER,
    kubelet,
    sink,
    periodMs: PERIOD_MS,
    now: () => clock,
  });
  collector.seedNode({
    name: node.name,
    uid: "node-uid-a",
    address: "127.0.0.1",
    port: node.port,
    ready: true,
    attributes: { "cpu.allocatable": 4, "mem.allocatable": 16 * 1024 ** 3 },
  });

  return {
    node,
    sink,
    collector,
    /** Advances the fixture's tick AND the agent clock by one period. */
    async advance(): Promise<InternalFrame | undefined> {
      const frame = await collector.tick();
      node.tick += 1;
      clock += PERIOD_MS;
      return frame;
    },
    async close() {
      await collector.stop();
      await kubelet.close();
      await node.close();
    },
  };
}

test("the collector only runs on protocol v5 or later", () => {
  assert.equal(MIN_CORE_PROTOCOL_FOR_METRICS, 5);
  assert.equal(shouldCollect(4), false);
  assert.equal(shouldCollect(5), true);
  assert.equal(shouldCollect(6), true);
});

test("one tick produces node and pod entities with both readings merged", async () => {
  const h = await harness({ pods: 3 });
  try {
    await h.advance();
    const frame = await h.advance();
    assert.ok(frame);

    const node = entitiesOf(frame).find((entity) => entity.kind === "node");
    assert.equal(node?.id, "node/node-a");
    assert.equal(node?.uid, "node-uid-a");
    // The denominator came from the node OBJECT, the rootfs capacity from the
    // Summary: both are attributes, neither is a series.
    assert.equal(node?.attributes["cpu.allocatable"], 4);
    assert.equal(node?.attributes["fs.capacity"], Math.fround(107_374_182_400));

    assert.equal(entitiesOf(frame).filter((entity) => entity.kind === "pod").length, 3);
    // From the Summary...
    assert.equal(valueOf(frame, "node/node-a", "cpu.cores"), Math.fround(1.45));
    // ...and from the cAdvisor text, in the same frame.
    assert.equal(valueOf(frame, "node/node-a", "io.readBps"), Math.fround(200_000 / 30));
    const pod = `pod/${h.node.pods[0]?.uid}`;
    assert.equal(valueOf(frame, pod, "cpu.throttled"), Math.fround(0.1));

    assert.deepEqual(frame.nodes, [
      { node: "node-a", state: "ok", psi: true, ioUnmeasurable: false },
    ]);
  } finally {
    await h.close();
  }
});

test("the workload owner comes from the metadata index", async () => {
  const h = await harness({ pods: 2 });
  try {
    const pod = h.node.pods[0];
    assert.ok(pod);
    h.collector.seedPod({
      uid: pod.uid,
      kind: "Pod",
      name: pod.name,
      namespace: pod.namespace,
      owners: [{ kind: "ReplicaSet", name: "web-5f9c", uid: "rs-1", controller: true }],
    });
    h.collector.seedOwner({
      uid: "rs-1",
      kind: "ReplicaSet",
      name: "web-5f9c",
      namespace: pod.namespace,
      owners: [{ kind: "Deployment", name: "web", uid: "d-1", controller: true }],
    });

    const frame = await h.advance();
    const entity = entitiesOf(frame!).find((item) => item.id === `pod/${pod.uid}`);
    assert.deepEqual(entity?.owner, { kind: "Deployment", name: "web", uid: "d-1" });
    // A pod the index does not know is still measured; it just has no workload.
    const other = entitiesOf(frame!).find((item) => item.id === `pod/${h.node.pods[1]?.uid}`);
    assert.equal(other?.owner, undefined);
  } finally {
    await h.close();
  }
});

test("PHASE 1 GAP, ASSERTED: no sample is ever produced for `restarts`", async () => {
  const h = await harness({ pods: 3 });
  try {
    await h.advance();
    const frame = await h.advance();
    // The restart count lives in a pod's `status`, `status` is an object body,
    // and the identity invariant says these jobs read no object bodies. The
    // name stays in the vocabulary so a later phase needs no protocol bump; the
    // absence is asserted here so that `owners.ts`'s explanation cannot quietly
    // become false.
    assert.deepEqual(
      samplesOf(frame!).filter((sample) => sample.metric === "restarts"),
      [],
    );
  } finally {
    await h.close();
  }
});

test("a node whose certificate does not verify produces a state and NO data", async () => {
  const h = await harness({ pods: 3, rogue: true });
  try {
    const frame = await h.advance();
    assert.equal(entitiesOf(frame!).length, 0);
    assert.equal(frame!.values.length, 0);
    assert.equal(frame?.nodes[0]?.state, "tls-unverified");
    // The failure is not a zero and not an omission: the node is in the frame,
    // with a code the screen turns into a sentence.
    assert.equal(frame?.nodes.length, 1);
  } finally {
    await h.close();
  }
});

test("a 403 is reported per node as the 'reapply the manifest' state", async () => {
  const h = await harness({ pods: 1, status: 403 });
  try {
    const frame = await h.advance();
    assert.equal(frame?.nodes[0]?.state, "forbidden");
    assert.equal(frame!.values.length, 0);
  } finally {
    await h.close();
  }
});

test("apiserver 403 on the node watch marks the frame apiserverForbidden, with no nodes at all", async () => {
  // The real-world shape of the bug this fix addresses: an old manifest was
  // never re-applied, so `nodes` LIST/WATCH is 403'd from the apiserver side.
  // The collector never discovers a node to poll -- `#nodes` stays empty for
  // every tick -- and BEFORE this fix that produced a frame indistinguishable
  // from "no nodes exist yet", which `collectorStatusOf` reports `degraded`.
  const api = await fakeApiserver(403);
  const kubelet = new KubeletClient({
    token: { read: async () => "tok", invalidate: () => undefined },
    insecureTls: true,
  });
  const sink = new RecordingSink();
  let clock = START_MS;
  const collector = new Collector({
    target: api.target,
    kubelet,
    sink,
    periodMs: PERIOD_MS,
    now: () => clock,
  });
  try {
    collector.start();
    // Give the three watches' first LIST attempt time to land a 403.
    await waitUntil(() => collector.stats().apiserverForbidden.includes("nodes"));

    const frame = await collector.tick();
    clock += PERIOD_MS;

    assert.deepEqual(frame?.nodes, []);
    // MEASURED (the "kırmızı gör" step): before this fix `InternalFrame` had
    // no `apiserverForbidden` field, so this was always `undefined` here.
    assert.equal(frame?.apiserverForbidden, true);
    assert.deepEqual(collector.stats().apiserverForbidden.slice().sort(), [
      "nodes",
      "pods",
      "replicasets",
    ]);
  } finally {
    await collector.stop();
    await kubelet.close();
    await api.close();
  }
});

test("a node with no InternalIP is reported, not omitted", async () => {
  const h = await harness({ pods: 1 });
  try {
    h.collector.seedNode({ name: "node-z", ready: true, attributes: {} });
    const frame = await h.advance();
    const state = frame?.nodes.find((item) => item.node === "node-z");
    // Omitting it would look exactly like a node that had been deleted.
    assert.equal(state?.state, "unreachable");
    assert.equal(state?.detail, "no InternalIP");
  } finally {
    await h.close();
  }
});

test("frames accumulate while the wire is down and drain in order when it returns", async () => {
  const h = await harness({ pods: 2 });
  try {
    h.sink.ready = false;
    for (let round = 0; round < 4; round += 1) await h.advance();
    assert.equal(h.sink.frames.length, 0);
    assert.equal(h.collector.stats().ringSize, 4);

    h.sink.ready = true;
    await h.advance();
    assert.deepEqual(
      h.sink.frames.map((frame) => frame.seq),
      [1, 2, 3, 4, 5],
    );
  } finally {
    await h.close();
  }
});

test("a queued user request delays the sample frame and loses nothing", async () => {
  const h = await harness({ pods: 2 });
  try {
    // K5: a `req` in the queue goes first. The sample frame is already in the
    // ring, so yielding costs a tick and no data.
    h.sink.busy = true;
    await h.advance();
    assert.equal(h.sink.frames.length, 0);

    h.sink.busy = false;
    await h.advance();
    assert.deepEqual(
      h.sink.frames.map((frame) => frame.seq),
      [1, 2],
    );
  } finally {
    await h.close();
  }
});

test("what the ring dropped rides on the next frame that gets through", async () => {
  const fixture = await tls();
  const node = await fakeKubeletNode("node-a", {
    cert: fixture.serverCert,
    key: fixture.serverKey,
    pods: 1,
  });
  const kubelet = new KubeletClient({
    token: { read: async () => "tok", invalidate: () => undefined },
    ca: fixture.ca,
    insecureTls: false,
  });
  const sink = new RecordingSink();
  let clock = START_MS;
  const collector = new Collector({
    target: NO_APISERVER,
    kubelet,
    sink,
    now: () => clock,
    ringCapacity: 2,
  });
  collector.seedNode({
    name: "node-a",
    address: "127.0.0.1",
    port: node.port,
    ready: true,
    attributes: {},
  });
  try {
    sink.ready = false;
    for (let round = 0; round < 5; round += 1) {
      await collector.tick();
      node.tick += 1;
      clock += PERIOD_MS;
    }
    // Capacity 2, five frames produced: three of them are gone.
    assert.equal(collector.stats().droppedPending, 3);

    sink.ready = true;
    // This tick produces frame 6 first, which pushes frame 4 out of a ring that
    // still holds only two -- so the count is 4 by the time anything is sent.
    // That ordering is the product's, not the test's: the collector always
    // collects before it drains, because the ring is only worth its memory if
    // something fills it while the wire is gone.
    await collector.tick();
    // The first frame that gets through carries the whole count; the ones after
    // it do not repeat it, or one outage would look like an unending series of
    // gaps.
    assert.equal(sink.frames[0]?.dropped, 4);
    assert.deepEqual(
      sink.frames.slice(1).map((frame) => frame.dropped),
      [0],
    );
    assert.deepEqual(
      sink.frames.map((frame) => frame.seq),
      [5, 6],
    );
  } finally {
    await collector.stop();
    await kubelet.close();
    await node.close();
  }
});

test("the IO zero probe fires end to end and the node says why", async () => {
  const h = await harness({ pods: 2 });
  try {
    // Counters flat at zero while the kernel reports processes waiting on IO:
    // the cgroup v2 breakage (cAdvisor #2881), not a quiet disk.
    h.node.io = "zero";
    h.node.psiIo = 0.6;

    for (let round = 0; round < 3; round += 1) {
      const frame = await h.advance();
      // Until the claim is established the honest answer is the counter's own
      // zero -- the probe asserts something about the NODE, not about a tick.
      assert.equal(frame?.nodes[0]?.ioUnmeasurable, round === 2, `round ${round}`);
    }

    const suppressed = await h.advance();
    assert.equal(suppressed?.nodes[0]?.ioUnmeasurable, true);
    assert.ok(Number.isNaN(valueOf(suppressed!, "node/node-a", "io.readBps") ?? 0));
    // Everything that is not IO keeps flowing: a stuck disk counter says
    // nothing about memory.
    assert.ok(!Number.isNaN(valueOf(suppressed!, "node/node-a", "mem.workingSet") ?? 0));

    // One real byte clears it immediately.
    h.node.io = "normal";
    const recovered = await h.advance();
    assert.equal(recovered?.nodes[0]?.ioUnmeasurable, false);
  } finally {
    await h.close();
  }
});

test("frames in the ring SHARE one layout while nothing comes or goes", async () => {
  const h = await harness({ pods: 3 });
  try {
    h.sink.ready = false;
    const frames: InternalFrame[] = [];
    for (let round = 0; round < 4; round += 1) {
      const frame = await h.advance();
      if (frame) frames.push(frame);
    }
    // Reference identity, not deep equality: this is the assertion the 64 MiB
    // target rests on. Four frames each carrying their own copy of the entity
    // dictionary is what cost 402 MiB at 50 nodes (`FrameLayout`).
    const first = frames[0]?.layout;
    assert.ok(first);
    for (const frame of frames.slice(1)) {
      assert.equal(frame.layout, first, "a frame allocated its own layout for an unchanged cluster");
    }
    // And the values are per frame, not shared: sharing those would make every
    // frame in the ring show the newest reading.
    assert.notEqual(frames[0]?.values, frames[1]?.values);

    // A pod appearing must produce a NEW layout, or the entity would never
    // reach the control plane.
    h.node.pods.push(...fixturePods("late", 1));
    const after = await h.advance();
    assert.notEqual(after?.layout, first);
  } finally {
    await h.close();
  }
});

test("rate memory does not grow with pod churn", async () => {
  const h = await harness({ pods: 3 });
  try {
    await h.advance();
    await h.advance();
    const before = h.collector.stats().samplesLastFrame;
    // Every pod on the node is replaced: new uids, new entity keys.
    h.node.pods.splice(0, h.node.pods.length, ...fixturePods("node-a-second", 3));
    await h.advance();
    await h.advance();
    const after = h.collector.stats().samplesLastFrame;
    // The sample count is stable, which is only true if the previous
    // generation's counter readings were forgotten rather than accumulated.
    assert.equal(after, before);
  } finally {
    await h.close();
  }
});

test("one tick produces PVC entities from the pods' `volume[]`", async () => {
  const h = await harness({ pods: 3, pvcEvery: 3 });
  try {
    const frame = await h.advance();
    assert.ok(frame);
    const pvcs = entitiesOf(frame).filter((entity) => entity.kind === "pvc");
    assert.deepEqual(
      pvcs.map((entity) => entity.id),
      ["pvc/kube-system/veri-node-a-0"],
    );
    assert.equal(pvcs[0]?.node, "node-a");
    assert.equal(pvcs[0]?.attributes["fs.capacity"], Math.fround(10_737_418_240));
    assert.equal(valueOf(frame, "pvc/kube-system/veri-node-a-0", "fs.used"), Math.fround(1_073_741_824));
  } finally {
    await h.close();
  }
});

test("a claim named like a pod does not steal that pod's cAdvisor counters", async () => {
  // The cAdvisor text names a series by `namespace` + `pod`, and the collector
  // resolves that pair to an entity id through an index built from the
  // Summary's entities. A PVC is namespaced too, so a claim called exactly what
  // a pod is called would land in that index and take the pod's disk counters
  // with it. The fixture's pod 0 is `kube-system-app-0-node-a`; the claim below
  // is given the SAME name in the SAME namespace, and it is mounted by every
  // pod, so it is read AFTER pod 0 — which is the order that would overwrite.
  const h = await harness({
    pods: 3,
    sharedPvc: { name: "kube-system-app-0-node-a", namespace: "kube-system", usedBytes: 8_192 },
  });
  try {
    await h.advance();
    const frame = await h.advance();
    assert.ok(frame);
    const pod = `pod/${h.node.pods[0]?.uid}`;
    const pvc = "pvc/kube-system/kube-system-app-0-node-a";
    assert.ok(entitiesOf(frame).some((entity) => entity.id === pvc), "the claim is missing");
    // The pod kept its own IO rate...
    assert.ok(
      (valueOf(frame, pod, "io.readBps") ?? Number.NaN) > 0,
      "the pod's disk counters went somewhere else",
    );
    // ...and the claim was given none: `io.readBps` is not a PVC metric.
    assert.equal(valueOf(frame, pvc, "io.readBps"), undefined);
    assert.equal(valueOf(frame, pvc, "fs.used"), 8_192);
  } finally {
    await h.close();
  }
});

test("an RWX claim mounted on TWO nodes is one entity, and the higher reading wins", async () => {
  const fixture = await tls();
  const shared = { name: "paylasilan", namespace: "ornek" } as const;
  const first = await fakeKubeletNode("node-a", {
    cert: fixture.serverCert,
    key: fixture.serverKey,
    pods: 2,
    // Only THIS node reports a capacity: the merge must keep a denominator one
    // kubelet knows even when the other does not.
    sharedPvc: { ...shared, usedBytes: 8_192, capacityBytes: 65_536 },
  });
  const second = await fakeKubeletNode("node-b", {
    cert: fixture.serverCert,
    key: fixture.serverKey,
    pods: 2,
    sharedPvc: { ...shared, usedBytes: 12_288 },
  });
  const kubelet = new KubeletClient({
    token: { read: async () => "tok", invalidate: () => undefined },
    ca: fixture.ca,
    insecureTls: false,
  });
  const sink = new RecordingSink();
  const collector = new Collector({
    target: NO_APISERVER,
    kubelet,
    sink,
    periodMs: PERIOD_MS,
    now: () => START_MS,
  });
  for (const node of [first, second]) {
    collector.seedNode({
      name: node.name,
      address: "127.0.0.1",
      port: node.port,
      ready: true,
      attributes: {},
    });
  }

  try {
    const frame = await collector.tick();
    assert.ok(frame);
    const rows = entitiesOf(frame).filter((entity) => entity.id === "pvc/ornek/paylasilan");
    assert.equal(rows.length, 1, "one claim produced one row per NODE");
    assert.equal(rows[0]?.attributes["fs.capacity"], 65_536);
    const used = samplesOf(frame).filter(
      (sample) => sample.entity === "pvc/ornek/paylasilan" && sample.metric === "fs.used",
    );
    assert.equal(used.length, 1, "the same volume's bytes were sent twice");
    // 12 288, not 8 192 and not 20 480: the mounts see one filesystem, so the
    // reading is neither the first one nor their sum.
    assert.equal(used[0]?.value, 12_288);
  } finally {
    await collector.stop();
    await kubelet.close();
    await first.close();
    await second.close();
  }
});

test("the TLS material is cleaned up", async () => {
  if (cached) await rm(cached.directory, { recursive: true, force: true });
});

/**
 * ─── The morning the collector went silent (09.09.2026) ─────────────────────
 *
 * These are the gates for the failure described in `collector.ts`'s header: a
 * healthy pod, zero restarts, an empty log and no samples for eleven minutes.
 * Each one fails against the code as it was that morning, and each one is about
 * a rule rather than about the particular way it broke.
 *
 * They use a `KubeletReader` stub instead of the TLS fixture on purpose. The
 * three things the collector has to survive — a busy wire, a read that throws,
 * a read that never settles — cannot be produced through a real socket, because
 * `KubeletClient` gives every socket a ceiling and turns all of them into
 * `unreachable`.
 */
const STUB_NODE: NodeRecord = {
  name: "node-a",
  uid: "node-uid-a",
  address: "10.0.0.1",
  ready: true,
  attributes: { "cpu.allocatable": 4 },
};

/** A kubelet that answers, hangs or throws, on command and without a network. */
class StubKubelet implements KubeletReader {
  mode: "ok" | "throw" | "hang" = "ok";
  /**
   * When set, `summary()` returns this per-node state instead of running
   * `mode`. Lets a test drive `tls-unverified` / `unreachable` state CHANGES
   * tick by tick, without a real socket -- the same seam-above-the-transport
   * reasoning as the rest of this stub (see the block comment above).
   */
  nodeState: Exclude<NodeStateCode, "ok"> | undefined;
  nodeStateDetail: string | undefined;
  reads = 0;
  async summary<T>(): Promise<KubeletResult<T>> {
    this.reads += 1;
    if (this.nodeState) return { state: this.nodeState, detail: this.nodeStateDetail };
    if (this.mode === "throw") throw new Error("the kubelet answered something unreadable");
    if (this.mode === "hang") return new Promise<KubeletResult<T>>(() => undefined);
    return {
      state: "ok",
      value: {
        node: {
          nodeName: "node-a",
          cpu: { time: "2026-09-09T00:00:00Z", usageNanoCores: 1_000_000 },
          memory: { time: "2026-09-09T00:00:00Z", workingSetBytes: 1024 },
        },
        pods: [],
      } as T,
    };
  }
  async cadvisor<T>(
    _target: KubeletTarget,
    consume: (lines: AsyncIterable<string>) => Promise<T>,
  ): Promise<KubeletResult<T>> {
    async function* nothing(): AsyncIterable<string> {}
    return { state: "ok", value: await consume(nothing()) };
  }
}

function stubHarness(options: { sink?: SampleSink; livenessMs?: number } = {}) {
  const kubelet = new StubKubelet();
  const sink = options.sink ?? new RecordingSink();
  let clock = START_MS;
  const collector = new Collector({
    target: NO_APISERVER,
    kubelet,
    sink,
    periodMs: PERIOD_MS,
    now: () => clock,
    ...(options.livenessMs === undefined ? {} : { livenessMs: options.livenessMs }),
  });
  collector.seedNode(STUB_NODE);
  return {
    kubelet,
    collector,
    sink,
    advance(periods = 1): void {
      clock += periods * PERIOD_MS;
    },
    async tick(): Promise<InternalFrame | undefined> {
      const frame = await collector.tick();
      clock += PERIOD_MS;
      return frame;
    },
  };
}

/** Captures both streams for one act, and always puts them back. */
async function captured(act: () => Promise<void>): Promise<{ warn: string[]; log: string[] }> {
  const warn: string[] = [];
  const log: string[] = [];
  const originalWarn = console.warn;
  const originalLog = console.log;
  console.warn = (...args: unknown[]) => void warn.push(args.join(" "));
  console.log = (...args: unknown[]) => void log.push(args.join(" "));
  try {
    await act();
  } finally {
    console.warn = originalWarn;
    console.log = originalLog;
  }
  return { warn, log };
}

test("a control plane that keeps a request open must not silence the collector", async () => {
  const h = stubHarness();
  const sink = h.sink as RecordingSink;
  try {
    // This is the production case, not a contrived one: the control plane holds
    // long-lived apiserver WATCHES open through the tunnel (CRDs and
    // APIServices are in the agent's own ClusterRole for it), so `busy` is true
    // for minutes at a time. Under the rule as it was, every one of those
    // minutes produced nothing.
    sink.busy = true;
    for (let round = 0; round < 6; round += 1) await h.tick();

    assert.ok(
      sink.frames.length >= 4,
      `a permanently busy wire kept ${6 - sink.frames.length} of 6 frames off the wire`,
    );
    // Nothing is lost either: what the ring held went out in order.
    assert.deepEqual(
      sink.frames.map((frame) => frame.seq),
      sink.frames.map((_, index) => index + 1),
    );
    assert.equal(h.collector.stats().droppedTotal, 0);
  } finally {
    await h.collector.stop();
  }
});

test("K5's priority rule still costs the sample frame a tick", async () => {
  const h = stubHarness();
  const sink = h.sink as RecordingSink;
  try {
    sink.busy = true;
    await h.tick();
    assert.equal(sink.frames.length, 0, "a queued user request must go first");
    sink.busy = false;
    await h.tick();
    assert.deepEqual(
      sink.frames.map((frame) => frame.seq),
      [1, 2],
    );
  } finally {
    await h.collector.stop();
  }
});

test("a collection pass that throws is counted, and the next one still runs", async () => {
  const h = stubHarness();
  try {
    h.kubelet.mode = "throw";
    const captures = await captured(async () => {
      // Not `rejects`: the caller is a timer chain, and a rejection there ends
      // the process in Node's default mode.
      assert.equal(await h.tick(), undefined);
    });
    assert.equal(h.collector.stats().tickErrors, 1);
    assert.ok(
      captures.warn.some((line) => line.includes("collection pass failed")),
      `the failure was silent: ${JSON.stringify(captures.warn)}`,
    );

    h.kubelet.mode = "ok";
    const frame = await h.tick();
    assert.ok(frame, "the collector stopped after one bad pass");
    assert.equal((h.sink as RecordingSink).frames.length, 1);
  } finally {
    await h.collector.stop();
  }
});

test("a sink that throws does not take the collector with it", async () => {
  // The `SampleSink` contract says an implementation must not throw. The
  // collector does not get to rely on that: it is the last thing standing
  // between a kubelet read and a process that stops collecting.
  class ThrowingSink implements SampleSink {
    ready = true;
    busy = false;
    calls = 0;
    push(): boolean {
      this.calls += 1;
      throw new Error("the wire threw");
    }
  }
  const sink = new ThrowingSink();
  const h = stubHarness({ sink });
  try {
    await captured(async () => {
      for (let round = 0; round < 3; round += 1) await h.tick();
    });
    assert.equal(h.collector.stats().tickErrors, 3);
    // The passes kept happening; the frames are in the ring, not lost.
    assert.equal(sink.calls, 3);
    assert.equal(h.collector.stats().ringSize, 3);
  } finally {
    await h.collector.stop();
  }
});

test("a collection pass that never settles is abandoned, not waited for", async () => {
  const h = stubHarness();
  try {
    h.kubelet.mode = "hang";
    // Never resolves. Nothing awaits it — that is the point.
    void h.collector.tick();
    await new Promise((resolve) => setImmediate(resolve));
    h.advance(1);
    assert.equal(await h.collector.tick(), undefined, "an overlapping pass must yield");

    // Four periods later the first pass is not slow, it is not coming back.
    h.advance(4);
    h.kubelet.mode = "ok";
    const captures = await captured(async () => {
      assert.ok(await h.collector.tick(), "the stuck pass held the lock for the life of the process");
    });
    assert.equal(h.collector.stats().tickStalls, 1);
    assert.ok(
      captures.warn.some((line) => line.includes("abandoning it")),
      `the abandoned pass was silent: ${JSON.stringify(captures.warn)}`,
    );
  } finally {
    await h.collector.stop();
  }
});

test("silence is reported once, with its reason, and so is the recovery", async () => {
  const h = stubHarness();
  const sink = h.sink as RecordingSink;
  try {
    sink.ready = false;
    const going = await captured(async () => {
      for (let round = 0; round < 6; round += 1) await h.tick();
    });
    const warnings = going.warn.filter((line) => line.includes("no sample frame is reaching"));
    assert.equal(warnings.length, 1, `expected exactly one warning, got ${JSON.stringify(going.warn)}`);
    assert.ok(warnings[0]?.includes("sink=down"), warnings[0]);
    assert.ok(/\d+ frames have been waiting/.test(warnings[0] ?? ""), warnings[0]);

    sink.ready = true;
    const back = await captured(async () => {
      await h.tick();
    });
    assert.ok(
      back.warn.some((line) => line.includes("reaching the control plane again")),
      JSON.stringify(back.warn),
    );
  } finally {
    await h.collector.stop();
  }
});

test("a busy wire names itself in the silence warning", async () => {
  // The line has to say WHICH of the three states it is in, or the operator is
  // back to guessing — which is exactly what the morning of 09.09.2026 cost.
  // A sink that is busy AND refuses what it is handed: the ring fills, and the
  // warning has to name the reason rather than merely report the silence.
  class BusyRefusingSink implements SampleSink {
    ready = true;
    busy = true;
    push(): boolean {
      return false;
    }
  }
  const h = stubHarness({ sink: new BusyRefusingSink() });
  try {
    const captures = await captured(async () => {
      for (let round = 0; round < 6; round += 1) await h.tick();
    });
    const warning = captures.warn.find((line) => line.includes("no sample frame is reaching"));
    assert.ok(warning, JSON.stringify(captures.warn));
    assert.ok(warning.includes("sink=busy"), warning);
  } finally {
    await h.collector.stop();
  }
});

test("one liveness line every ten minutes, and it carries the counters", async () => {
  const h = stubHarness({ livenessMs: 10 * PERIOD_MS });
  try {
    const captures = await captured(async () => {
      for (let round = 0; round < 21; round += 1) await h.tick();
    });
    const lines = captures.log.filter((line) => line.startsWith("[metrics] ticks="));
    assert.equal(lines.length, 2, `expected two liveness lines, got ${JSON.stringify(captures.log)}`);
    assert.match(lines[0] ?? "", /^\[metrics\] ticks=\d+ frames=\d+ pushed=\d+ dropped=\d+ sink=(ready|busy|down)$/);
    assert.ok(lines[1]?.includes("ticks=21"), lines[1]);
  } finally {
    await h.collector.stop();
  }
});

test("flush drains the ring without waiting for the next tick", async () => {
  const h = stubHarness();
  const sink = h.sink as RecordingSink;
  try {
    sink.ready = false;
    for (let round = 0; round < 3; round += 1) await h.tick();
    assert.equal(h.collector.queuedFrames, 3);

    // The tunnel is back and the control plane is already asking questions
    // again — which is the normal state, not an unusual one.
    sink.ready = true;
    sink.busy = true;
    h.collector.flush();
    assert.deepEqual(
      sink.frames.map((frame) => frame.seq),
      [1, 2, 3],
    );
    assert.equal(h.collector.queuedFrames, 0);
  } finally {
    await h.collector.stop();
  }
});

/**
 * F9, 09.09.2026: a live agent on a Kubespray cluster (`c-10`) reported "1
 * node: TLS doğrulanamadı" on the screen with NOTHING in `kubectl logs` —
 * `#classify` produced `{ state: "tls-unverified", detail }` and the detail
 * was never logged anywhere. These three tests are the state-change guard
 * added for it (`Collector#logNodeState`), following the precedent already
 * set by `ResourceWatch#setForbidden` in `owners.ts`.
 */
test("a kubelet TLS rejection is logged once on the state change, with the remedy, node and address", async () => {
  const h = stubHarness();
  h.kubelet.nodeState = "tls-unverified";
  h.kubelet.nodeStateDetail = "DEPTH_ZERO_SELF_SIGNED_CERT — self-signed certificate";
  try {
    const captures = await captured(async () => {
      await h.tick();
    });
    const tlsLines = captures.warn.filter((line) => line.includes("TLS verification failed"));
    assert.equal(tlsLines.length, 1, JSON.stringify(captures.warn));
    const line = tlsLines[0] ?? "";
    assert.ok(line.includes("node-a"), line);
    assert.ok(line.includes("10.0.0.1"), line);
    assert.ok(line.includes("DEPTH_ZERO_SELF_SIGNED_CERT"), line);
    assert.ok(line.includes("YEKE_KUBELET_INSECURE_TLS=true"), line);
    assert.ok(line.includes("serverTLSBootstrap"), line);
    assert.ok(line.includes("kubelet_rotate_server_certificates"), line);
  } finally {
    await h.collector.stop();
  }
});

test("13 consecutive TLS rejections still produce exactly one line (owners.ts#setForbidden precedent)", async () => {
  const h = stubHarness();
  h.kubelet.nodeState = "tls-unverified";
  h.kubelet.nodeStateDetail = "DEPTH_ZERO_SELF_SIGNED_CERT — self-signed certificate";
  try {
    const captures = await captured(async () => {
      // One tick to enter the state, thirteen more that repeat it. At the
      // default 30-second period this is seven minutes of an operator
      // watching "0/1 node reporting" with the failure logged only once.
      for (let round = 0; round < 14; round += 1) await h.tick();
    });
    const tlsLines = captures.warn.filter((line) => line.includes("TLS verification failed"));
    assert.equal(
      tlsLines.length,
      1,
      `14 consecutive rejections logged more than once: ${JSON.stringify(captures.warn)}`,
    );
  } finally {
    await h.collector.stop();
  }
});

test("a node's return to ok after a TLS rejection is logged once, and does not repeat the failure line", async () => {
  const h = stubHarness();
  h.kubelet.nodeState = "tls-unverified";
  h.kubelet.nodeStateDetail = "DEPTH_ZERO_SELF_SIGNED_CERT — self-signed certificate";
  try {
    await captured(async () => {
      await h.tick();
    });

    // Certificate rotation completed, or YEKE_KUBELET_INSECURE_TLS was set:
    // the next read succeeds.
    h.kubelet.nodeState = undefined;
    const recovered = await captured(async () => {
      await h.tick();
    });
    const nodeLines = recovered.warn.filter((line) => line.includes("node-a") && line.includes("10.0.0.1"));
    assert.equal(nodeLines.length, 1, JSON.stringify(recovered.warn));
    assert.ok(nodeLines[0]?.includes("recovered from tls-unverified"), nodeLines[0]);
    assert.ok(!nodeLines[0]?.includes("TLS verification failed"), nodeLines[0]);

    // And it does not repeat while the node stays healthy.
    const steady = await captured(async () => {
      for (let round = 0; round < 5; round += 1) await h.tick();
    });
    assert.deepEqual(
      steady.warn.filter((line) => line.includes("node-a") && line.includes("10.0.0.1")),
      [],
    );
  } finally {
    await h.collector.stop();
  }
});

test("an unreachable kubelet is logged once on the change too, with the reason and address", async () => {
  const h = stubHarness();
  h.kubelet.nodeState = "unreachable";
  h.kubelet.nodeStateDetail = "UND_ERR_CONNECT_TIMEOUT";
  try {
    const captures = await captured(async () => {
      for (let round = 0; round < 6; round += 1) await h.tick();
    });
    const lines = captures.warn.filter((line) => line.includes("unreachable") && line.includes("node-a"));
    assert.equal(lines.length, 1, `6 consecutive ticks logged more than once: ${JSON.stringify(captures.warn)}`);
    assert.ok(lines[0]?.includes("10.0.0.1"), lines[0]);
    assert.ok(lines[0]?.includes("UND_ERR_CONNECT_TIMEOUT"), lines[0]);

    h.kubelet.nodeState = undefined;
    const recovered = await captured(async () => {
      await h.tick();
    });
    const nodeLines = recovered.warn.filter((line) => line.includes("node-a") && line.includes("10.0.0.1"));
    assert.equal(nodeLines.length, 1, JSON.stringify(recovered.warn));
    assert.ok(nodeLines[0]?.includes("recovered from unreachable"), nodeLines[0]);
  } finally {
    await h.collector.stop();
  }
});
