/**
 * `pods.count` against a fake apiserver that EVALUATES the field selector.
 *
 * The fake does not echo a fixed list: it holds pods with a node and a phase
 * and answers each request by applying the request's own `fieldSelector`, the
 * way the apiserver does. That is what lets "a Failed pod is not counted" be a
 * property of the selector the agent sends, and not of the fixture — remove a
 * clause from `podCountFieldSelector` and the counting tests turn red.
 *
 * Nothing here waits on wall-clock time for staleness: the agent clock is
 * injected and moved by hand.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Agent } from "undici";
import type { KubeTarget } from "../kube.js";
import {
  NodePodCounter,
  NodePodWatch,
  POD_COUNT_LIST_LIMIT,
  POD_COUNT_STALE_MS,
  podCountFieldSelector,
} from "./pod-count.js";

interface FakePod {
  uid: string;
  node: string;
  phase: "Pending" | "Running" | "Succeeded" | "Failed" | "Unknown";
}

interface Seen {
  readonly path: string;
  readonly query: URLSearchParams;
  readonly accept: string;
}

type Override = (req: IncomingMessage, res: ServerResponse, query: URLSearchParams) => boolean;

/** `k=v` / `k!=v` clauses, ANDed — the apiserver's field selector grammar, the part used here. */
function selects(selector: string, pod: FakePod): boolean {
  const field = (key: string): string | undefined =>
    key === "spec.nodeName" ? pod.node : key === "status.phase" ? pod.phase : undefined;
  return selector
    .split(",")
    .filter(Boolean)
    .every((clause) => {
      const negated = clause.includes("!=");
      const [key, value] = clause.split(negated ? "!=" : "=") as [string, string];
      const actual = field(key);
      if (actual === undefined) throw new Error(`fake apiserver: unsupported field ${key}`);
      return negated ? actual !== value : actual === value;
    });
}

function meta(pod: FakePod, resourceVersion: string) {
  // What `PartialObjectMetadata` carries: metadata, and no spec or status.
  return {
    kind: "PartialObjectMetadata",
    apiVersion: "meta.k8s.io/v1",
    metadata: { uid: pod.uid, name: pod.uid, namespace: "default", resourceVersion },
  };
}

async function fakeApiserver(options: { pods?: FakePod[]; pageSize?: number } = {}) {
  const pods = options.pods ?? [];
  const requests: Seen[] = [];
  const overrides: Override[] = [];
  const watches = new Set<ServerResponse>();
  let revision = 100;
  const invalidations: string[] = [];

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://fake");
    const query = url.searchParams;
    requests.push({ path: url.pathname, query, accept: String(req.headers.accept ?? "") });
    const override = overrides.shift();
    if (override && override(req, res, query)) return;
    if (url.pathname !== "/api/v1/pods") {
      res.writeHead(404).end();
      return;
    }
    const selector = query.get("fieldSelector") ?? "";
    if (query.get("watch") === "1") {
      res.writeHead(200, { "content-type": "application/json" });
      res.flushHeaders();
      watches.add(res);
      res.on("close", () => watches.delete(res));
      return;
    }
    const all = pods.filter((pod) => selects(selector, pod));
    // A server that pages: only when asked WITHOUT `resourceVersion=0`, as
    // measured on k3s v1.31.5 (RV=0 ignores `limit`).
    const page = options.pageSize !== undefined && query.get("resourceVersion") !== "0";
    const start = Number(query.get("continue") ?? "0");
    const size = page ? options.pageSize! : all.length;
    const slice = all.slice(start, start + size);
    const next = start + size < all.length ? String(start + size) : undefined;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        kind: "PartialObjectMetadataList",
        metadata: { resourceVersion: String(revision), ...(next ? { continue: next } : {}) },
        items: slice.map((pod) => meta(pod, String(revision))),
      }),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const target: KubeTarget = {
    baseUrl: `http://127.0.0.1:${port}`,
    authHeaders: async () => ({}),
    dispatcher: new Agent(),
    tlsOptions: () => ({ rejectUnauthorized: true }),
    invalidateCredential: (reason: string) => {
      invalidations.push(reason);
    },
    close: async () => undefined,
  };
  return {
    pods,
    requests,
    overrides,
    invalidations,
    target,
    lists: () => requests.filter((item) => item.query.get("watch") !== "1"),
    watchRequests: () => requests.filter((item) => item.query.get("watch") === "1"),
    openWatches: () => watches.size,
    /** Writes one event to every open watch, with a fresh revision. */
    emit(type: string, pod?: FakePod, extra: Record<string, unknown> = {}): void {
      revision += 1;
      const object =
        type === "BOOKMARK"
          ? { kind: "PartialObjectMetadata", metadata: { resourceVersion: String(revision) } }
          : pod
            ? meta(pod, String(revision))
            : extra;
      for (const res of watches) res.write(`${JSON.stringify({ type, object })}\n`);
    },
    /** The server-side timeout: every open watch ends cleanly. */
    endWatches(): void {
      for (const res of watches) res.end();
    },
    /** A broken stream: the socket dies mid-response. */
    breakWatches(): void {
      for (const res of watches) res.socket?.destroy();
    },
    close: () =>
      new Promise<void>((resolve) => {
        for (const res of watches) res.end();
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

async function waitFor(what: string, condition: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** A watch on `node-a` with a hand-moved clock. */
function watchOn(target: KubeTarget, extra: { requestTimeoutMs?: number } = {}) {
  let clock = 1_000_000;
  const watch = new NodePodWatch("node-a", {
    target,
    now: () => clock,
    retryMs: 10,
    watchTimeoutSeconds: () => 60,
    ...extra,
  });
  return {
    watch,
    advance(ms: number) {
      clock += ms;
    },
  };
}

const count = (watch: NodePodWatch): number | undefined => {
  const reading = watch.read();
  return reading.ok ? reading.count : undefined;
};

/** Every slot-holding phase on node-a, every terminal one, and another node's pods. */
function mixedPods(): FakePod[] {
  return [
    { uid: "running-1", node: "node-a", phase: "Running" },
    { uid: "running-2", node: "node-a", phase: "Running" },
    { uid: "pending-pull", node: "node-a", phase: "Pending" }, // ImagePullBackOff / ContainerCreating
    { uid: "crashloop", node: "node-a", phase: "Running" }, // CrashLoopBackOff keeps phase Running
    { uid: "unknown", node: "node-a", phase: "Unknown" },
    { uid: "job-done", node: "node-a", phase: "Succeeded" },
    { uid: "evicted", node: "node-a", phase: "Failed" },
    { uid: "elsewhere", node: "node-b", phase: "Running" },
    { uid: "unbound", node: "", phase: "Pending" },
  ];
}

test("the request: path, selector, resourceVersion=0, limit and the metadata Accept, exactly", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("the watch to open", () => api.openWatches() === 1);

    assert.equal(
      podCountFieldSelector("node-a"),
      "spec.nodeName=node-a,status.phase!=Succeeded,status.phase!=Failed",
    );
    const [list] = api.lists();
    assert.ok(list);
    assert.equal(list.path, "/api/v1/pods");
    assert.deepEqual(
      [...list.query.entries()].sort(),
      [
        ["fieldSelector", "spec.nodeName=node-a,status.phase!=Succeeded,status.phase!=Failed"],
        ["limit", String(POD_COUNT_LIST_LIMIT)],
        ["resourceVersion", "0"],
      ].sort(),
    );
    // `owners.ts`'s constants: the apiserver is asked for metadata, so no
    // spec, no env, no status is ever sent.
    assert.equal(list.accept, "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1");

    const [opened] = api.watchRequests();
    assert.ok(opened);
    assert.equal(opened.path, "/api/v1/pods");
    assert.deepEqual(
      [...opened.query.entries()].sort(),
      [
        ["allowWatchBookmarks", "true"],
        ["fieldSelector", "spec.nodeName=node-a,status.phase!=Succeeded,status.phase!=Failed"],
        ["resourceVersion", "100"],
        ["timeoutSeconds", "60"],
        ["watch", "1"],
      ].sort(),
    );
    assert.equal(opened.accept, "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1");
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("counts bound, non-terminated pods: pending and crash-looping YES, Succeeded/Failed/other node/unbound NO", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("the first count", () => watch.read().ok);
    // running-1, running-2, pending-pull, crashloop, unknown.
    assert.equal(count(watch), 5);
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("watch events move the count; a repeated MODIFIED does not count a pod twice", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("the watch to open", () => api.openWatches() === 1 && watch.read().ok);
    assert.equal(count(watch), 5);

    const bound: FakePod = { uid: "newly-bound", node: "node-a", phase: "Pending" };
    api.emit("ADDED", bound);
    await waitFor("ADDED applied", () => count(watch) === 6);
    api.emit("MODIFIED", bound);
    api.emit("MODIFIED", { uid: "running-1", node: "node-a", phase: "Running" });
    // A pod leaving the selector (Running -> Succeeded) arrives as DELETED
    // (measured on k3s); so does a deleted pod once it is gone.
    api.emit("DELETED", { uid: "running-2", node: "node-a", phase: "Succeeded" });
    await waitFor("DELETED applied", () => count(watch) === 5);
    assert.equal(count(watch), 5);
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("pagination: every page is summed, continuation pages carry `continue` and NO resourceVersion", async () => {
  const pods: FakePod[] = Array.from({ length: 5 }, (_, index) => ({
    uid: `p-${index}`,
    node: "node-a",
    phase: "Running" as const,
  }));
  // The first page is answered as RV=0 normally is NOT (a server that pages
  // anyway), to drive the loop: the override returns page 1 of 2.
  const api = await fakeApiserver({ pods, pageSize: 2 });
  api.overrides.push((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        metadata: { resourceVersion: "100", continue: "2" },
        items: pods.slice(0, 2).map((pod) => meta(pod, "100")),
      }),
    );
    return true;
  });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("the count", () => watch.read().ok);
    assert.equal(count(watch), 5);
    const lists = api.lists();
    assert.equal(lists.length, 3);
    assert.equal(lists[0]!.query.get("resourceVersion"), "0");
    for (const page of lists.slice(1)) {
      assert.equal(page.query.has("resourceVersion"), false);
      assert.ok(page.query.get("continue"));
      assert.equal(page.query.get("fieldSelector"), podCountFieldSelector("node-a"));
      assert.equal(page.accept, "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1");
    }
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("a half-delivered LIST (page 2 fails) is NO reading — not the page-1 size, not zero", async () => {
  const pods: FakePod[] = Array.from({ length: 4 }, (_, index) => ({
    uid: `p-${index}`,
    node: "node-a",
    phase: "Running" as const,
  }));
  const api = await fakeApiserver({ pods });
  api.overrides.push((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        metadata: { resourceVersion: "100", continue: "2" },
        items: pods.slice(0, 2).map((pod) => meta(pod, "100")),
      }),
    );
    return true;
  });
  // ...and page 2 is a 500, every time it is retried.
  for (let index = 0; index < 1000; index += 1) {
    api.overrides.push((_req, res, query) => {
      if (query.get("continue")) {
        res.writeHead(500).end();
        return true;
      }
      // A fresh first page again, so every attempt is "page 1 ok, page 2 fails".
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          metadata: { resourceVersion: "100", continue: "2" },
          items: pods.slice(0, 2).map((pod) => meta(pod, "100")),
        }),
      );
      return true;
    });
  }
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("two failed attempts", () => watch.failures >= 2);
    const reading = watch.read();
    assert.equal(reading.ok, false);
    assert.deepEqual(reading.ok ? undefined : reading.state, "unreachable");
    assert.equal(api.openWatches(), 0, "no watch is opened on a partial LIST");
  } finally {
    await watch.stop();
    await api.close();
  }
});

for (const [status, state] of [
  [403, "forbidden"],
  [401, "unauthorized"],
  [500, "unreachable"],
  [503, "unreachable"],
] as const) {
  test(`a ${status} on the LIST is NO reading (${state}), never 0`, async () => {
    const api = await fakeApiserver({ pods: mixedPods() });
    for (let index = 0; index < 1000; index += 1) {
      api.overrides.push((_req, res) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify({ kind: "Status", code: status }));
        return true;
      });
    }
    const { watch } = watchOn(api.target);
    try {
      watch.start();
      await waitFor("a failure", () => watch.failures >= 1);
      const reading = watch.read();
      assert.equal(reading.ok, false);
      assert.equal(reading.ok ? undefined : reading.state, state);
      if (status === 401) assert.ok(api.invalidations.length >= 1, "401 drops the cached identity");
      else assert.equal(api.invalidations.length, 0);
    } finally {
      await watch.stop();
      await api.close();
    }
  });
}

test("a LIST that never answers times out into NO reading", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  for (let index = 0; index < 1000; index += 1) api.overrides.push(() => true); // never responds
  const { watch } = watchOn(api.target, { requestTimeoutMs: 100 });
  try {
    watch.start();
    await waitFor("the timeout", () => watch.failures >= 1);
    const reading = watch.read();
    assert.equal(reading.ok, false);
    assert.equal(reading.ok ? undefined : reading.state, "unreachable");
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("a valid count is lost the moment the stream breaks, and comes back only with a fresh LIST", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("synced", () => api.openWatches() === 1 && watch.read().ok);
    assert.equal(count(watch), 5);
    // Hold the retry so the gap is observable: the next request hangs.
    let release: (() => void) | undefined;
    api.overrides.push((_req, res) => {
      release = () => res.destroy();
      return true;
    });
    api.breakWatches();
    await waitFor("the failure and the held retry", () => watch.failures >= 1 && release !== undefined);
    assert.equal(watch.read().ok, false, "not the last known 5");
    release!();
    await waitFor("a fresh LIST", () => watch.read().ok);
    assert.equal(count(watch), 5);
    assert.ok(api.lists().length >= 2);
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("a clean end of the stream resumes from the newest revision (bookmark), without a LIST", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("open", () => api.openWatches() === 1);
    api.emit("BOOKMARK"); // revision 101
    await new Promise((resolve) => setTimeout(resolve, 20));
    api.endWatches();
    await waitFor("the reconnect", () => api.watchRequests().length === 2 && api.openWatches() === 1);
    assert.equal(api.lists().length, 1, "no re-LIST on a clean end");
    assert.equal(api.watchRequests()[1]!.query.get("resourceVersion"), "101");
    assert.equal(count(watch), 5, "the count survives a routine reconnect");
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("a 410 inside the stream re-LISTs; the count is gone until it lands", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("open", () => api.openWatches() === 1 && watch.read().ok);
    api.emit("ERROR", undefined, { kind: "Status", code: 410, reason: "Expired" });
    await waitFor("the re-LIST", () => api.lists().length === 2 && watch.read().ok);
    assert.equal(count(watch), 5);
    assert.equal(watch.failures, 0, "410 is routine, not a failure");
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("STALE: a stream that shows no life for longer than the bound is NO reading; a bookmark revives it", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  const { watch, advance } = watchOn(api.target);
  try {
    watch.start();
    await waitFor("open", () => api.openWatches() === 1 && watch.read().ok);
    advance(POD_COUNT_STALE_MS);
    assert.equal(count(watch), 5, "exactly at the bound it still counts");
    advance(1);
    const reading = watch.read();
    assert.equal(reading.ok, false, "a frozen stream must not serve its last number");
    assert.equal(reading.ok ? undefined : reading.state, "stale");
    api.emit("BOOKMARK");
    await waitFor("revived", () => watch.read().ok);
    assert.equal(count(watch), 5);
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("before the first LIST lands there is no number (pending)", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  for (let index = 0; index < 1000; index += 1) api.overrides.push(() => true);
  const { watch } = watchOn(api.target);
  try {
    watch.start();
    const reading = watch.read();
    assert.equal(reading.ok, false);
    assert.equal(reading.ok ? undefined : reading.state, "pending");
  } finally {
    await watch.stop();
    await api.close();
  }
});

test("the counter follows the node list: a new node gets a watch, a removed node's watch closes", async () => {
  const api = await fakeApiserver({
    pods: [
      ...mixedPods(),
      { uid: "b-1", node: "node-b", phase: "Pending" },
    ],
  });
  const counter = new NodePodCounter({ target: api.target, retryMs: 10 });
  try {
    counter.sync(["node-a", "node-b"]);
    await waitFor("both counts", () => counter.read("node-a").ok && counter.read("node-b").ok);
    assert.deepEqual(counter.read("node-a"), { ok: true, count: 5 });
    assert.deepEqual(counter.read("node-b"), { ok: true, count: 2 }); // elsewhere + b-1
    await waitFor("two streams", () => api.openWatches() === 2);
    counter.sync(["node-a"]);
    await waitFor("node-b's stream closed", () => api.openWatches() === 1);
    assert.equal(counter.size, 1);
    assert.equal(counter.read("node-b").ok, false);
  } finally {
    await counter.stop();
    await api.close();
  }
});

/**
 * ─── Live round R2 (13.10.2026): `list` granted, `watch` revoked ────────────
 *
 * Measured on k3s under the agent's own ServiceAccount: every 30 s the log
 * said "restored (was forbidden)" and, 5 ms later, "unavailable: forbidden",
 * because a successful LIST counted as a restoration. In the same window the
 * count was readable. The fake below answers the LIST with 200 and refuses
 * every WATCH with 403 — SLOWLY (`REFUSE_AFTER_MS`), so that the window
 * between the two is wide enough that a poll lands in it every time.
 */
const REFUSE_AFTER_MS = 40;

function refuseWatches(api: Awaited<ReturnType<typeof fakeApiserver>>): void {
  for (let index = 0; index < 1000; index += 1) {
    api.overrides.push((_req, res, query) => {
      if (query.get("watch") !== "1") return false;
      setTimeout(() => {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ kind: "Status", code: 403 }));
      }, REFUSE_AFTER_MS);
      return true;
    });
  }
}

function captureWarnings(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    lines.push(args.map(String).join(" "));
  };
  return { lines, restore: () => (console.warn = original) };
}

test("R2: LIST 200 + WATCH 403 publishes NO number at any moment, logs ONE line and never 'restored'", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  refuseWatches(api);
  const warnings = captureWarnings();
  // A real backoff ceiling but test-sized steps: 5, 10, 20, 20, 20 ms.
  const watch = new NodePodWatch("node-a", { target: api.target, retryMs: 5, retryMaxMs: 20 });
  const seen: number[] = [];
  try {
    watch.start();
    const deadline = Date.now() + 5000;
    while (watch.failures < 4 && Date.now() < deadline) {
      const reading = watch.read();
      if (reading.ok) seen.push(reading.count);
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    assert.ok(watch.failures >= 4, `four refused attempts (got ${watch.failures})`);
    // Every attempt WAS a successful LIST: the window existed each time.
    assert.ok(watch.lists >= 4);
    assert.deepEqual(seen, [], "a count was readable between the LIST and the refused WATCH");
    const reading = watch.read();
    assert.equal(reading.ok ? undefined : reading.state, "forbidden");

    const mine = warnings.lines.filter((line) => line.includes("pod count for node node-a"));
    assert.equal(mine.filter((line) => line.includes("restored")).length, 0, mine.join("\n"));
    assert.equal(mine.filter((line) => line.includes("unavailable: forbidden")).length, 1, mine.join("\n"));
  } finally {
    warnings.restore();
    await watch.stop();
    await api.close();
  }
});

test("R2: once the WATCH is granted again the count returns and 'restored' is logged once", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  // Two refusals, then the ordinary handler.
  api.overrides.push(() => false, (_req, res) => (res.writeHead(403).end(), true));
  api.overrides.push(() => false, (_req, res) => (res.writeHead(403).end(), true));
  const warnings = captureWarnings();
  const watch = new NodePodWatch("node-a", { target: api.target, retryMs: 5, retryMaxMs: 20 });
  try {
    watch.start();
    await waitFor("restored", () => watch.read().ok);
    assert.equal(count(watch), 5);
    const mine = warnings.lines.filter((line) => line.includes("pod count for node node-a"));
    assert.deepEqual(
      mine.map((line) => (line.includes("restored") ? "restored" : line.includes("forbidden") ? "forbidden" : line)),
      ["forbidden", "restored"],
    );
  } finally {
    warnings.restore();
    await watch.stop();
    await api.close();
  }
});

test("the retry backs off: consecutive failures double the wait up to the ceiling", async () => {
  const api = await fakeApiserver({ pods: mixedPods() });
  for (let index = 0; index < 1000; index += 1) {
    api.overrides.push((_req, res) => (res.writeHead(500).end(), true));
  }
  const times: number[] = [];
  const server = api.requests;
  const watch = new NodePodWatch("node-a", { target: api.target, retryMs: 20, retryMaxMs: 80 });
  try {
    watch.start();
    const deadline = Date.now() + 5000;
    let last = 0;
    while (server.length < 6 && Date.now() < deadline) {
      if (server.length !== last) {
        last = server.length;
        times.push(Date.now());
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    const gaps = times.slice(1).map((time, index) => time - times[index]!);
    // 20, 40, 80, 80, 80 ms — each gap at least its step (timers do not fire early).
    for (const [index, minimum] of [20, 40, 80, 80].entries()) {
      assert.ok(gaps[index]! >= minimum - 2, `gap ${index}: ${gaps[index]} ms < ${minimum}`);
    }
    assert.ok(gaps[3]! < 80 * 4, `the ceiling holds: ${gaps[3]} ms`);
  } finally {
    await watch.stop();
    await api.close();
  }
});
