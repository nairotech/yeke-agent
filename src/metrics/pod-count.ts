/**
 * Per-node count of the pods that hold a scheduler slot (`pods.count`).
 *
 * ─── What is counted ────────────────────────────────────────────────────────
 *
 * A pod is counted on node N when it is BOUND to N (`spec.nodeName=N`) and has
 * not terminated (`status.phase` is neither `Succeeded` nor `Failed`). That is
 * the set the scheduler charges against `status.allocatable.pods`: when it
 * reaches the allocatable number, the scheduler answers "Too many pods". The
 * kubelet's Summary cannot give this number — it lists only pods whose
 * containers are running. Measured on a local k3s with `max-pods=12`
 * (13.10.2026): with the node full the scheduler said "Too many pods", this
 * count said 12 and the Summary listed 10; the pods it missed were pending,
 * pulling an image or waiting out a crash back-off.
 *
 * ─── What is asked, and what is NOT sent back ──────────────────────────────
 *
 * One metadata WATCH per node, under the agent's own identity:
 *
 *   GET /api/v1/pods?fieldSelector=spec.nodeName=<n>,status.phase!=Succeeded,status.phase!=Failed
 *   Accept: application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1   (LIST)
 *   Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1       (WATCH)
 *
 * The two `Accept` values are `owners.ts`'s, unchanged: the apiserver returns
 * `metadata` only, never `spec` or `status`. The two body fields appear only as
 * a server-side PREDICATE; membership in the answer tells the agent the coarse
 * value of both ("bound to this node", "not terminated") and nothing more. The
 * agent keeps a set of pod UIDs per node — no names, no labels, nothing else —
 * and hands the collector only its size. This widening of the identity
 * invariant's third job is recorded in the README ("What the agent does under
 * its own identity") and in the decision document's revision note.
 *
 * ─── Why a WATCH and not a LIST every 60 seconds ────────────────────────────
 *
 * The decision (13.10.2026) preferred a LIST every second tick and named this
 * watch as the fallback, behind a cost gate: if one LIST per node per minute
 * cost more than 25 % of today's Summary reading (~40 MB/min at 100 nodes),
 * the watch was to be used. MEASURED on k3s v1.31.5, 13.10.2026: a pod's
 * `PartialObjectMetadata` is 1 945–3 768 bytes (2 174 on average, 75 % of it
 * `managedFields`), uncompressed — the apiserver gzips only answers above
 * 128 KiB, and the agent does not ask for gzip at all. 2 174 B × 110 pods ×
 * 100 nodes is ~23.9 MB/min, against a 10 MB/min gate. The LIST path was
 * therefore not built. Two more measurements shaped the code below:
 *
 *  · `resourceVersion=0` IGNORES `limit` (limit=2 returned all 12 pods, no
 *    `continue`). The pagination loop is kept for servers that do page, and
 *    its continuation pages are sent WITHOUT `resourceVersion`.
 *  · A pod that LEAVES the selector arrives as `DELETED` (a Job pod turning
 *    `Succeeded`, a deleted pod after its `Terminating` MODIFIED), a pending
 *    pod that gets bound arrives as `ADDED`, and BOOKMARKs came ~60 s apart and
 *    2 s before the server-side timeout.
 *
 * ─── Why a watch cannot freeze a number here ────────────────────────────────
 *
 * The decision's objection to a watch was that a stuck stream keeps serving a
 * plausible, wrong number until undici's body timeout — exactly when the
 * feature should warn. Three rules close that:
 *
 *  1. The server is asked to end every stream after ~60 s (`timeoutSeconds`,
 *     spread per node so 100 watches do not reconnect in the same second). A
 *     clean end resumes from the last seen revision — bookmarks keep it fresh —
 *     so it costs headers, not a LIST.
 *  2. undici's body timeout is that timeout + 30 s: a stream that goes silent
 *     past its own deadline is cut, counted as a failure, and the number is
 *     gone (NaN) until a fresh LIST.
 *  3. `read()` returns a number only if the stream showed life (LIST done,
 *     headers, an event or a bookmark) within `POD_COUNT_STALE_MS`. This holds
 *     even if 1 and 2 were somehow bypassed.
 *
 * ─── Failure means NO number ────────────────────────────────────────────────
 *
 * 401, 403, 5xx, a timeout, a broken stream, a half-delivered page, a 410 or
 * an `ERROR` event: the count becomes "no reading" (NaN on the wire) until a
 * complete LIST has been applied again. Never 0, never the partial size —
 * "0 pods" and "N-3 pods" are both numbers a screen would believe.
 */
import { type Dispatcher, request } from "undici";
import type { KubeTarget } from "../kube.js";
import {
  ApiserverHttpError,
  METADATA_LIST_ACCEPT,
  METADATA_WATCH_ACCEPT,
  delay,
  ndjson,
} from "./owners.js";

/** The scheduler's own selector for "this pod occupies a slot on node N". */
export function podCountFieldSelector(node: string): string {
  return `spec.nodeName=${node},status.phase!=Succeeded,status.phase!=Failed`;
}

/** Page size for the LIST; `resourceVersion=0` ignores it (measured), other servers may not. */
export const POD_COUNT_LIST_LIMIT = 500;

/** Base server-side watch timeout; each node adds 0–14 s so reconnects spread out. */
export const POD_COUNT_WATCH_TIMEOUT_SECONDS = 60;

/**
 * A count older than this is not a reading.
 *
 * Two watch periods: a healthy stream shows life at least once per period
 * (its reconnect headers, and on current apiservers a bookmark each minute).
 */
export const POD_COUNT_STALE_MS = 120_000;

/** Ceiling for one LIST page and for a watch's response headers. */
export const POD_COUNT_REQUEST_TIMEOUT_MS = 10_000;

/**
 * Backoff after a failed LIST or WATCH. One collector period: a failed node
 * costs the apiserver one request per tick, not one every five seconds per
 * node.
 */
export const POD_COUNT_RETRY_MS = 30_000;

/** Why a node has no count right now. Codes for the log line, never sent on the wire. */
export type PodCountState = "ok" | "pending" | "stale" | "unauthorized" | "forbidden" | "unreachable";

export type PodCountReading =
  | { readonly ok: true; readonly count: number }
  | { readonly ok: false; readonly state: Exclude<PodCountState, "ok">; readonly detail?: string };

export interface PodCounterOptions {
  readonly target: KubeTarget;
  /** The agent clock; staleness is measured on it. */
  readonly now?: () => number;
  readonly retryMs?: number;
  /** Overridden by the tests so a stream ends without waiting a minute. */
  readonly watchTimeoutSeconds?: (node: string) => number;
  /** `POD_COUNT_REQUEST_TIMEOUT_MS` unless a test needs a timeout it can wait for. */
  readonly requestTimeoutMs?: number;
}

/** 60–74 s, fixed per node name: no randomness to test around, no reconnect herd. */
function spreadTimeout(node: string): number {
  let hash = 0;
  for (let index = 0; index < node.length; index += 1) {
    hash = (hash * 31 + node.charCodeAt(index)) >>> 0;
  }
  return POD_COUNT_WATCH_TIMEOUT_SECONDS + (hash % 15);
}

/** A 410 inside the stream: the revision aged out; LIST again. Not a failure. */
class Relist extends Error {}

/**
 * One node's watch. LIST once, then WATCH from the revision it last saw;
 * re-LIST only when the revision expires or something fails.
 */
export class NodePodWatch {
  readonly node: string;
  readonly #options: PodCounterOptions;
  readonly #now: () => number;
  readonly #retryMs: number;
  readonly #requestTimeoutMs: number;
  readonly #abort = new AbortController();
  #running = false;
  #loop: Promise<void> | undefined;

  /** UIDs only. The SIZE is the reading; the set exists so events are idempotent. */
  #uids = new Set<string>();
  /** True between a complete LIST and the next failure. */
  #synced = false;
  #resourceVersion: string | undefined;
  #aliveAt = 0;
  /** Why there is no number; meaningful only while not synced. */
  #state: Exclude<PodCountState, "ok" | "stale"> = "pending";
  #detail: string | undefined;
  /** Logged state, so a line is written on a CHANGE only (`ResourceWatch#setForbidden`). */
  #loggedState: PodCountState = "ok";

  /** Requests made, for the tests and the measurement harness. */
  lists = 0;
  watches = 0;
  failures = 0;

  constructor(node: string, options: PodCounterOptions) {
    this.node = node;
    this.#options = options;
    this.#now = options.now ?? Date.now;
    this.#retryMs = options.retryMs ?? POD_COUNT_RETRY_MS;
    this.#requestTimeoutMs = options.requestTimeoutMs ?? POD_COUNT_REQUEST_TIMEOUT_MS;
  }

  start(): void {
    if (this.#running) return;
    this.#running = true;
    this.#loop = this.#run();
  }

  async stop(): Promise<void> {
    this.#running = false;
    this.#abort.abort();
    await this.#loop?.catch(() => undefined);
    this.#loop = undefined;
  }

  read(): PodCountReading {
    if (!this.#synced) {
      return this.#detail === undefined
        ? { ok: false, state: this.#state }
        : { ok: false, state: this.#state, detail: this.#detail };
    }
    const age = this.#now() - this.#aliveAt;
    if (age > POD_COUNT_STALE_MS) {
      this.#log("stale", `no event, bookmark or reconnect for ${age} ms`);
      return { ok: false, state: "stale", detail: `${age} ms` };
    }
    return { ok: true, count: this.#uids.size };
  }

  async #run(): Promise<void> {
    while (this.#running) {
      try {
        if (!this.#synced || this.#resourceVersion === undefined) await this.#list();
        await this.#watch();
      } catch (err) {
        if (!this.#running) return;
        this.#unsync();
        if (err instanceof Relist) continue;
        this.failures += 1;
        const status = err instanceof ApiserverHttpError ? err.statusCode : undefined;
        this.#state = status === 401 ? "unauthorized" : status === 403 ? "forbidden" : "unreachable";
        this.#detail = err instanceof Error ? err.message : String(err);
        this.#log(this.#state, this.#detail);
        await delay(this.#retryMs, this.#abort.signal);
      }
    }
  }

  /** Every failure path ends here: the number is gone, not kept. */
  #unsync(): void {
    this.#synced = false;
    this.#resourceVersion = undefined;
    this.#uids = new Set();
  }

  #alive(): void {
    this.#aliveAt = this.#now();
    if (this.#synced) {
      this.#state = "pending";
      this.#detail = undefined;
      this.#log("ok");
    }
  }

  /**
   * The full LIST. The set is built aside and swapped in only when the LAST
   * page has arrived: a failure on page 2 leaves no partial count behind.
   */
  async #list(): Promise<void> {
    const uids = new Set<string>();
    let cont: string | undefined;
    let resourceVersion: string | undefined;
    do {
      const query = new URLSearchParams({
        fieldSelector: podCountFieldSelector(this.node),
        limit: String(POD_COUNT_LIST_LIMIT),
      });
      // `resourceVersion=0` on the first page only: it lets the apiserver
      // answer from its watch cache through the `spec.nodeName` index instead
      // of reading every pod from etcd. Continuation pages carry `continue`
      // alone, which already pins the snapshot.
      if (cont) query.set("continue", cont);
      else query.set("resourceVersion", "0");
      this.lists += 1;
      const body = (await this.#json(`/api/v1/pods?${query}`)) as {
        metadata?: { resourceVersion?: string; continue?: string };
        items?: { metadata?: { uid?: string } }[];
      };
      if (!Array.isArray(body.items)) throw new Error("pod LIST answer has no items");
      for (const item of body.items) {
        const uid = item.metadata?.uid;
        if (uid) uids.add(uid);
      }
      resourceVersion = body.metadata?.resourceVersion ?? resourceVersion;
      cont = body.metadata?.continue || undefined;
    } while (cont);
    if (!resourceVersion) throw new Error("pod LIST answer has no resourceVersion");
    this.#uids = uids;
    this.#resourceVersion = resourceVersion;
    this.#synced = true;
    this.#alive();
  }

  async #watch(): Promise<void> {
    const timeoutSeconds = (this.#options.watchTimeoutSeconds ?? spreadTimeout)(this.node);
    const query = new URLSearchParams({
      fieldSelector: podCountFieldSelector(this.node),
      watch: "1",
      allowWatchBookmarks: "true",
      resourceVersion: this.#resourceVersion ?? "",
      timeoutSeconds: String(timeoutSeconds),
    });
    this.watches += 1;
    const response = await this.#open(`/api/v1/pods?${query}`, METADATA_WATCH_ACCEPT, (timeoutSeconds + 30) * 1000);
    if (response.statusCode === 410) {
      await response.body.dump();
      throw new Relist();
    }
    await this.#check(response);
    this.#alive();

    for await (const line of ndjson(response.body)) {
      if (!this.#running) return;
      const event = JSON.parse(line) as {
        type?: string;
        object?: { code?: number; metadata?: { uid?: string; resourceVersion?: string } };
      };
      if (event.type === "ERROR") {
        // 410 Gone is the routine "revision too old"; anything else is a
        // failure. Either way the set is no longer known to be complete.
        if (event.object?.code === 410) throw new Relist();
        throw new Error(`watch ERROR event${event.object?.code ? ` ${event.object.code}` : ""}`);
      }
      const uid = event.object?.metadata?.uid;
      const revision = event.object?.metadata?.resourceVersion;
      if (revision) this.#resourceVersion = revision;
      if (event.type === "ADDED" || event.type === "MODIFIED") {
        if (uid) this.#uids.add(uid);
      } else if (event.type === "DELETED") {
        if (uid) this.#uids.delete(uid);
      }
      this.#alive();
    }
    // A clean end is the server-side timeout: resume from the last revision.
  }

  async #open(path: string, accept: string, bodyTimeout: number) {
    const { target } = this.#options;
    return request(`${target.baseUrl}${path}`, {
      method: "GET",
      dispatcher: target.dispatcher,
      headers: { ...(await target.authHeaders()), accept },
      signal: this.#abort.signal,
      headersTimeout: this.#requestTimeoutMs,
      bodyTimeout,
    });
  }

  async #check(response: Dispatcher.ResponseData): Promise<void> {
    if (response.statusCode === 401) {
      await response.body.dump();
      this.#options.target.invalidateCredential("apiserver returned 401");
      throw new ApiserverHttpError(401);
    }
    if (response.statusCode >= 300) {
      await response.body.dump();
      throw new ApiserverHttpError(response.statusCode);
    }
  }

  async #json(path: string): Promise<unknown> {
    const response = await this.#open(path, METADATA_LIST_ACCEPT, this.#requestTimeoutMs);
    await this.#check(response);
    return response.body.json();
  }

  #log(state: PodCountState, detail?: string): void {
    if (state === this.#loggedState) return;
    const previous = this.#loggedState;
    this.#loggedState = state;
    if (state === "ok") {
      console.warn(`[metrics] pod count for node ${this.node} restored (was ${previous})`);
      return;
    }
    console.warn(`[metrics] pod count for node ${this.node} unavailable: ${state}${detail ? `: ${detail}` : ""}`);
  }
}

/** One `NodePodWatch` per known node; started and stopped as nodes come and go. */
export class NodePodCounter {
  readonly #options: PodCounterOptions;
  readonly #watches = new Map<string, NodePodWatch>();
  #stopped = false;

  constructor(options: PodCounterOptions) {
    this.#options = options;
  }

  /** Makes the watched set equal `nodes`. Cheap when nothing changed. */
  sync(nodes: Iterable<string>): void {
    if (this.#stopped) return;
    const wanted = new Set(nodes);
    for (const [node, watch] of this.#watches) {
      if (wanted.has(node)) continue;
      this.#watches.delete(node);
      void watch.stop();
    }
    for (const node of wanted) {
      if (this.#watches.has(node)) continue;
      const watch = new NodePodWatch(node, this.#options);
      this.#watches.set(node, watch);
      watch.start();
    }
  }

  read(node: string): PodCountReading {
    return this.#watches.get(node)?.read() ?? { ok: false, state: "pending" };
  }

  /** For the tests and the measurement harness. */
  watchOf(node: string): NodePodWatch | undefined {
    return this.#watches.get(node);
  }

  get size(): number {
    return this.#watches.size;
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    const all = [...this.#watches.values()];
    this.#watches.clear();
    await Promise.all(all.map((watch) => watch.stop()));
  }
}
