/**
 * Node discovery and the pod -> workload owner chain.
 *
 * The kubelet answers "how much", never "whose". A pod's series is only useful
 * once the control plane can roll it up into the Deployment it belongs to, and
 * that mapping lives in the apiserver. This file is the only part of the
 * collector that talks to the apiserver, and everything it asks for is bounded
 * by the closed list in `2026-09-09-yeke-izleme-kimlik-degismezi.md` K1.
 *
 * ─── Metadata only, and what that costs ─────────────────────────────────────
 *
 * Pods and ReplicaSets are watched with
 * `Accept: application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1`.
 * The apiserver then serves the object's `metadata` and nothing else: no
 * `spec`, no `status`, no `data`. This is not a filter applied after receiving
 * the object — the body is never sent, so there is no version of this code
 * that could accidentally read one.
 *
 * That is what makes the agent's third self-identity job legal. The invariant
 * says these jobs read no object bodies; asking for `PartialObjectMetadata` is
 * how a program says that to the apiserver rather than to a code reviewer.
 *
 * Nodes ARE read in full, and K4 permits it explicitly: addresses,
 * `allocatable`, conditions and the kubelet version are all in the node object,
 * a node carries no Secret, and the collector cannot reach a kubelet without
 * the address.
 *
 * ─── The restart counter: measured, and left out of Phase 1 ─────────────────
 *
 * K3's table lists "restarts / waiting reason" as a Phase 1 pod metric, sourced
 * from "pod status (the same stream as the owner watch)". It is not produced
 * here, and this is the reasoning rather than an oversight.
 *
 * The count lives in `status.containerStatuses[].restartCount`. `status` is
 * part of the object BODY. The identity invariant, written on the same day as
 * K3 and about the same collector, says these jobs read no object bodies. The
 * two sentences cannot both be honoured, so the question is which one is the
 * decision and which one is the wish. The invariant is the decision: it is the
 * reason the collector is allowed to exist at all, it is the sentence the
 * public README repeats to a security reviewer, and widening it requires
 * revising a decision document rather than adding a field to a request.
 *
 * Three roads were considered:
 *
 *  (a) Watch pods as FULL objects. It works and it is what every metrics agent
 *      does. It also breaks the invariant in the most consequential way: a full
 *      pod watch streams `spec`, which carries `env` values, and
 *      `metadata.managedFields`, which is routinely the largest part of a pod
 *      object. The agent would be holding, in memory, in every customer
 *      cluster, exactly the class of content the invariant exists to keep it
 *      away from. Rejected on the invariant, not on the bytes.
 *
 *  (b) Take it from the kubelet. It is not there. The Summary API has no
 *      restart count, and the four cAdvisor families read here do not either.
 *      (`container_start_time_seconds` moves when a container restarts, but it
 *      is a start time, not a count: it cannot distinguish one restart from
 *      forty, and a metric that answers a different question is not a
 *      substitute for the one on the table.)
 *
 *  (c) Leave it out of Phase 1 and say so. Chosen. The metric NAME stays in the
 *      vocabulary (`types.ts`) so a later phase does not need a protocol bump;
 *      no sample is ever emitted for it, and `collector.test.ts` asserts that
 *      mechanically so this comment cannot quietly become false.
 *
 * One road was NOT taken because it could not be measured here: the apiserver's
 * Table conversion (`Accept: application/json;as=Table;g=meta.k8s.io;v=v1`)
 * returns server-rendered columns, and the default pod columns include
 * RESTARTS. That would carry the number without any object body. Whether Table
 * supports `watch` well enough to keep an index fresh, and whether the column
 * set is stable enough to key on, are questions about a live apiserver, and no
 * live apiserver was available in the round that wrote this file. Implementing
 * it on the strength of a recollection would be exactly the fabrication this
 * repository's conventions forbid. It is written down as the next thing to
 * measure, and the decision document has to be the place that accepts it.
 */
import { request } from "undici";
import type { KubeTarget } from "../kube.js";
import type { AttributeName, EntityOwner } from "./types.js";

/** How the apiserver is asked for metadata instead of an object. */
const METADATA_LIST_ACCEPT = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1";
/**
 * A watch stream carries single objects, so it negotiates the singular kind.
 * This is the pair client-go's metadata client uses; sending the list form on a
 * watch is answered with full objects by some server versions, which would
 * defeat the entire point without any visible symptom.
 */
const METADATA_WATCH_ACCEPT = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1";

/** Page size for the initial LIST. Large enough for one round trip per 500 pods. */
const LIST_LIMIT = 500;

/**
 * Server-side watch timeout.
 *
 * A watch that never ends is a watch that silently stops delivering when a
 * middlebox drops the idle connection. Asking the apiserver to close it every
 * few minutes makes the reconnect a normal, exercised path instead of a rare
 * one.
 */
const WATCH_TIMEOUT_SECONDS = 300;

export interface OwnerReference {
  readonly kind: string;
  readonly name: string;
  readonly uid: string;
  readonly controller?: boolean;
}

/** What a metadata watch keeps about one object. */
export interface MetaRecord {
  readonly uid: string;
  readonly kind: string;
  readonly name: string;
  readonly namespace?: string;
  readonly owners: readonly OwnerReference[];
}

/**
 * Walks the owner chain to the top-level workload.
 *
 * Pod -> ReplicaSet -> Deployment and Pod -> Job -> CronJob are the two shapes
 * with a middle link; Pod -> StatefulSet / DaemonSet arrive in one hop, and a
 * bare pod has no owner at all.
 *
 * The walk stops at the last link the index KNOWS. It does not invent the next
 * one: a pod owned by a ReplicaSet whose record has not arrived yet is reported
 * as owned by that ReplicaSet, which is true, rather than by a Deployment whose
 * name was guessed from the ReplicaSet's (the `<deployment>-<hash>` convention
 * is a convention, and a hand-written ReplicaSet does not follow it).
 *
 * Phase 1 populates the index with pods and ReplicaSets only, because that is
 * what the ClusterRole in the identity decision grants. A pod owned by a Job
 * therefore resolves to the JOB, not to its CronJob — correct, and one hop
 * short. Making it two hops means watching `batch/jobs`, which means a fourth
 * entry in the closed list of self-identity jobs, which means revising that
 * document. The walker itself needs no change: it is written against the index,
 * not against a list of kinds.
 *
 * `maxDepth` is a cycle guard. Owner references can be made to point in a
 * circle by hand, and an unbounded walk in an agent running in someone else's
 * cluster is a hang, not a bug report.
 */
export function resolveOwner(
  index: ReadonlyMap<string, MetaRecord>,
  start: MetaRecord,
  maxDepth = 4,
): EntityOwner | undefined {
  let current = start;
  let owner: EntityOwner | undefined;
  for (let depth = 0; depth < maxDepth; depth += 1) {
    // `controller: true` is the ONE reference that owns the lifecycle. A pod
    // can carry several references (an operator adding its own), and taking the
    // first would attribute the series to whichever one the apiserver happened
    // to serialise first.
    const reference = current.owners.find((item) => item.controller) ?? current.owners[0];
    if (!reference) return owner;
    owner = { kind: reference.kind, name: reference.name, uid: reference.uid };
    const next = index.get(reference.uid);
    if (!next) return owner;
    current = next;
  }
  return owner;
}

/** What the collector needs about a node, out of the full node object. */
export interface NodeRecord {
  readonly name: string;
  readonly uid?: string;
  /** `InternalIP`; the collector cannot read a node without one. */
  readonly address?: string;
  /**
   * The kubelet's serving port, from `status.daemonEndpoints.kubeletEndpoint.Port`.
   *
   * Almost always 10250, and reading it rather than assuming it costs one field:
   * `--port` is a kubelet flag, the node object publishes the answer, and a
   * cluster that moved it would otherwise show every node as unreachable with
   * no clue as to why. (The capital `P` is the API's, not a typo.)
   */
  readonly port?: number;
  readonly ready: boolean;
  readonly kubeletVersion?: string;
  readonly attributes: Readonly<Partial<Record<AttributeName, number>>>;
}

/**
 * Kubernetes quantities -> numbers.
 *
 * Only the suffixes that appear in a node's `allocatable`/`capacity` are
 * handled: CPU in cores or milli-cores, memory and storage in binary or decimal
 * SI. An unrecognised suffix returns `undefined` rather than a number that is
 * wrong by a factor of 1024 — a denominator that is quietly off by three orders
 * of magnitude produces a utilisation chart that looks plausible and is not.
 */
export function parseQuantity(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const match = /^([0-9.]+)([a-zA-Z]*)$/.exec(raw.trim());
  if (!match) return undefined;
  const value = Number(match[1]);
  if (!Number.isFinite(value)) return undefined;
  switch (match[2]) {
    case "":
      return value;
    case "m":
      return value / 1000;
    case "k":
      return value * 1e3;
    case "M":
      return value * 1e6;
    case "G":
      return value * 1e9;
    case "T":
      return value * 1e12;
    case "P":
      return value * 1e15;
    case "Ki":
      return value * 1024;
    case "Mi":
      return value * 1024 ** 2;
    case "Gi":
      return value * 1024 ** 3;
    case "Ti":
      return value * 1024 ** 4;
    case "Pi":
      return value * 1024 ** 5;
    default:
      return undefined;
  }
}

interface RawNode {
  metadata?: { name?: string; uid?: string };
  status?: {
    addresses?: { type?: string; address?: string }[];
    allocatable?: Record<string, string>;
    capacity?: Record<string, string>;
    conditions?: { type?: string; status?: string }[];
    nodeInfo?: { kubeletVersion?: string };
    daemonEndpoints?: { kubeletEndpoint?: { Port?: number } };
  };
}

export function decodeNode(raw: unknown): NodeRecord | undefined {
  const node = raw as RawNode;
  const name = node.metadata?.name;
  if (!name) return undefined;
  const attributes: Partial<Record<AttributeName, number>> = {};
  const put = (key: AttributeName, value: number | undefined): void => {
    if (value !== undefined) attributes[key] = value;
  };
  put("cpu.allocatable", parseQuantity(node.status?.allocatable?.["cpu"]));
  put("mem.allocatable", parseQuantity(node.status?.allocatable?.["memory"]));
  put("fs.allocatable", parseQuantity(node.status?.allocatable?.["ephemeral-storage"]));
  put("pods.allocatable", parseQuantity(node.status?.allocatable?.["pods"]));
  put("cpu.capacity", parseQuantity(node.status?.capacity?.["cpu"]));
  put("mem.capacity", parseQuantity(node.status?.capacity?.["memory"]));

  return {
    name,
    uid: node.metadata?.uid,
    // `InternalIP` and not `Hostname`: K4 dials the address, and a hostname
    // that only the cluster's DNS resolves is not an address the agent's pod
    // can necessarily reach.
    address: node.status?.addresses?.find((item) => item.type === "InternalIP")?.address,
    port: node.status?.daemonEndpoints?.kubeletEndpoint?.Port,
    ready: node.status?.conditions?.some(
      (item) => item.type === "Ready" && item.status === "True",
    ) ?? false,
    kubeletVersion: node.status?.nodeInfo?.kubeletVersion,
    attributes,
  };
}

interface RawMeta {
  kind?: string;
  metadata?: {
    uid?: string;
    name?: string;
    namespace?: string;
    ownerReferences?: { kind?: string; name?: string; uid?: string; controller?: boolean }[];
  };
}

export function decodeMeta(raw: unknown, fallbackKind: string): MetaRecord | undefined {
  const object = raw as RawMeta;
  const uid = object.metadata?.uid;
  const name = object.metadata?.name;
  if (!uid || !name) return undefined;
  const owners: OwnerReference[] = [];
  for (const reference of object.metadata?.ownerReferences ?? []) {
    if (!reference.kind || !reference.name || !reference.uid) continue;
    owners.push({
      kind: reference.kind,
      name: reference.name,
      uid: reference.uid,
      controller: reference.controller === true,
    });
  }
  return {
    uid,
    // A `PartialObjectMetadata` answer carries `kind: "PartialObjectMetadata"`,
    // not the kind of the thing it describes, so the caller's kind wins.
    kind: fallbackKind,
    name,
    namespace: object.metadata?.namespace,
    owners,
  };
}

export interface WatchHandlers<T> {
  /** An object appeared or changed. Called for every LIST item too. */
  applied(item: T, uid: string): void;
  deleted(uid: string): void;
  /**
   * A LIST completed. The set is authoritative at that instant, so the caller
   * can drop everything it holds that is not in it — a delete that arrived
   * while the watch was broken is otherwise invisible forever.
   */
  resynced(uids: ReadonlySet<string>): void;
}

export interface ResourceWatchOptions<T> {
  readonly target: KubeTarget;
  /** e.g. `/api/v1/pods`, `/apis/apps/v1/replicasets`, `/api/v1/nodes`. */
  readonly path: string;
  /**
   * Short label for this watch's resource, e.g. `"nodes"`, `"pods"`,
   * `"replicasets"`. Used only for the forbidden/restored log line — the
   * operator reading `kubectl logs` needs to know WHICH of the closed list's
   * three watches the ClusterRole is missing, not just that one of them is.
   */
  readonly resource: string;
  /** `true` for pods and ReplicaSets; `false` for nodes (K4 allows the body). */
  readonly metadataOnly: boolean;
  readonly decode: (raw: unknown) => T | undefined;
  readonly handlers: WatchHandlers<T>;
  /** Backoff after a failed watch. Injected so the tests do not sleep. */
  readonly retryMs?: number;
}

/**
 * An apiserver response outside 2xx, carrying the status code so the catch
 * site can tell a 403 (RBAC — the manifest needs re-applying) apart from a 401
 * (identity, already handled by `invalidateCredential`), a 5xx or a watch
 * that simply timed out. A bare `Error` with the code baked into the message
 * would make that distinction a string parse; this makes it a field.
 */
class ApiserverHttpError extends Error {
  constructor(readonly statusCode: number) {
    super(`HTTP ${statusCode}`);
  }
}

/**
 * LIST once, then WATCH from that revision, forever, until stopped.
 *
 * The shape is the standard informer contract and it is written by hand for the
 * same reason the rest of `kube.ts` is: `@kubernetes/client-node`'s informer
 * builds its own request pipeline and cannot be pointed at the dispatcher and
 * the identity this repository already resolves, and it has no way to ask for
 * `PartialObjectMetadata` — which is not a detail here, it is the whole
 * invariant.
 */
export class ResourceWatch<T> {
  readonly #options: ResourceWatchOptions<T>;
  readonly #retryMs: number;
  #abort: AbortController | undefined;
  #running = false;
  #loop: Promise<void> | undefined;
  /**
   * Rising while the apiserver is unreachable.
   *
   * Surfaced through `Collector.stats()` rather than logged on every retry: a
   * watch that cannot connect retries every five seconds, and a log line per
   * attempt would bury the reason it failed under the fact that it keeps
   * failing.
   */
  failures = 0;
  /**
   * True when the MOST RECENT attempt (LIST or WATCH) was refused with 403.
   *
   * Not latched across error types: a 401, a 5xx or a network error after a
   * 403 clears it, because those are not evidence the manifest is missing —
   * only a 403 is. A successful LIST also clears it. This is what
   * `Collector` reads to tell the wire the whole collector is `forbidden`
   * rather than merely `degraded` (`collectorStatusOf` in `wire.ts`).
   */
  #forbidden = false;
  /** So the log line below fires on a CHANGE, not on every five-second retry. */
  #loggedForbidden = false;

  get forbidden(): boolean {
    return this.#forbidden;
  }

  constructor(options: ResourceWatchOptions<T>) {
    this.#options = options;
    this.#retryMs = options.retryMs ?? 5_000;
  }

  start(): void {
    if (this.#running) return;
    this.#running = true;
    this.#abort = new AbortController();
    this.#loop = this.#run();
  }

  async stop(): Promise<void> {
    this.#running = false;
    this.#abort?.abort();
    await this.#loop?.catch(() => undefined);
    this.#loop = undefined;
  }

  async #run(): Promise<void> {
    while (this.#running) {
      try {
        const resourceVersion = await this.#list();
        this.#setForbidden(false);
        await this.#watch(resourceVersion);
      } catch (err) {
        if (!this.#running) return;
        this.failures += 1;
        // A 403 on `nodes`/`pods`/`apps/replicasets` LIST or WATCH is the
        // closed-list RBAC failure K1 names: the manifest was not re-applied
        // after the ClusterRole gained these verbs. Anything else — 401
        // (already handled below), a 5xx, a timeout, DNS — is not evidence of
        // that, and stays `degraded` at the collector level.
        this.#setForbidden(err instanceof ApiserverHttpError && err.statusCode === 403);
        // Foreign text, verbatim. The operator reading `kubectl logs` is the
        // audience; the control plane is told through the collector's state,
        // not through this line.
        console.warn(
          `[metrics] watch ${this.#options.path} failed, retrying: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
        await delay(this.#retryMs);
      }
    }
  }

  /**
   * Updates `#forbidden` and, only on a CHANGE, logs which resource is
   * denied. Without the change guard this would log every five seconds for
   * as long as the manifest stays stale — "durum değişince, dakikada bir
   * değil".
   */
  #setForbidden(forbidden: boolean): void {
    this.#forbidden = forbidden;
    if (forbidden === this.#loggedForbidden) return;
    this.#loggedForbidden = forbidden;
    console.warn(
      forbidden
        ? `[metrics] apiserver denied ${this.#options.resource} (403) — re-apply the agent manifest to grant list/watch on ${this.#options.resource}`
        : `[metrics] apiserver access to ${this.#options.resource} restored`,
    );
  }

  async #list(): Promise<string> {
    const seen = new Set<string>();
    let cont: string | undefined;
    let resourceVersion = "";
    do {
      const query = new URLSearchParams({ limit: String(LIST_LIMIT) });
      if (cont) query.set("continue", cont);
      const body = (await this.#json(`${this.#options.path}?${query}`, false)) as {
        metadata?: { resourceVersion?: string; continue?: string };
        items?: unknown[];
      };
      resourceVersion = body.metadata?.resourceVersion ?? resourceVersion;
      cont = body.metadata?.continue || undefined;
      for (const raw of body.items ?? []) {
        const uid = (raw as RawMeta).metadata?.uid;
        const item = this.#options.decode(raw);
        if (!uid || !item) continue;
        seen.add(uid);
        this.#options.handlers.applied(item, uid);
      }
    } while (cont);
    this.#options.handlers.resynced(seen);
    return resourceVersion;
  }

  async #watch(resourceVersion: string): Promise<void> {
    const query = new URLSearchParams({
      watch: "1",
      allowWatchBookmarks: "true",
      resourceVersion,
      timeoutSeconds: String(WATCH_TIMEOUT_SECONDS),
    });
    const response = await this.#open(`${this.#options.path}?${query}`, true);
    if (response.statusCode === 410) {
      // The revision aged out of the apiserver's window. The contract's answer
      // is to LIST again, which the outer loop does.
      await response.body.dump();
      return;
    }
    if (response.statusCode >= 300) {
      await response.body.dump();
      throw new ApiserverHttpError(response.statusCode);
    }

    for await (const line of ndjson(response.body)) {
      if (!this.#running) return;
      const event = JSON.parse(line) as { type?: string; object?: unknown };
      // A BOOKMARK carries only a resource version; there is nothing to decode
      // and nothing to apply. Its whole job is to let a reconnect start from a
      // recent revision instead of paying for a fresh LIST.
      if (event.type === "BOOKMARK") continue;
      if (event.type === "ERROR") return; // relist
      const uid = (event.object as RawMeta | undefined)?.metadata?.uid;
      if (!uid) continue;
      if (event.type === "DELETED") {
        this.#options.handlers.deleted(uid);
        continue;
      }
      const item = this.#options.decode(event.object);
      if (item) this.#options.handlers.applied(item, uid);
    }
  }

  async #open(path: string, watch: boolean) {
    const { target } = this.#options;
    const accept = this.#options.metadataOnly
      ? watch
        ? METADATA_WATCH_ACCEPT
        : METADATA_LIST_ACCEPT
      : "application/json";
    return request(`${target.baseUrl}${path}`, {
      method: "GET",
      dispatcher: target.dispatcher,
      headers: { ...(await target.authHeaders()), accept },
      signal: this.#abort?.signal,
      // A watch stays open for `WATCH_TIMEOUT_SECONDS`; undici's default body
      // timeout would kill it long before the apiserver does.
      bodyTimeout: watch ? (WATCH_TIMEOUT_SECONDS + 30) * 1000 : 30_000,
      headersTimeout: 30_000,
    });
  }

  async #json(path: string, watch: boolean): Promise<unknown> {
    const response = await this.#open(path, watch);
    if (response.statusCode === 401) {
      await response.body.dump();
      // The apiserver path's own hook: the cached identity is dropped and the
      // next call resolves it again (`KubeTarget.invalidateCredential`).
      this.#options.target.invalidateCredential("apiserver returned 401");
      throw new ApiserverHttpError(401);
    }
    if (response.statusCode >= 300) {
      await response.body.dump();
      throw new ApiserverHttpError(response.statusCode);
    }
    return response.body.json();
  }
}

async function* ndjson(body: AsyncIterable<Buffer | string>): AsyncIterable<string> {
  let carry = "";
  for await (const chunk of body) {
    const text = carry + (typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    let start = 0;
    for (;;) {
      const newline = text.indexOf("\n", start);
      if (newline < 0) break;
      const line = text.slice(start, newline).trim();
      if (line) yield line;
      start = newline + 1;
    }
    carry = text.slice(start);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms).unref?.();
  });
}
