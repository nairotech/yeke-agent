/**
 * HTTP client for the kubelet's read-only statistics endpoints.
 *
 * ─── Why the collector talks to the kubelet DIRECTLY ────────────────────────
 *
 * The obvious road is the apiserver's proxy
 * (`/api/v1/nodes/<node>/proxy/stats/summary`): one RBAC verb, one address, no
 * per-node TLS problem. K4 rejected it and the reason is the name of that verb.
 * It is `nodes/proxy`, and `nodes/proxy` also covers the kubelet's `exec` and
 * `attach` endpoints — granting it means granting the ability to run commands
 * inside containers. A component whose stated job is to read numbers should not
 * hold a verb that reaches that far, and a security review of this repository
 * would be right to stop there.
 *
 * The direct road needs `get` on `nodes/stats` and `nodes/metrics` and nothing
 * else. The kubelet maps `/stats/*` to the `nodes/stats` subresource and
 * `/metrics/*` to `nodes/metrics`, then asks the apiserver with a
 * SubjectAccessReview — so the ceiling is still RBAC the cluster owner applied
 * and can revoke. It also keeps 100 requests per 30 seconds (50 nodes, two
 * each) off the apiserver entirely.
 *
 * ─── The token is read from the file on EVERY request ───────────────────────
 *
 * The projected ServiceAccount token rotates, and a token cached in memory
 * starts returning 401 some time after the kubelet swaps the file. This is not
 * a hypothesis: it is the documented failure of the OpenTelemetry kubeletstats
 * receiver (open-telemetry/opentelemetry-collector-contrib #26120), and K4
 * names it.
 *
 * `serviceAccountToken` from `src/kube.ts` is reused rather than re-written, so
 * that a token read failure is classified as an IDENTITY failure here exactly
 * as it is on the apiserver path (`kube.test.ts`). Its 60-second TTL cache is
 * defeated on purpose by invalidating before each read. Configuring the TTL to
 * zero was the tidier-looking alternative and it is wrong: the cache check is
 * `now() - readAt <= ttlMs`, so a TTL of zero still serves two requests that
 * land in the same millisecond -- which is precisely what the two reads of one
 * node do. The cost of the honest version is one small file read per request,
 * 100 per 30 seconds at 50 nodes.
 *
 * On a 401 the token is re-read and the request is retried ONCE. Not twice: a
 * second failure means the identity is invalid rather than stale, and retrying
 * a rejected credential in a loop is how a component gets itself rate-limited
 * by the very server it is trying to reach.
 *
 * ─── TLS, and why the failure is loud ───────────────────────────────────────
 *
 * The kubelet's serving certificate is verified against the cluster CA
 * (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`). In a large share of
 * real clusters that verification FAILS, and not because anything is wrong with
 * this code: kubeadm does not sign kubelet serving certificates with the
 * cluster CA by default (`serverTLSBootstrap` is off), which is why
 * metrics-server ships `--kubelet-insecure-tls` in most installation guides and
 * the OpenTelemetry receiver's documentation suggests
 * `insecure_skip_verify: true`.
 *
 * YEKE does not do that silently. A node whose certificate cannot be verified
 * produces NO data and is reported as `tls-unverified`; the operator can accept
 * the weakness explicitly with `YEKE_KUBELET_INSECURE_TLS=true`, and when they
 * do, the acceptance is visible in the startup log and on the screen. The
 * precedent is the direct-mode import's `acknowledgeInsecureTLS` /
 * `INSECURE_TLS_NOT_ACKNOWLEDGED` pair: an obstacle is reported, not routed
 * around.
 */
import { Agent, type Dispatcher, request } from "undici";
import type { NodeStateCode } from "./types.js";

/** The kubelet's authenticated read-only port. 10255 is closed on modern clusters. */
export const KUBELET_PORT = 10250;

/**
 * Upper bound for one kubelet request.
 *
 * Shorter than the 30 second sampling period on purpose: a node that has not
 * answered by then must be reported as unreachable before the next tick starts,
 * or two ticks end up in flight against the same node and the rate arithmetic
 * sees an interval it cannot explain.
 */
const REQUEST_TIMEOUT_MS = 10_000;

/**
 * TLS verification failures, as Node reports them.
 *
 * The list is OpenSSL's verify codes plus Node's own hostname check. It is a
 * list and not a substring match on the message because the message is foreign
 * text that changes between Node releases; the codes are part of OpenSSL's
 * interface and do not.
 */
const TLS_VERIFY_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_REVOKED",
  "CERT_SIGNATURE_FAILURE",
  "CERT_UNTRUSTED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "HOSTNAME_MISMATCH",
  "INVALID_CA",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNSUPPORTED_CERTIFICATE_PURPOSE",
]);

/** The node the collector is about to read, as the node watch reported it. */
export interface KubeletTarget {
  readonly node: string;
  /** The node's `InternalIP`. K4: addresses come from the node object. */
  readonly address: string;
  /**
   * The node's own kubelet port, when it published one.
   *
   * A property of the NODE and not of the client: `--port` is a kubelet flag
   * and the node object answers it (`status.daemonEndpoints.kubeletEndpoint`).
   * Falls back to the client's default, which is 10250.
   */
  readonly port?: number;
}

/**
 * The two reads the collector performs, as an interface rather than the class.
 *
 * Written for one reason and it is worth naming: a failure that the collector
 * has to survive — a read that throws, a read that never settles — cannot be
 * produced through a socket, because every socket in `KubeletClient` has its
 * own ceiling and turns both of those into a tidy `unreachable`. Testing the
 * collector's own robustness needs a seam ABOVE the transport. `KubeletClient`
 * satisfies this structurally; nothing in production implements it twice.
 */
export interface KubeletReader {
  summary<T>(target: KubeletTarget): Promise<KubeletResult<T>>;
  cadvisor<T>(
    target: KubeletTarget,
    consume: (lines: AsyncIterable<string>) => Promise<T>,
  ): Promise<KubeletResult<T>>;
}

export type KubeletResult<T> =
  | { readonly state: "ok"; readonly value: T }
  | { readonly state: Exclude<NodeStateCode, "ok">; readonly detail?: string };

/**
 * Request counters.
 *
 * Kept per client rather than per node: their reader is the operator asking
 * "is the collector working at all", and 50 separate counters answer a
 * different question. Per-node state is already carried, per node, in the
 * frame's `NodeState`.
 */
export interface KubeletCounters {
  requests: number;
  ok: number;
  timeout: number;
  tlsUnverified: number;
  unauthorized: number;
  forbidden: number;
  unreachable: number;
  /** 401s that a token re-read fixed. A rising number is a rotation working. */
  tokenRetries: number;
}

export interface TokenReader {
  read(): Promise<string>;
  invalidate(): void;
}

export interface KubeletClientOptions {
  readonly token: TokenReader;
  /** The cluster CA. Absent only in the insecure mode. */
  readonly ca?: Buffer;
  /** `YEKE_KUBELET_INSECURE_TLS` — an explicit, logged acceptance (K4). */
  readonly insecureTls: boolean;
  readonly timeoutMs?: number;
  readonly port?: number;
  /** Injected by the tests and the measurement harness; production uses undici's own. */
  readonly dispatcher?: Dispatcher;
}

export class KubeletClient {
  readonly #token: TokenReader;
  readonly #dispatcher: Dispatcher;
  readonly #ownsDispatcher: boolean;
  readonly #timeoutMs: number;
  readonly #port: number;
  readonly counters: KubeletCounters = {
    requests: 0,
    ok: 0,
    timeout: 0,
    tlsUnverified: 0,
    unauthorized: 0,
    forbidden: 0,
    unreachable: 0,
    tokenRetries: 0,
  };

  constructor(options: KubeletClientOptions) {
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
    this.#port = options.port ?? KUBELET_PORT;

    if (options.dispatcher) {
      this.#dispatcher = options.dispatcher;
      this.#ownsDispatcher = false;
    } else {
      // One pool for every kubelet: connections are keyed by origin inside
      // undici, so 50 nodes share one Agent and its keep-alive settings without
      // sharing a socket.
      this.#dispatcher = new Agent({
        connect: options.insecureTls
          ? { rejectUnauthorized: false }
          : { ca: options.ca, rejectUnauthorized: true },
        headersTimeout: this.#timeoutMs,
        bodyTimeout: this.#timeoutMs,
      });
      this.#ownsDispatcher = true;
    }

    if (options.insecureTls) {
      // One line, once, at startup. Its reader is the operator running
      // `kubectl logs yeke-agent`, so it is English and ASCII-only (README,
      // "Conventions"). It says what was given up, not that a flag is set.
      console.warn(
        "[metrics] YEKE_KUBELET_INSECURE_TLS=true: kubelet server certificates are NOT verified. " +
          "Statistics are collected over connections that could be intercepted inside the cluster network.",
      );
    }
  }

  /** `GET /stats/summary` — the typed document, parsed by `summary.ts`. */
  async summary<T>(target: KubeletTarget): Promise<KubeletResult<T>> {
    return this.#get(target, "/stats/summary", async (body) => (await body.json()) as T);
  }

  /**
   * `GET /metrics/cadvisor` — handed to `consume` as a line stream.
   *
   * The body never becomes a string. On a node with 30 pods this document is
   * megabytes of text of which four families survive; materialising it would
   * put the whole thing in the agent's heap 50 times over, once per node, right
   * next to a 64 MiB RSS target.
   */
  async cadvisor<T>(
    target: KubeletTarget,
    consume: (lines: AsyncIterable<string>) => Promise<T>,
  ): Promise<KubeletResult<T>> {
    return this.#get(target, "/metrics/cadvisor", (body) => consume(lines(body)));
  }

  async close(): Promise<void> {
    if (this.#ownsDispatcher) await this.#dispatcher.close();
  }

  async #get<T>(
    target: KubeletTarget,
    path: string,
    consume: (body: Dispatcher.ResponseData["body"]) => Promise<T>,
  ): Promise<KubeletResult<T>> {
    const first = await this.#attempt(target, path, consume);
    if (first.state !== "unauthorized") return first;

    // A 401 is the shape a rotated token takes. Re-read and try exactly once;
    // the second failure is an invalid identity, not a stale one.
    this.counters.tokenRetries += 1;
    this.#token.invalidate();
    return this.#attempt(target, path, consume);
  }

  async #attempt<T>(
    target: KubeletTarget,
    path: string,
    consume: (body: Dispatcher.ResponseData["body"]) => Promise<T>,
  ): Promise<KubeletResult<T>> {
    this.counters.requests += 1;
    let token: string;
    try {
      // Invalidate first: this is what "read the file on every request" means,
      // and the header of this file explains why a zero TTL is not the same
      // thing.
      this.#token.invalidate();
      token = await this.#token.read();
    } catch (err) {
      // An `AgentFailure` with `CREDENTIAL_UNAVAILABLE` / `TOKEN_FILE_EMPTY`.
      // It is the agent's own identity that is missing, not the node's, but
      // from the collector's point of view this node produced no data and the
      // detail carries the code so the operator is not sent to the kubelet.
      this.counters.unauthorized += 1;
      return { state: "unauthorized", detail: messageOf(err) };
    }

    const url = `https://${bracket(target.address)}:${target.port ?? this.#port}${path}`;
    try {
      const response = await request(url, {
        method: "GET",
        dispatcher: this.#dispatcher,
        headers: {
          authorization: `Bearer ${token}`,
          // Asking for the typed document explicitly. The kubelet answers JSON
          // for `/stats/summary` regardless, but a Prometheus-shaped answer
          // would otherwise be parsed as one and fail somewhere further down.
          accept: "application/json, text/plain",
        },
        signal: AbortSignal.timeout(this.#timeoutMs),
      });

      if (response.statusCode === 401) {
        // The body must be drained or the connection is not returned to the pool.
        await response.body.dump();
        this.counters.unauthorized += 1;
        return { state: "unauthorized" };
      }
      if (response.statusCode === 403) {
        await response.body.dump();
        this.counters.forbidden += 1;
        // K4/K5: this is the "the manifest has not been re-applied" state. The
        // ClusterRole gained `nodes/stats` and `nodes/metrics` with this
        // feature, and the agent cannot widen its own RBAC.
        return { state: "forbidden" };
      }
      if (response.statusCode >= 300) {
        await response.body.dump();
        this.counters.unreachable += 1;
        return { state: "unreachable", detail: `HTTP ${response.statusCode}` };
      }

      const value = await consume(response.body);
      this.counters.ok += 1;
      return { state: "ok", value };
    } catch (err) {
      return this.#classify(err);
    }
  }

  #classify(err: unknown): KubeletResult<never> {
    const detail = messageOf(err);
    for (let cause: unknown = err, depth = 0; cause && depth < 5; depth += 1) {
      const code = (cause as { code?: unknown }).code;
      if (typeof code === "string") {
        if (TLS_VERIFY_CODES.has(code)) {
          this.counters.tlsUnverified += 1;
          // K4: no data for this node. Not a partial reading, not a zero.
          //
          // The OpenSSL code is prefixed onto the message here, not left for
          // the caller to look up separately: `collector.ts` logs this
          // `detail` verbatim on a state change, and the code is the part of
          // it that survives across Node releases (see the header comment on
          // `TLS_VERIFY_CODES` above) -- the operator reading `kubectl logs`
          // gets a stable string to search for, not just foreign prose.
          return { state: "tls-unverified", detail: `${code} — ${detail}` };
        }
        if (code === "UND_ERR_HEADERS_TIMEOUT" || code === "UND_ERR_BODY_TIMEOUT") {
          this.counters.timeout += 1;
          return { state: "unreachable", detail };
        }
      }
      if ((cause as { name?: unknown }).name === "TimeoutError") {
        this.counters.timeout += 1;
        return { state: "unreachable", detail };
      }
      cause = (cause as { cause?: unknown }).cause;
    }
    this.counters.unreachable += 1;
    return { state: "unreachable", detail };
  }
}

/** Foreign text, verbatim: Node's and undici's messages are theirs, not ours. */
function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** An IPv6 `InternalIP` needs brackets in a URL; an IPv4 one must not have them. */
function bracket(address: string): string {
  return address.includes(":") ? `[${address}]` : address;
}

/**
 * Splits a response body into lines without ever holding the whole document.
 *
 * The chunk boundary falls in the middle of a line often enough that getting
 * this wrong is not a rare failure: the tail of a chunk is carried into the
 * next one. The final partial line is emitted too — the exposition format's
 * last line may arrive without a trailing newline.
 */
async function* lines(body: AsyncIterable<Buffer | string>): AsyncIterable<string> {
  let carry = "";
  for await (const chunk of body) {
    const text = carry + (typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    let start = 0;
    for (;;) {
      const newline = text.indexOf("\n", start);
      if (newline < 0) break;
      // `\r` is not in the exposition format, but a proxy in front of a kubelet
      // has been known to add one and a trailing `\r` turns a value into NaN.
      const end = newline > start && text.charCodeAt(newline - 1) === 13 ? newline - 1 : newline;
      yield text.slice(start, end);
      start = newline + 1;
    }
    carry = text.slice(start);
  }
  if (carry.length > 0) yield carry;
}
