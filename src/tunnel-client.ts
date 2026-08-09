/**
 * The tunnel client: opens a single **outbound** WebSocket to the control plane
 * and applies the incoming HTTP requests to the downstream apiserver.
 *
 * Because the connection direction is cluster → control plane, the downstream
 * side needs no inbound firewall rule, no port-forward and no VPN; outbound 443
 * is enough.
 */
import { WebSocket, type RawData } from "ws";
import { request } from "undici";
import {
  AGENT_CLUSTER_HEADER,
  AGENT_TOKEN_HEADER,
  CreditWindow,
  MAX_REQUEST_BODY_BYTES,
  RESPONSE_CREDIT_WINDOW_BYTES,
  TUNNEL_LIVENESS_TIMEOUT_MS,
  TUNNEL_PING_INTERVAL_MS,
  TUNNEL_PROTOCOL_VERSION,
  decodeBodyFrame,
  describeFailure,
  encodeBodyFrame,
  parseControlMessage,
  serializeControlMessage,
  type ControlMessage,
  type RequestMessage,
  type StreamOpenMessage,
  type TunnelFailure,
} from "@nairotech/yeke-tunnel";
import type { AgentConfig } from "./config.js";
import { failureOf } from "./failure.js";
import { readKubernetesVersion, resolveKubeTarget, type KubeTarget } from "./kube.js";
import { UpstreamStream } from "./stream.js";

/**
 * The version the agent reports to the control plane — and therefore to the
 * cluster card in the user interface.
 *
 * ─── The measured failure (product owner, 2026-08-04) ───────────────────────
 *
 * The user interface was showing the wrong agent version: the image running in
 * the cluster was `nairotech/yeke-agent:0.4.25` while the card said `0.1.0`. The
 * interface was drawing it correctly; the one LYING was the agent itself — this
 * constant was hand-written and had no link whatsoever to the release tag, so it
 * had been silently going stale on every release since 0.1.0.
 *
 * ─── Why we do not read it from `package.json` ──────────────────────────────
 *
 * `package.json` also says `0.1.0`, and that is deliberate: in this repository
 * the package version is not a RELEASE version, it is a fixed placeholder. The
 * release version is the control plane's, not the agent's own (see "Lockstep" in
 * README.md). Reading from there would repeat the same mistake from a different
 * file — the source of the bug was not where the value lived but that it had no
 * link to the release.
 *
 * The ONLY truth about the release version is the image tag; that is why the
 * value enters the image as a build argument (`Dockerfile`, `ARG YEKE_VERSION`).
 *
 * ─── Why the fallback is `"unknown"` ────────────────────────────────────────
 *
 * An agent started without the variable (local development, a manual
 * `node dist/index.js`) does NOT know its version, and saying so is better than
 * inventing a number. `"unknown"` also matches the control plane's initial value
 * for the tunnel session.
 *
 * CORRECTION (2026-08-04): the sentence here used to claim "the interface
 * already draws this state as '—'" and that was WRONG — the interface only
 * filtered nullish values, so this string passed the filter and was printed on
 * screen as `Agent unknown`. The fallback value itself is right; what was
 * missing was the reader side, and it was fixed in one place in the control
 * plane's web layer. Had this wrong comment not been corrected, it would have
 * legitimised the same assumption again on the next round.
 */
const AGENT_VERSION = process.env.YEKE_VERSION?.trim() || "unknown";

/**
 * The allowlist of paths the agent is willing to touch on the control plane's
 * behalf.
 *
 * A tunnel agent is structurally a hole punched outward through the cluster
 * perimeter, and whoever holds the other end can ask it to dial. If the set of
 * reachable addresses is open-ended — the shape some tunnel designs take, where
 * the authorizer accepts any `tcp` target — then a compromised control plane
 * reaches everything the pod's network namespace reaches: neighbouring services,
 * the container runtime socket, the cloud metadata endpoint.
 *
 * The tunnel's only legitimate target here is the apiserver, so the surface is
 * narrowed to it. The point is not that a wider authorizer would be
 * *unauthorized*; it is that this request cannot be expressed at all.
 */
const ALLOWED_PATH_PREFIXES = ["/api", "/apis", "/openapi", "/version", "/healthz", "/livez", "/readyz"];

function isAllowedPath(path: string): boolean {
  if (!path.startsWith("/")) return false;
  if (path.includes("..")) return false;
  return ALLOWED_PATH_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`) || path.startsWith(`${p}?`));
}

/** Hop-by-hop and identity headers that must not be forwarded to the apiserver. */
const STRIPPED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "authorization",
  "proxy-authorization",
  "content-length",
  // `Expect: 100-continue` is a handshake between the client and the control
  // plane and has already completed there (in Node's HTTP server); by the time
  // it reaches us the body is in hand. Carrying it downstream is meaningless,
  // and undici rejects it outright ("expect header not supported") — curl adds
  // this header by itself for bodies over 1 MiB, so in practice it was breaking
  // large POSTs.
  "expect",
]);

// `CreditWindow` is used at both ends in v4 (response body: agent → control
// plane; stdin: control plane → agent) and lives in `@nairotech/yeke-tunnel`. Had
// the waiting rule ("credit > 0", not "credit ≥ chunk") existed in two copies,
// the day they diverged the result would have been a permanent deadlock —
// visible only when a chunk larger than the window arrived.

interface InFlight {
  abort: AbortController;
  /** Remaining credit for this request's response body. */
  credit: CreditWindow;
}

/**
 * The buffer that collects one request's body.
 *
 * It exists to close a race: the `req` control message and the body frames are
 * delivered by separate 'message' events, usually in separate IO turns. If the
 * request handler read the body as "whatever I have right now", large bodies
 * would come out truncated or empty almost every time. So the handler waits here
 * until `reqend` arrives — the wait is not a latency guess but the end signal
 * the protocol declares explicitly.
 *
 * Kept as a list of chunks (not a single Buffer): the protocol allows the body
 * to be split into N frames, and streaming request bodies will take the same
 * path later.
 */
class RequestBody {
  #chunks: Buffer[] = [];
  #bytes = 0;
  #state: "open" | "complete" | "aborted" | "overflow" = "open";
  #wake: (() => void) | null = null;

  get state(): "open" | "complete" | "aborted" | "overflow" {
    return this.#state;
  }

  push(chunk: Buffer): void {
    if (this.#state !== "open") return;
    this.#bytes += chunk.byteLength;
    if (this.#bytes > MAX_REQUEST_BODY_BYTES) {
      // A request over the limit will be rejected anyway; drop what was
      // collected immediately so a compromised control plane cannot inflate the
      // agent's memory.
      this.#chunks = [];
      this.#settle("overflow");
      return;
    }
    this.#chunks.push(chunk);
  }

  /** `reqend`: the body is complete. */
  complete(): void {
    this.#settle("complete");
  }

  /** Cancellation or a dropped connection: discard the half buffer, wake the waiter. */
  abort(): void {
    this.#chunks = [];
    this.#settle("aborted");
  }

  /** Waits until the body closes (complete/aborted/over the limit). */
  wait(): Promise<void> {
    if (this.#state !== "open") return Promise.resolve();
    return new Promise((resolve) => {
      this.#wake = resolve;
    });
  }

  take(): Buffer {
    const body = Buffer.concat(this.#chunks);
    this.#chunks = [];
    return body;
  }

  #settle(state: "complete" | "aborted" | "overflow"): void {
    if (this.#state !== "open") return;
    this.#state = state;
    const wake = this.#wake;
    this.#wake = null;
    wake?.();
  }
}

export class TunnelClient {
  #config: AgentConfig;
  #target: KubeTarget | null = null;
  #socket: WebSocket | null = null;
  #inFlight = new Map<number, InFlight>();
  #requestBodies = new Map<number, RequestBody>();
  /** Open v4 streams; the id space is shared with requests (the control plane splits it). */
  #streams = new Map<number, UpstreamStream>();
  /**
   * The negotiated version reported by the control plane (`welcome.protocol`).
   *
   * If the field is absent the peer is a v3 control plane and 3 is the correct
   * assumption: treating the unknown as 4 would mean trying to send stream
   * frames to a v3 peer.
   */
  #protocol = 0;
  #backoff: number;
  #stopped = false;
  /** When the last message was received from the control plane; the sole criterion for the keepalive decision. */
  #lastSeenAt = Date.now();
  #liveness: NodeJS.Timeout | null = null;

  constructor(config: AgentConfig) {
    this.#config = config;
    this.#backoff = config.reconnectMinMs;
  }

  /**
   * Diagnostic: the number of half-finished body buffers. Kept public so that
   * the cancellation/disconnect paths can be verified from the outside not to
   * leak buffers.
   */
  get pendingBodyCount(): number {
    return this.#requestBodies.size;
  }

  /** Diagnostic: requests waiting to be applied to the apiserver, or in progress. */
  get inFlightCount(): number {
    return this.#inFlight.size;
  }

  /** Diagnostic: streams open to the apiserver (so a leak can be measured from the outside). */
  get streamCount(): number {
    return this.#streams.size;
  }

  /** Diagnostic: the negotiated tunnel version reported by the control plane. */
  get protocolVersion(): number {
    return this.#protocol;
  }

  async start(): Promise<void> {
    this.#target = await resolveKubeTarget(this.#config);
    console.log(`[agent] apiserver: ${this.#target.baseUrl}`);
    this.#connect();
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    this.#stopLiveness();
    this.#abortAll();
    this.#socket?.close();
    await this.#target?.close();
  }

  #connect(): void {
    if (this.#stopped) return;

    const socket = new WebSocket(this.#config.coreUrl, {
      headers: {
        [AGENT_TOKEN_HEADER]: this.#config.token,
        [AGENT_CLUSTER_HEADER]: this.#config.clusterId,
      },
    });
    this.#socket = socket;

    socket.on("open", async () => {
      this.#backoff = this.#config.reconnectMinMs;
      console.log("[agent] core connection opened");
      this.#lastSeenAt = Date.now();
      this.#startLiveness(socket);
      this.#send({
        t: "hello",
        protocol: TUNNEL_PROTOCOL_VERSION,
        agentVersion: AGENT_VERSION,
        kubernetesVersion: this.#target ? await readKubernetesVersion(this.#target) : undefined,
      });
    });

    socket.on("message", (data, isBinary) => {
      // The criterion is "any message", not "pong": the control plane's `ping`,
      // its `req` or its `credit` — each of them is proof that it is alive.
      this.#lastSeenAt = Date.now();
      if (isBinary) this.#onBodyFrame(data as Buffer);
      else this.#onControl(data);
    });

    socket.on("close", (code, reason) => {
      console.warn(`[agent] connection closed (${code}) ${reason.toString()}`);
      this.#stopLiveness();
      this.#cleanupAfterDisconnect();
      this.#scheduleReconnect();
    });

    socket.on("error", (err) => {
      console.error(`[agent] connection error: ${err.message}`);
    });
  }

  /**
   * How the death of the control plane is noticed.
   *
   * Because the control plane sends a `ping` every `TUNNEL_PING_INTERVAL_MS`,
   * receiving **no** message at all for that long is abnormal; after
   * `TUNNEL_LIVENESS_TIMEOUT_MS` (3 periods) of silence the connection is
   * considered dead. The agent does not ping from its own side: on a half-dead
   * connection an outgoing ping is written into the void anyway, and what makes
   * the diagnosis is the absence of incoming messages.
   *
   * `terminate()` is used because `close()` waits for a closing handshake; while
   * the peer is not answering, that handshake never completes and reconnection
   * would never be triggered either. `terminate()` produces the 'close' event
   * immediately, so the existing reconnect/backoff logic engages through its
   * normal path.
   */
  #startLiveness(socket: WebSocket): void {
    this.#stopLiveness();
    this.#liveness = setInterval(() => {
      if (Date.now() - this.#lastSeenAt <= TUNNEL_LIVENESS_TIMEOUT_MS) return;
      console.warn(
        `[agent] core silent for ${TUNNEL_LIVENESS_TIMEOUT_MS} ms; connection considered dead`,
      );
      socket.terminate();
    }, TUNNEL_PING_INTERVAL_MS);
    this.#liveness.unref();
  }

  #stopLiveness(): void {
    if (this.#liveness) clearInterval(this.#liveness);
    this.#liveness = null;
  }

  #cleanupAfterDisconnect(): void {
    // Open requests belong to this session; when the control plane reconnects it
    // re-establishes the watches from scratch, so cancelling all of them is the
    // correct behaviour.
    this.#abortAll();
  }

  /**
   * Releases every open request and body buffer.
   *
   * Handlers waiting on a body are woken up via `RequestBody.abort()`; otherwise
   * they would wait forever for a `reqend` that will never come, leaking both
   * the buffer and their own completion.
   */
  #abortAll(): void {
    for (const { abort } of this.#inFlight.values()) abort.abort();
    this.#inFlight.clear();
    for (const body of this.#requestBodies.values()) body.abort();
    this.#requestBodies.clear();
    // Streams close as well: when the tunnel drops, the control plane cannot
    // **resume** that session (exec has no `resync`), and a pty left open on the
    // apiserver side would be a process nobody is reading.
    for (const stream of this.#streams.values()) stream.close(1001, "tunnel disconnected");
    this.#streams.clear();
  }

  #scheduleReconnect(): void {
    if (this.#stopped) return;
    const delay = this.#backoff;
    this.#backoff = Math.min(this.#backoff * 2, this.#config.reconnectMaxMs);
    setTimeout(() => this.#connect(), delay);
  }

  #send(message: ControlMessage): void {
    if (this.#socket?.readyState === WebSocket.OPEN) {
      this.#socket.send(serializeControlMessage(message));
    }
  }

  #sendBody(requestId: number, payload: Uint8Array): void {
    if (this.#socket?.readyState === WebSocket.OPEN) {
      this.#socket.send(encodeBodyFrame(requestId, payload));
    }
  }

  /**
   * Writes the failure to the wire and drops **the same line** into the agent's
   * own stdout.
   *
   * Both jobs in one place because if they are separated one of them gets
   * forgotten: a failure written to the wire but not to the log is invisible to
   * the operator running `kubectl logs yeke-agent` — and that visibility was the
   * only legitimate function of the `message` field removed in that round. The
   * line is English and machine-readable (`describeFailure`): its reader is the
   * operator of the customer's cluster, not the user in front of the interface
   * (see "Conventions" in README.md).
   *
   * Most branches also write a more detailed English line at their own point
   * (the credential plugin family, for example); the line here is not a record
   * of that detail but of "what went on the wire".
   */
  #fail(id: number, failure: TunnelFailure): void {
    console.warn(`[agent] request ${id} failed: ${describeFailure(failure)}`);
    this.#send({ t: "err", id, ...failure });
  }

  #onControl(raw: RawData): void {
    let message: ControlMessage;
    try {
      message = parseControlMessage(raw.toString());
    } catch (err) {
      console.error(`[agent] unparseable control message: ${(err as Error).message}`);
      return;
    }

    switch (message.t) {
      case "welcome":
        // No `protocol` means the peer is a v3 control plane (it never sends the field).
        this.#protocol = message.protocol ?? 3;
        console.log(
          `[agent] registered — cluster=${message.clusterId} session=${message.sessionId} protocol=v${this.#protocol}`,
        );
        break;
      case "req": {
        // Both the body buffer and the abort controller are registered **here**,
        // before the handler starts. In the time it takes the handler to reach
        // its first await, a body frame or a `cancel` may arrive; had the
        // registrations been on that side, the body would be orphaned and the
        // `cancel` would be lost, leaving a watch on the apiserver that never
        // closes.
        const abort = new AbortController();
        // The window opens implicitly together with `req`: both ends know
        // RESPONSE_CREDIT_WINDOW_BYTES, so there is no opening round trip.
        const credit = new CreditWindow(RESPONSE_CREDIT_WINDOW_BYTES);
        this.#inFlight.set(message.id, { abort, credit });
        if (message.hasBody) this.#requestBodies.set(message.id, new RequestBody());
        // The window is passed to the handler as a parameter: even if `cancel`
        // removes the map entry, the reference the handler holds stays valid, so
        // an `undefined` check cannot silently degrade into an unbounded stream.
        void this.#handleRequest(message, abort, credit);
        break;
      }
      case "reqend":
        this.#requestBodies.get(message.id)?.complete();
        break;
      case "cancel": {
        this.#inFlight.get(message.id)?.abort.abort();
        this.#inFlight.delete(message.id);
        // A handler waiting on the body is woken up; a half buffer that never
        // reached a handler is dropped here too (so nothing leaks).
        this.#requestBodies.get(message.id)?.abort();
        this.#requestBodies.delete(message.id);
        // `cancel` can also arrive with a stream id (the id space is shared):
        // cancelling a stream means closing its upstream socket.
        this.#closeStream(message.id, 1000, "cancelled");
        break;
      }
      case "credit": {
        // An id with no record is dropped silently: the late credit of a
        // cancelled request must not open a new window. In v4 the same message
        // also arrives for the stdout/stderr direction of a stream — that it
        // does not state a direction is by design: credit is always granted by
        // the **receiver**.
        this.#inFlight.get(message.id)?.credit.grant(message.bytes);
        this.#streams.get(message.id)?.grantCredit(message.bytes);
        break;
      }
      case "stropen": {
        void this.#openStream(message);
        break;
      }
      case "strclose": {
        this.#closeStream(message.id, message.code ?? 1000, message.reason);
        break;
      }
      case "ping":
        this.#send({ t: "pong", ts: message.ts });
        break;
      default:
        break;
    }
  }

  #onBodyFrame(frame: Buffer): void {
    const decoded = decodeBodyFrame(frame);
    if (!decoded) return;
    // If it is a stream id, the payload is written straight to the apiserver:
    // its first byte is k8s's channel byte and the agent does **not** interpret
    // it (the one exception being the half-close gate, see
    // `UpstreamStream.write`).
    const stream = this.#streams.get(decoded.requestId);
    if (stream) {
      stream.write(decoded.payload);
      return;
    }
    // Ids with no record are dropped silently: a late frame of a cancelled or
    // rejected request must not create a new map entry — in v1 that left buffers
    // that were never collected.
    this.#requestBodies.get(decoded.requestId)?.push(decoded.payload);
  }

  /**
   * `stropen`: opens a WebSocket to the apiserver and reports the outcome with
   * `strok` or `err`.
   *
   * Two gates shared with request handling (`#handleRequest`) run here as well,
   * and they must: the **path allowlist** (even if the control plane is
   * compromised, the agent only goes to apiserver paths) and **impersonation**
   * (the final say on authorization belongs to Kubernetes RBAC). Measured:
   * impersonation headers are both carried and enforced on the WS upgrade
   * request.
   */
  async #openStream(message: StreamOpenMessage): Promise<void> {
    const target = this.#target;
    if (!target) {
      this.#fail(message.id, { code: "NO_TARGET", params: {} });
      return;
    }
    if (!isAllowedPath(message.path)) {
      this.#fail(message.id, { code: "PATH_NOT_ALLOWED", params: { path: message.path } });
      return;
    }
    if (message.protocols.length === 0) {
      // The wire schema already rejects this (`z.array().min(1)`); the gate is
      // here too because a stream opened with an empty list would fall back to
      // the unversioned `channel.k8s.io` and the failure would surface months
      // later as "exit codes are always 0".
      this.#fail(message.id, { code: "STREAM_PROTOCOL_REQUIRED", params: {} });
      return;
    }
    if (this.#streams.has(message.id)) return;

    try {
      const headers: Record<string, string | string[]> = {};
      if (message.impersonate) {
        headers["Impersonate-User"] = message.impersonate.user;
        if (message.impersonate.groups.length > 0) {
          headers["Impersonate-Group"] = message.impersonate.groups;
        }
      }
      // The order is binding: `authHeaders()` can replace the TLS material
      // during an exec refresh, so `tlsOptions()` is read AFTER it (the same
      // rule as the dispatcher in `#handleRequest`).
      Object.assign(headers, await target.authHeaders());
      const tls = target.tlsOptions();

      // `https:` → `wss:`. Rather than writing the scheme by hand we derive it
      // from the target.
      const base = target.baseUrl.replace(/^http/, "ws");
      const url = `${base}${message.path}${message.query ? `?${message.query}` : ""}`;

      const stream = new UpstreamStream(
        { url, protocols: [...message.protocols], headers, tls },
        {
          onOpen: (protocol) => this.#send({ t: "strok", id: message.id, protocol }),
          onFrame: (frame) => this.#sendBody(message.id, frame),
          onStdinDelivered: (bytes) => this.#send({ t: "credit", id: message.id, bytes }),
          onClose: (code, reason) => {
            this.#streams.delete(message.id);
            this.#send({ t: "strclose", id: message.id, code, reason });
          },
          onError: (failure) => {
            this.#streams.delete(message.id);
            this.#fail(message.id, failure);
          },
        },
      );
      this.#streams.set(message.id, stream);
    } catch (err) {
      // The only way to land here is identity resolution and TLS material
      // (`authHeaders`, `tlsOptions`): the socket does not exist yet. Identity
      // failures arrive already typed as `AgentFailure` and pass through AS IS —
      // the fallback branch is only for an unclassifiable error, and even then
      // the `detail` is Node's text, not ours.
      //
      // `origin: "node"` is this very comment, except now it is IN THE SCHEMA:
      // for one round it was only written here, and the user interface still
      // printed "what the socket reported:" — while no socket had reported
      // anything. The comment was right, nobody read it; a truth without a gate
      // is violated sooner or later.
      this.#fail(
        message.id,
        failureOf(err, (detail) => ({
          code: "EXEC_UPGRADE_UNREACHABLE",
          params: { origin: "node", detail },
        })),
      );
    }
  }

  #closeStream(id: number, code: number, reason?: string): void {
    const stream = this.#streams.get(id);
    if (!stream) return;
    this.#streams.delete(id);
    stream.close(code, reason);
  }

  async #handleRequest(
    req: RequestMessage,
    abort: AbortController,
    credit: CreditWindow,
  ): Promise<void> {
    const target = this.#target;
    if (!target) {
      this.#rejectRequest(req, { code: "NO_TARGET", params: {} });
      return;
    }

    if (!isAllowedPath(req.path)) {
      // Defense in depth: even if the control plane is compromised, the agent
      // only goes to apiserver paths.
      this.#rejectRequest(req, { code: "PATH_NOT_ALLOWED", params: { path: req.path } });
      return;
    }

    try {
      const headers: Record<string, string> = {};
      for (const [key, value] of Object.entries(req.headers)) {
        if (!STRIPPED_REQUEST_HEADERS.has(key.toLowerCase())) headers[key] = value;
      }

      const finalHeaders: Record<string, string | string[]> = { ...headers };

      // Delegate authorization to Kubernetes: the request is applied with the
      // identity of the user who made it. That way the real user appears in the
      // downstream audit log and the product does not have to write its own
      // authorization engine. `Impersonate-Group` is a multi-valued header and
      // undici accepts a `string[]` directly, emitting each value as its own
      // header line — there is no need for an intermediate representation that
      // joins the groups into one string (and splits them again before the
      // apiserver).
      if (req.impersonate) {
        finalHeaders["Impersonate-User"] = req.impersonate.user;
        if (req.impersonate.groups.length > 0) {
          finalHeaders["Impersonate-Group"] = req.impersonate.groups;
        }
      }

      // If there is a body we stop here until `reqend` arrives. This wait is
      // part of the protocol: sending a request with an incomplete body to the
      // apiserver means the apiserver treats it as an empty body and returns
      // 400 — that is, silent data loss.
      let payload: Buffer | undefined;
      if (req.hasBody) {
        const body = this.#requestBodies.get(req.id);
        // No buffer means the request was cancelled before we took it over; the
        // control plane has long forgotten this id, so there is no point sending
        // an error either.
        if (!body) return;
        await body.wait();
        if (body.state === "aborted" || abort.signal.aborted) return;
        if (body.state === "overflow") {
          this.#fail(req.id, {
            code: "BODY_TOO_LARGE",
            params: { maxBytes: MAX_REQUEST_BODY_BYTES },
          });
          return;
        }
        payload = body.take();
      }

      // The identity is resolved at the **last moment**, after the body wait:
      // for short-lived tokens produced by `exec` plugins, the narrower the
      // window the better. The order is also binding — since `authHeaders()` can
      // replace `target.dispatcher` during a refresh, the dispatcher must be
      // read AFTER it (see `syncDispatcher` in kube.ts).
      Object.assign(finalHeaders, await target.authHeaders());

      const url = `${target.baseUrl}${req.path}${req.query ? `?${req.query}` : ""}`;
      const response = await request(url, {
        method: req.method as never,
        headers: finalHeaders,
        body: payload,
        dispatcher: target.dispatcher,
        signal: abort.signal,
        // Watches and `logs -f` flow indefinitely; we disable undici's default timeouts.
        headersTimeout: 0,
        bodyTimeout: 0,
      });

      // 401 = "the apiserver did not accept our identity". Short-lived
      // credentials (an exec plugin, a rotating tokenFile) can become invalid
      // earlier than expected; dropping the cache here makes the next request
      // resolve it again. We still forward the response as-is to the control
      // plane — silently retrying the request would change the result the caller
      // sees.
      if (response.statusCode === 401) {
        console.warn(`[agent] apiserver returned 401 (${req.method} ${req.path})`);
        target.invalidateCredential("apiserver 401");
      }

      const responseHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(response.headers)) {
        if (value === undefined) continue;
        responseHeaders[key] = Array.isArray(value) ? value.join(", ") : String(value);
      }

      this.#send({ t: "res", id: req.id, status: response.statusCode, headers: responseHeaders });

      // Response-body flow control is applied here. Because the `await` is
      // inside the loop, `for await` is suspended when credit runs out; undici
      // does not pull the next chunk and backpressure travels over TCP all the
      // way to the apiserver. We do not take the chunk into memory and count it
      // as "sent" — no buffer is displaced, production really stops.
      for await (const chunk of response.body) {
        if (abort.signal.aborted) break;
        const payload = chunk as Uint8Array;
        await credit.wait(abort.signal);
        // The session may have been cancelled or dropped while waiting; leave
        // without trying to write to a closed one.
        if (abort.signal.aborted) break;
        credit.consume(payload.byteLength);
        this.#sendBody(req.id, payload);
      }

      if (!abort.signal.aborted) this.#send({ t: "end", id: req.id });
    } catch (err) {
      if (!abort.signal.aborted) {
        // The fallback branch is `UPSTREAM_ERROR` and `detail` is undici's/Node's
        // OWN text. The agent's own diagnostic sentence cannot enter here: the
        // failures the agent knows about (the identity family) arrive typed as
        // `AgentFailure` and `failureOf` passes them through untouched.
        this.#fail(
          req.id,
          failureOf(err, (detail) => ({ code: "UPSTREAM_ERROR", params: { detail } })),
        );
      }
    } finally {
      this.#inFlight.delete(req.id);
      // Whichever way we leave (success, upstream error, cancellation) the
      // buffer is released here; late frames now land on an unregistered id.
      this.#requestBodies.delete(req.id);
    }
  }

  /**
   * The request was rejected before being applied. Body frames may still be in
   * flight, so we close the buffer and delete the records: the remaining frames
   * land on an unregistered id and `reqend` is not orphaned either.
   */
  #rejectRequest(req: RequestMessage, failure: TunnelFailure): void {
    this.#inFlight.delete(req.id);
    this.#requestBodies.get(req.id)?.abort();
    this.#requestBodies.delete(req.id);
    this.#fail(req.id, failure);
  }
}
