/**
 * One tunnel session, and everything the control plane addressed by id inside it.
 *
 * ─── Why this file exists (12.10.2026) ──────────────────────────────────────
 *
 * Four failures of the same class were fixed one by one on a single day (#12,
 * #14, #16, and a `cancel` that reached a stream still in its WebSocket
 * handshake). Each was a different async path that outlived the session it
 * was started for and then either wrote to the socket OF THE MOMENT (the next
 * session's) or edited a long-lived map by an id the next session had already
 * reused — core allocates ids from 1 again on every connection
 * (`RequestIdAllocator` in core's `tunnel/session.ts`). Every fix was a guard
 * at one call site ("pass the session", "compare before you delete"), and the
 * next path to forget its guard was the next bug.
 *
 * The fix here is structural rather than one more guard:
 *
 *  · A `TunnelSession` owns ONE socket and every per-id record of that
 *    socket. There is no other per-id state in the agent, and no other way to
 *    write to the wire than through a session or a record — so a handler can
 *    only ever speak to the session that created it, and there is no "socket
 *    of the moment" left to fall back on.
 *  · An `IdRecord` is what the control plane is owed for one id. Once the
 *    control plane has forgotten the id (`cancel`, `strclose`), once the
 *    record's own work is over, or once its session ended, the record stops
 *    being `live` and every write through it is a no-op. Late callbacks
 *    (an upstream close that completes later, a credential plugin that
 *    returns after the session dropped) therefore need no guard of their own.
 *  · Removal is by identity (`release(id, record)`), never by id alone.
 *
 * Core keeps the same model on its side (`AgentTunnelSession`, one object per
 * socket with its own `#closed` flag and `#teardown`), so the two ends of the
 * tunnel now reason about sessions the same way.
 *
 * What stays OUT of this file on purpose: the metrics collector and the sample
 * sink. They outlive sessions by design (the ring is the history K5 keeps
 * across an outage, and the encoder's `seq` must keep counting across
 * reconnects); they ask the client for the current session at the moment they
 * write. And no failure is BUILT here: the codes and their parameters are
 * chosen at the call sites in `tunnel-client.ts` and `stream.ts`, which is also
 * where core's source-scanning tests look for them.
 */
import { WebSocket } from "ws";
import {
  CreditWindow,
  MAX_REQUEST_BODY_BYTES,
  RESPONSE_CREDIT_WINDOW_BYTES,
  describeFailure,
  encodeBodyFrame,
  serializeControlMessage,
  type ControlMessage,
  type TunnelFailure,
} from "@nairotech/yeke-tunnel";
import type { UpstreamStream } from "./stream.js";

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
export class RequestBody {
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

/**
 * What the control plane is owed for ONE id of ONE session.
 *
 * Three ways a record stops, and all three end in the same state (not `live`,
 * not in its session's map, its `signal` aborted):
 *
 *  · `stop()` — from OUTSIDE the record's own work: the control plane forgot
 *    the id (`cancel`, `strclose`) or the session ended. The resources the
 *    record still holds (a body buffer, an upstream socket) are released here,
 *    and the record's handler learns of it through `signal`.
 *  · `finish()` — the record's OWN work is over (the response ended, the
 *    upstream closed or failed, a request was rejected before it was applied).
 *    Nothing is left to release.
 *  · its session ending, which calls `stop()` on every record it holds.
 *
 * Both are idempotent and the first one wins: a late `finish()` after a
 * `cancel` changes nothing, and a `stop()` after `finish()` does not touch a
 * resource that is already gone.
 */
export abstract class IdRecord {
  readonly session: TunnelSession;
  readonly id: number;
  readonly #abort = new AbortController();

  constructor(session: TunnelSession, id: number) {
    this.session = session;
    this.id = id;
  }

  /** Aborted the moment the record stops, for whatever reason. Handed to every abortable await. */
  get signal(): AbortSignal {
    return this.#abort.signal;
  }

  /**
   * The control plane still waits for this id, on a session that can still
   * carry the answer. Every wire write below checks this, so a callback that
   * arrives after the record stopped has nothing to guard by itself.
   */
  get live(): boolean {
    return !this.#abort.signal.aborted && this.session.live;
  }

  send(message: ControlMessage): void {
    if (this.live) this.session.send(message);
  }

  sendBody(payload: Uint8Array): void {
    if (this.live) this.session.sendBody(this.id, payload);
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
   *
   * The two jobs answer two different questions, so they have two gates.
   *
   *  · The LOG is skipped for a record that was STOPPED — the control plane
   *    forgot the id (`cancel`, `strclose`) or the session ended. Measured
   *    before this rule (12.10.2026): a `cancel`/`strclose` for a stream whose
   *    upstream WebSocket was still in its handshake made `ws` emit "WebSocket
   *    was closed before the connection was established", and the agent
   *    logged "request N failed" for a stream nobody wanted any more; the same
   *    line came out for every such stream when the session dropped. Neither
   *    said anything true about the stream: the agent had torn it down itself.
   *  · The WIRE write is skipped for a record that is not `live` — stopped,
   *    OR its session's socket can no longer carry a frame. In that same
   *    measurement the agent answered the control plane with an `err` for the
   *    id it had just forgotten.
   *
   * The difference is a record that was never stopped while its socket is
   * already closing (the peer has started the close, the 'close' event has
   * not arrived yet): its failure is a REAL one — an upstream error the agent
   * did not cause — and the operator's log is the only place it can still
   * go. Gating the log on `live` as well (the first version of this method)
   * swallowed exactly that line (found by the independent tester, 12.10.2026).
   */
  fail(failure: TunnelFailure): void {
    if (this.#abort.signal.aborted) return;
    console.warn(`[agent] request ${this.id} failed: ${describeFailure(failure)}`);
    if (this.live) this.session.send({ t: "err", id: this.id, ...failure });
  }

  /** Stopped from outside: the id is forgotten or the session is over. See the class comment. */
  stop(code = 1000, reason?: string): void {
    if (this.#abort.signal.aborted) return;
    this.#abort.abort();
    this.session.release(this.id, this);
    this.halt(code, reason);
  }

  /** The record's own work is over. See the class comment. */
  finish(): void {
    if (this.#abort.signal.aborted) return;
    this.#abort.abort();
    this.session.release(this.id, this);
  }

  /** Releases what the record still holds when it is stopped from outside. */
  protected abstract halt(code: number, reason: string | undefined): void;

  /** `credit` from the control plane for this id; its meaning depends on the kind. */
  abstract grantCredit(bytes: number): void;
}

/** A `req`: an HTTP request applied to the apiserver, its response flowing back. */
export class RequestRecord extends IdRecord {
  /**
   * Remaining credit for this request's response body. The window opens
   * implicitly together with `req`: both ends know RESPONSE_CREDIT_WINDOW_BYTES,
   * so there is no opening round trip.
   */
  readonly credit = new CreditWindow(RESPONSE_CREDIT_WINDOW_BYTES);
  /** Present exactly when the `req` announced a body (`hasBody`). */
  readonly body: RequestBody | undefined;
  /**
   * `res` has gone out: the apiserver answered and the body is flowing (or
   * about to). From here on the request is no longer WAITING for anything the
   * agent could give it sooner, which is what `SampleWire.busy` asks about.
   */
  responding = false;

  constructor(session: TunnelSession, id: number, hasBody: boolean) {
    super(session, id);
    this.body = hasBody ? new RequestBody() : undefined;
  }

  /** A handler waiting on the body is woken up; a half buffer is dropped. */
  protected halt(): void {
    this.body?.abort();
  }

  grantCredit(bytes: number): void {
    this.credit.grant(bytes);
  }
}

/** A `stropen`: a WebSocket to the apiserver (exec, port-forward), framed onto the tunnel. */
export class StreamRecord extends IdRecord {
  /**
   * Absent while the stream is still resolving its credentials — the phase in
   * which `stop()` can only abort `signal` (which keeps the handler from ever
   * opening upstream) because there is no socket to close yet.
   */
  upstream: UpstreamStream | undefined;

  /** The upstream socket is closed (or, still in its handshake, terminated: see `UpstreamStream.close`). */
  protected halt(code: number, reason: string | undefined): void {
    this.upstream?.close(code, reason);
  }

  /** stdout/stderr credit; dropped while there is no upstream yet, as before the upstream existed. */
  grantCredit(bytes: number): void {
    this.upstream?.grantCredit(bytes);
  }
}

/**
 * One WebSocket to the control plane, from construction to its end.
 *
 * `end()` is the session's single exit: it aborts `signal`, stops every record
 * and clears the timers the session owns. It is idempotent, and it is called
 * as soon as the agent DECIDES the session is over (the liveness timer giving
 * up, `stop()`), not only when the socket's 'close' event finally arrives —
 * the client drops every message that reaches a session that is no longer
 * `live`, so nothing new is started in that gap.
 */
export class TunnelSession {
  readonly socket: WebSocket;
  readonly #controller = new AbortController();
  readonly #records = new Map<number, IdRecord>();
  readonly #timers = new Set<NodeJS.Timeout>();
  /**
   * The negotiated version this session's `welcome` reported; 0 until then.
   *
   * Per session, not per agent: a reconnect can land on an older control plane
   * (a rollback, a load balancer with two versions behind it), and a number
   * left over from the previous peer would answer for the next one before it
   * has spoken.
   */
  protocol = 0;
  /** The session's `welcome` has been applied; a second one is ignored (see the client). */
  welcomed = false;
  /** When the last message arrived on this socket; the sole criterion for the keepalive decision. */
  lastSeenAt = Date.now();

  constructor(socket: WebSocket) {
    this.socket = socket;
  }

  /** Aborted by `end()`. Handed to every await that belongs to the session as a whole (the `/version` read). */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  get ended(): boolean {
    return this.#controller.signal.aborted;
  }

  /**
   * Not ended, and the socket can carry a frame. A socket that has closed
   * never becomes OPEN again (a reconnect is a new `WebSocket` and a new
   * session), so whatever a finished session still has to say is dropped here
   * rather than landing on the next session.
   */
  get live(): boolean {
    return !this.ended && this.socket.readyState === WebSocket.OPEN;
  }

  send(message: ControlMessage): void {
    if (this.live) this.socket.send(serializeControlMessage(message));
  }

  sendBody(id: number, payload: Uint8Array): void {
    if (this.live) this.socket.send(encodeBodyFrame(id, payload));
  }

  /**
   * Registers a record for `id`, or returns `undefined` when this session
   * already has a record for it — of EITHER kind.
   *
   * Requests and streams share one id space (core allocates both from one
   * `RequestIdAllocator` over the union of its two maps), and the binary frame
   * header, `credit` and `cancel` carry nothing but the id. A second record for
   * an id would leave the first one unaddressable: measured before this rule
   * (12.10.2026), a second `req` for an id overwrote the first one's entry, so
   * the first handler was never aborted — not by `cancel`, not when the
   * session dropped — and its watch went on writing into the NEXT session
   * under an id that session had never allocated, and kept `stop()` waiting on
   * it. A correct control plane never sends a duplicate; the agent does not
   * rely on that.
   */
  claim<R extends IdRecord>(id: number, make: (session: this) => R): R | undefined {
    if (this.#records.has(id)) return undefined;
    const record = make(this);
    this.#records.set(id, record);
    return record;
  }

  lookup(id: number): IdRecord | undefined {
    return this.#records.get(id);
  }

  /**
   * Removes `id` only while it is still `record`.
   *
   * Within one session core does not hand out an id again until its counter
   * wraps at 2³²−1, so by id alone would be correct today. It is by identity
   * anyway because "today" is exactly the assumption the four failures above
   * leaned on: the cost is one comparison, and the rule no longer depends on
   * how a peer allocates.
   */
  release(id: number, record: IdRecord): void {
    if (this.#records.get(id) === record) this.#records.delete(id);
  }

  /** A timer that belongs to this session (the liveness check) and must not outlive it. */
  own(timer: NodeJS.Timeout): void {
    if (this.ended) {
      clearInterval(timer);
      return;
    }
    this.#timers.add(timer);
  }

  /** Requests and streams currently held, for the client's diagnostic counters and `busy`. */
  *records(): IterableIterator<IdRecord> {
    yield* this.#records.values();
  }

  /** At least one request whose response has not started yet (`SampleWire.busy`). */
  hasWaitingRequest(): boolean {
    for (const record of this.#records.values()) {
      if (record instanceof RequestRecord && !record.responding) return true;
    }
    return false;
  }

  /**
   * The session is over: nothing it started may write, wait or hold a
   * resource any longer. Idempotent.
   *
   * Open requests are aborted (when the control plane reconnects it
   * re-establishes its watches from scratch), body buffers are woken, and
   * streams are closed: the control plane cannot RESUME an exec session (exec
   * has no `resync`), and a pty left open on the apiserver side would be a
   * process nobody is reading. A stream still resolving its credentials is
   * aborted, so its handler never opens upstream at all.
   */
  end(): void {
    if (this.ended) return;
    this.#controller.abort(new Error("tunnel session ended"));
    for (const timer of this.#timers) clearInterval(timer);
    this.#timers.clear();
    // A copy: each `stop()` releases its own entry from the map.
    for (const record of [...this.#records.values()]) record.stop(1001, "tunnel disconnected");
    this.#records.clear();
  }
}
