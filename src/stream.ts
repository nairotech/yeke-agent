/**
 * The apiserver end of a stream, on the agent side (tunnel v4).
 *
 * ─── Terminate-and-reframe: no second handshake passes through the tunnel ────
 *
 * The first version of the architecture plan noted exec as a "WS upgrade
 * passthrough"; this code is the revision of that sentence. Passthrough means
 * the socket becomes a **raw byte pipe** after the 101: credit-based flow
 * control is lost for that request (raw bytes have no "message", hence no
 * credit) and the agent's path allowlist ends at the handshake — no layer can
 * see what flows after the 101. In other words, the unbounded-buffering class
 * of failure measured in v2 would come back through a single exception.
 *
 * Instead, the **agent** opens the WebSocket to the apiserver (and the agent
 * terminates TLS too — no TLS-in-TLS, and the cluster credential never reaches
 * the control plane) and translates k8s channel frames into the tunnel's binary
 * frames. What the tunnel sees is still "a payload belonging to an id"; credit,
 * cancellation and path policy work exactly as before.
 *
 * ─── Backpressure ────────────────────────────────────────────────────────────
 *
 * On the `request` path backpressure came from suspending the `for await` loop
 * (undici does not pull the next chunk). A WebSocket has no such loop: `ws`
 * pushes whatever it read off the socket into user space as a 'message' event.
 * So when credit runs out the socket is **explicitly** paused (`pause()`) and
 * resumed when credit arrives. Pausing closes the TCP window, which means
 * backpressure reaches all the way down to the kubelet and the data is not
 * moved into the agent's memory.
 */
import { WebSocket, type RawData } from "ws";
import {
  CreditWindow,
  RESPONSE_CREDIT_WINDOW_BYTES,
  STREAM_CLOSE_FRAME_BYTES,
  STREAM_STDIN_CREDIT_GRANT_THRESHOLD_BYTES,
  classifyStreamUpgradeFailure,
  isStreamCloseFrame,
  supportsStreamHalfClose,
} from "@nairotech/yeke-tunnel";
import type { TunnelFailure } from "@nairotech/yeke-tunnel";
import type { KubeTlsOptions } from "./kube.js";

export interface UpstreamStreamOptions {
  /** `wss://…` or `ws://…` — derived from the apiserver address. */
  url: string;
  /** **Must not be empty**; rationale in the `StreamOpenMessage.protocols` comment. */
  protocols: string[];
  headers: Record<string, string | string[]>;
  /** The **same** TLS material the request path uses (see `KubeTarget.tlsOptions`). */
  tls: KubeTlsOptions;
}

export interface UpstreamStreamHooks {
  /** The handshake is done; `protocol` is the subprotocol the server **chose**. */
  onOpen(protocol: string): void;
  /** A channel frame arrived from upstream; it is carried to the control plane as-is. */
  onFrame(frame: Buffer): void;
  /** Return the credit consumed in the stdin direction to the control plane. */
  onStdinDelivered(bytes: number): void;
  onClose(code: number, reason: string): void;
  /**
   * The stream ended with a FAILURE — code + parameters, no sentence.
   *
   * The signature used to be `(code, message)`, and `message` went straight
   * from here into the tunnel's `err` message, and from there into the API body
   * as `params.detail`, where it was rendered on screen. That is, the prose in
   * this file used to reach the end user's screen. What travels now is a
   * `TunnelFailure`: the sentence is composed by the user interface.
   */
  onError(failure: TunnelFailure): void;
}

/**
 * The apiserver end of one stream.
 *
 * The class itself does not know the tunnel protocol (it sends no messages); it
 * reports what happened through hooks. That keeps "what the stream did" and
 * "what gets written to the wire" as separate decisions in the tunnel client,
 * and lets this file be tested without the wire format.
 */
export class UpstreamStream {
  #socket: WebSocket;
  #hooks: UpstreamStreamHooks;
  /** stdout/stderr direction: credit granted by the control plane. When it runs out the socket is paused. */
  #credit = new CreditWindow(RESPONSE_CREDIT_WINDOW_BYTES);
  #paused = false;
  #opened = false;
  #closed = false;
  /** stdin bytes written upstream but not yet acknowledged to the control plane. */
  #stdinOwed = 0;

  constructor(options: UpstreamStreamOptions, hooks: UpstreamStreamHooks) {
    this.#hooks = hooks;
    this.#socket = new WebSocket(options.url, options.protocols, {
      headers: options.headers,
      ...options.tls,
    });

    // ─── `403` means TWO different things (measured) ────────────────────────
    // Unsupported subprotocol → 403 + an **empty body**; RBAC denial → 403 + a
    // `Status` body. Looking only at the status code and saying "you are not
    // authorized" would send the user chasing a permission problem that does
    // not exist while the server simply does not speak v5. The classification
    // lives in one shared function: direct mode uses the very same one.
    this.#socket.on("unexpected-response", (_request, response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        const failure = classifyStreamUpgradeFailure(
          response.statusCode ?? 0,
          Buffer.concat(chunks).toString("utf8"),
        );
        this.#fail(failure);
      });
      response.on("error", () => {
        this.#fail(classifyStreamUpgradeFailure(response.statusCode ?? 0, ""));
      });
    });

    this.#socket.on("open", () => {
      // The `ws` client already rejects the handshake when we offered
      // subprotocols and the server chose none. The check here is a second
      // gate: we do not consider a stream that fell back to the unversioned
      // `channel.k8s.io` to be **open** — there is no exit-code and no
      // error-channel contract there, and the failure would surface months
      // later as "exit codes are always 0".
      if (!this.#socket.protocol) {
        this.#socket.close(1002, "no subprotocol selected");
        // No parameters, and there should be none: the only thing worth saying
        // is the code itself. This used to carry a localized sentence, and that
        // sentence travelled all the way to the screen.
        console.error(
          "[agent] apiserver answered 101 without selecting a subprotocol (unversioned channel.k8s.io); refusing the stream",
        );
        this.#fail({ code: "EXEC_PROTOCOL_UNSUPPORTED", params: {} });
        return;
      }
      this.#opened = true;
      this.#hooks.onOpen(this.#socket.protocol);
    });

    this.#socket.on("message", (data, isBinary) => {
      // The k8s stream protocol is entirely binary; a text frame carries no
      // channel byte, and if it were mistaken for data the client would read
      // channel 0x7B ("{").
      if (!isBinary || this.#closed) return;
      const frame = toBuffer(data);
      this.#hooks.onFrame(frame);
      this.#credit.consume(frame.byteLength);
      if (this.#credit.available <= 0 && !this.#paused) {
        // Credit exhausted: stop reading from the socket. Buffering frames and
        // counting them as "sent" would move the buffer from the control plane
        // into the agent — that is exactly the 222 → 350 MB measured in v2.
        this.#paused = true;
        this.#socket.pause();
      }
    });

    this.#socket.on("error", (err) => {
      // `err.message` is `ws`'/Node's OWN text — a foreign text; it passes
      // through verbatim as `detail` and is never translated.
      if (this.#opened) {
        this.#fail({ code: "STREAM_UPSTREAM_ERROR", params: { detail: err.message } });
        return;
      }
      // The handshake never completed: a code SEPARATE from `EXEC_UPGRADE_FAILED`,
      // because there an HTTP response exists (look at authorization/protocol/
      // proxy), while here there is none at all (look at network/TLS).
      //
      // `origin: "socket"` — a socket really does exist here (we are inside
      // `this.#socket`'s own 'error' event) and `ws` wrote the text. The
      // socket-less variant of the same branch is in `tunnel-client.ts`, in the
      // `#openStream` `catch`, and it says `"node"`; the rationale for the
      // distinction lives in `@nairotech/yeke-tunnel`, on the
      // `EXEC_UPGRADE_UNREACHABLE` branch.
      this.#fail({
        code: "EXEC_UPGRADE_UNREACHABLE",
        params: { origin: "socket", detail: err.message },
      });
    });

    this.#socket.on("close", (code, reason) => {
      if (this.#closed) return;
      this.#closed = true;
      this.#hooks.onClose(code, reason.toString());
    });
  }

  get protocol(): string {
    return this.#socket.protocol;
  }

  /** Credit from the control plane: the window grows, a paused socket resumes. */
  grantCredit(bytes: number): void {
    this.#credit.grant(bytes);
    if (this.#paused && this.#credit.available > 0) {
      this.#paused = false;
      this.#socket.resume();
    }
  }

  /**
   * Writes a stdin/resize frame coming from the control plane to upstream.
   *
   * The half-close gate exists here as well (the control plane already has one)
   * because a defensive layer cannot be left to a single point: a compromised
   * or buggy control plane could send `FF 00` in a v4 session and create the
   * illusion that stdin was closed — whereas the apiserver **silently swallows**
   * that frame (measured) and the session hangs until it times out. We replace
   * the silent swallow with a loud error.
   */
  write(frame: Buffer): void {
    if (this.#closed || this.#socket.readyState !== WebSocket.OPEN) return;

    if (isStreamCloseFrame(frame)) {
      if (!supportsStreamHalfClose(this.#socket.protocol)) {
        this.#fail({
          code: "STREAM_HALF_CLOSE_UNSUPPORTED",
          params: { protocol: this.#socket.protocol },
        });
        return;
      }
      if (frame.byteLength !== STREAM_CLOSE_FRAME_BYTES) {
        // If the length is not 2 the apiserver drops the connection; the user
        // would see that as "the terminal closed out of nowhere".
        this.#fail({
          code: "STREAM_CLOSE_FRAME_INVALID",
          params: { expectedBytes: STREAM_CLOSE_FRAME_BYTES, actualBytes: frame.byteLength },
        });
        return;
      }
    }

    this.#socket.send(frame, (err) => {
      if (err) {
        this.#fail({ code: "STREAM_UPSTREAM_ERROR", params: { detail: err.message } });
        return;
      }
      // Credit is granted **when the write completes**, not when the frame is
      // received: otherwise the control plane would earn a new window for bytes
      // that never reached the apiserver.
      this.#stdinOwed += frame.byteLength;
      if (this.#stdinOwed >= STREAM_STDIN_CREDIT_GRANT_THRESHOLD_BYTES) {
        const grant = this.#stdinOwed;
        this.#stdinOwed = 0;
        this.#hooks.onStdinDelivered(grant);
      }
    });
  }

  close(code = 1000, reason?: string): void {
    if (this.#socket.readyState === WebSocket.CONNECTING) {
      // The handshake is still in progress: in that state `close()` waits for a
      // closing handshake that may never complete.
      this.#socket.terminate();
      return;
    }
    this.#socket.close(code, reason);
  }

  #fail(failure: TunnelFailure): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#hooks.onError(failure);
    this.#socket.terminate();
  }
}

/** `ws`'s `RawData` may be a Buffer, an ArrayBuffer or a Buffer[]. */
function toBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (Array.isArray(data)) return Buffer.concat(data);
  return Buffer.from(data as ArrayBuffer);
}
