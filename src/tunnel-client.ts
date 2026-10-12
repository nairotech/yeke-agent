/**
 * The tunnel client: opens a single **outbound** WebSocket to the control plane
 * and applies the incoming HTTP requests to the downstream apiserver.
 *
 * Because the connection direction is cluster → control plane, the downstream
 * side needs no inbound firewall rule, no port-forward and no VPN; outbound 443
 * is enough.
 */
import { readFile } from "node:fs/promises";
import { WebSocket, type RawData } from "ws";
import { request } from "undici";
import {
  type CoreCaBundle,
  defaultCoreCaCertificates,
  describeCoreCa,
  describeSkippedCoreCa,
  loadCoreCa,
} from "./core-ca.js";
import {
  AGENT_CLUSTER_HEADER,
  AGENT_TOKEN_HEADER,
  HELLO_CORE_CA_ROOTS_MAX,
  MAX_REQUEST_BODY_BYTES,
  SAMPLE_FRAME_REQUEST_ID,
  SAMPLE_MIN_PROTOCOL_VERSION,
  TUNNEL_LIVENESS_TIMEOUT_MS,
  TUNNEL_PING_INTERVAL_MS,
  TUNNEL_PROTOCOL_VERSION,
  decodeBodyFrame,
  parseControlMessage,
  type ControlMessage,
  type HelloMessage,
  type RequestMessage,
  type StreamOpenMessage,
} from "@nairotech/yeke-tunnel";
import type { AgentConfig } from "./config.js";
import { failureOf } from "./failure.js";
import {
  SA_DIR,
  readKubernetesVersion,
  resolveKubeTarget,
  serviceAccountToken,
  type KubeTarget,
} from "./kube.js";
import { Collector, shouldCollect } from "./metrics/collector.js";
import { KubeletClient } from "./metrics/kubelet-client.js";
import type { InternalFrame, SampleSink } from "./metrics/types.js";
import { SampleEncoder } from "./metrics/wire.js";
import { type IdRecord, RequestRecord, StreamRecord, TunnelSession } from "./session.js";
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

/**
 * Whether two root fingerprint SETS are the same — order-independent, since
 * a re-read of the same file must not be treated as a change just because
 * `loadCoreCa` happened to hand the certificates back in a different order
 * (it does not today, but nothing about `#loadCoreCaForConnect`'s "print
 * only on a real change" rule should depend on that staying true).
 */
function sameRootFingerprintSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = [...a].sort();
  const sortedB = [...b].sort();
  return sortedA.every((fingerprint, index) => fingerprint === sortedB[index]);
}

/**
 * The ceiling `hello.coreCaRoots` (K15) can carry on the wire
 * (architecture decision §3.15: "en çok 16 öğe").
 *
 * Read from the installed contract (`HELLO_CORE_CA_ROOTS_MAX`, the same
 * constant behind `HelloMessage.coreCaRoots`'s `.max()`). When this was first
 * written the repository was pinned to `@nairotech/yeke-tunnel` 5.0.0, whose
 * schema had no `coreCaRoots` at all, so the value was a local mirror with
 * this comment as its only cross-reference. The pin has been 5.1.0 since
 * 16.09.2026 (`c0e69c5`); the mirror — and the drift it risked — went on
 * 12.10.2026.
 *
 * Independent finding, 15.09.2026: with more roots loaded than this, the
 * agent sent a `coreCaRoots` array over the cap and core rejected the whole
 * `hello` for it — the tunnel never finished negotiating, with no log line
 * on the agent's side to say why (core's own fix, capping and reporting
 * that rejection, is a separate change). The agent's half of the fix is
 * simpler than accepting a broken tunnel: past this many roots, leave the
 * field out of `hello` entirely (absent, the same as an agent that
 * predates the field — see the `open` handler) rather than send something
 * the wire will not accept.
 */
const CORE_CA_HELLO_ROOTS_LIMIT = HELLO_CORE_CA_ROOTS_MAX;

/**
 * How long the `/version` read behind `hello.kubernetesVersion` may take
 * before `hello` goes without it (the field is optional on the wire).
 *
 * PO decision D2, 12.10.2026. The read used to be bounded only by undici's
 * defaults (300 s for the headers, 300 s for the body) plus an exec credential
 * plugin's 60 s, and core has no `hello` deadline of its own — so a slow
 * apiserver or plugin kept the whole session at protocol 0 for minutes: core
 * refuses every stream (`STREAM_TUNNEL_VERSION`) until `hello`, and the
 * collector is not started until `welcome`. A missing version on the cluster
 * card is a far smaller loss than an exec that does not open. Ten seconds is
 * long for an apiserver to answer `/version` and short next to the reconnect
 * and liveness periods. The read is also bound to its session: a session that
 * ends stops waiting for it at once (see the `open` handler).
 */
const VERSION_READ_TIMEOUT_MS = 10_000;

/**
 * Node's TLS error codes for "the certificate does not chain to anything I
 * trust" — the ONLY family a corporate CA can fix. A closed list on purpose:
 * an expired certificate or a hostname mismatch is a different problem that
 * `YEKE_CORE_CA_FILE` does nothing for, and telling an operator to mount a CA
 * for either would send them down a dead end.
 */
const TLS_TRUST_ERROR_CODES = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_GET_ISSUER_CERT",
]);

/** The remedy appended to a connection error whose code is in `TLS_TRUST_ERROR_CODES`. */
const TLS_TRUST_HINT =
  "core's certificate is not trusted; if it is signed by your organization's CA, mount the CA and set " +
  "YEKE_CORE_CA_FILE (the install manifest does this when core has YEKE_PUBLIC_CA_FILE)";

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
// visible only when a chunk larger than the window arrived. The agent's copies
// of the window, and the request body buffer, live on the per-id records in
// `session.ts` (`RequestRecord`), next to the session that owns them.

/**
 * How many internal frames share one wire frame.
 *
 * K5: the collector samples every 30 seconds and the wire carries a frame every
 * 60, with two samples per entity. The pairing is here rather than in the
 * collector because it is a WIRE decision — halving the number of control
 * messages and dictionaries, not the number of readings — and the collector's
 * ring must keep filling at its own rate while the tunnel is down.
 */
const SAMPLES_PER_WIRE_FRAME = 2;

/** What the tunnel client needs from a collector; the tests supply their own. */
export interface MetricsCollector {
  start(): void;
  stop(): Promise<void>;
  /** Frames the ring is holding, for the line the reconnect writes. */
  readonly queuedFrames: number;
  /**
   * Drain the ring onto the wire now.
   *
   * The reconnect path calls it: K5's half hour of buffered history drains
   * "when the tunnel returns", and the collector's own next tick can be thirty
   * seconds away — thirty seconds in which the control plane's screen has a
   * hole it did not need to have.
   */
  flush(): void;
}

/**
 * Builds the collector once the handshake says the control plane can receive
 * samples.
 *
 * A seam, and not a generality for its own sake: the collector reaches a real
 * apiserver and 50 real kubelets, and a test of the WIRE side (dictionary
 * deltas, reconnects, priority) must be able to hand frames to the sink without
 * any of that. Returning `undefined` is a legitimate answer — see
 * `inClusterCollector`.
 */
export type CollectorFactory = (context: {
  readonly target: KubeTarget;
  readonly sink: SampleSink;
  readonly config: AgentConfig;
}) => Promise<MetricsCollector | undefined>;

/**
 * The production collector: the agent's own ServiceAccount, in its own pod.
 *
 * `kubeconfig` mode gets no collector and says so once. The kubelet reads
 * authenticate with the projected SA token and verify the kubelet's certificate
 * against the projected CA (K4); outside a pod neither file exists, so every
 * node would report `unauthorized` forever. Announcing the absence is the rule
 * this repository follows over routing around it — a developer running the
 * agent against a kubeconfig should see one line explaining why no metrics
 * appear, not fifty node failures a minute.
 */
const inClusterCollector: CollectorFactory = async ({ target, sink, config }) => {
  if (config.kubeMode !== "in-cluster") {
    console.log(
      "[metrics] collector not started: kubelet reads need an in-cluster service account (YEKE_KUBE_MODE=kubeconfig)",
    );
    return undefined;
  }
  const ca = await readFile(`${SA_DIR}/ca.crt`);
  const kubelet = new KubeletClient({
    token: serviceAccountToken(`${SA_DIR}/token`),
    ca,
    insecureTls: config.kubeletInsecureTls,
  });
  const collector = new Collector({ target, kubelet, sink });
  return {
    start: () => collector.start(),
    get queuedFrames() {
      return collector.queuedFrames;
    },
    flush: () => collector.flush(),
    // The connection pool belongs to this collector and nothing else holds it;
    // leaving it open would keep 50 keep-alive sockets to kubelets after the
    // agent decided to stop reading them.
    stop: async () => {
      await collector.stop();
      await kubelet.close();
    },
  };
};

/**
 * What `SampleWire` needs from the tunnel client, as a function rather than a
 * back-reference: the sink asks for the session at the moment it is asked a
 * question, and a captured session would answer for one that has already
 * ended. Unlike everything addressed by id, samples are not owned by a
 * session — the collector and its ring outlive every reconnect — so "the
 * session of the moment" is the right question HERE, and only here.
 */
interface SampleWireHooks {
  /** The client's current session, ended or not; `null` before the first connection attempt. */
  readonly session: () => TunnelSession | null;
}

/**
 * The `SampleSink` the collector writes into: the wire, seen from the collector.
 *
 * ─── The two flags, on this side of the seam ────────────────────────────────
 *
 *  · `ready` is "there is a live session AND its peer can read samples". Both
 *    halves matter: the protocol number is per SESSION (`TunnelSession.protocol`,
 *    0 until that session's own `welcome`). Were it the agent's, a reconnect to
 *    an OLDER control plane would keep the previous session's answer and the
 *    agent would send frames into a peer that drops them — or, before the new
 *    peer's `welcome`, into one that has not negotiated anything yet.
 *  · `busy` is "a request of the current session has not started its response
 *    yet" — the request is still in the queue K5 gives priority to: its body
 *    is arriving, its identity is being resolved, or the apiserver has not
 *    answered. Once `res` is sent the request is a flowing response, not a
 *    queued one, and it stops counting. That matters because the control plane
 *    keeps responses open for as long as a session lives: the discovery
 *    watcher's two watches per cluster (CRDs, APIServices; re-opened every
 *    300 s without a pause), browser subscriptions, `logs -f`. Counting every
 *    entry made `busy` true on almost every tick (12.10.2026, production: 14 of
 *    14 clusters `sink=busy` before a core restart; see `collector.ts`).
 *    Streams are deliberately NOT counted either, for the same reason: an open
 *    `kubectl exec` lives for minutes, and a shell left open in one browser tab
 *    would otherwise hold the cluster's monitoring back for as long as it stays
 *    open.
 *
 * ─── The one frame this class holds, and how its loss is counted ────────────
 *
 * Pairing means the first of the two frames is accepted and held here, OUT of
 * the ring. If the connection drops before its partner arrives that frame is
 * gone, and the ring — which is where `dropped` normally comes from — never
 * knew about it. So the loss is counted here and added to the `dropped` of the
 * next frame that gets through. The rejected alternative was to pair it with
 * the first frame after the reconnect: the two sample times would then straddle
 * the whole outage, and a receiver drawing a rate between them would draw a
 * number nobody measured.
 *
 * ─── Which session the dictionary belongs to ────────────────────────────────
 *
 * The encoder lives here, not on the session, because its `seq` must keep
 * counting across reconnects (`wire.ts`); its alias dictionary, on the other
 * hand, is connection-local. Until 12.10.2026 the client reset it from its
 * disconnect cleanup — one more call that had to stay in step with the rest
 * of that cleanup. Now the dictionary is tagged with the session it was built
 * for, and the first frame offered for any other session resets it (and
 * counts the half pair the old session never got): the reset follows from the
 * identity of the session, not from remembering to call it.
 */
class SampleWire implements SampleSink {
  // Default clock: `agentTimeMs` is stamped at encode (= send) time, see wire.ts.
  readonly #encoder = new SampleEncoder();
  readonly #hooks: SampleWireHooks;
  #pending: InternalFrame[] = [];
  #droppedBeforeWire = 0;
  /** The session the encoder's dictionary and `#pending` belong to. */
  #dictionarySession: TunnelSession | null = null;
  /** Wire frames written. A frame split by size counts as its parts. */
  framesSent = 0;
  /** Frames the encoder refused. A rising number is a shape bug, not a network one. */
  encodeFailures = 0;

  constructor(hooks: SampleWireHooks) {
    this.#hooks = hooks;
  }

  /** The session samples may go to right now, or `null`. */
  #target(): TunnelSession | null {
    const session = this.#hooks.session();
    return session?.live && session.protocol >= SAMPLE_MIN_PROTOCOL_VERSION ? session : null;
  }

  get ready(): boolean {
    return this.#target() !== null;
  }

  get busy(): boolean {
    return this.#hooks.session()?.hasWaitingRequest() ?? false;
  }

  push(frame: InternalFrame): boolean {
    const session = this.#target();
    if (!session) return false;
    if (session !== this.#dictionarySession) this.#beginSession(session);
    // Accepted, not yet sent: the collector drops it from the ring on `true`,
    // so from here on this class is responsible for it (see the header).
    this.#pending.push(frame);
    if (this.#pending.length < SAMPLES_PER_WIRE_FRAME) return true;
    const batch = this.#pending;
    this.#pending = [];
    return this.#write(batch, session);
  }

  /**
   * A frame for a session the dictionary was not built for. The half-built
   * pair of the previous session is dropped and counted; the dictionary
   * starts again at 1.
   */
  #beginSession(session: TunnelSession): void {
    this.#droppedBeforeWire += this.#pending.length;
    this.#pending = [];
    this.#encoder.reset();
    this.#dictionarySession = session;
  }

  #write(frames: readonly InternalFrame[], session: TunnelSession): boolean {
    const dropped = this.#droppedBeforeWire;
    this.#droppedBeforeWire = 0;
    try {
      for (const { message, payload } of this.#encoder.encode(frames, {
        droppedBeforeWire: dropped,
      })) {
        // The order is the contract: the control message first, the binary
        // frame second. The receiver holds the message until the frame arrives
        // and pairs them by arrival order, because WebSocket preserves it.
        session.send(message);
        session.sendBody(SAMPLE_FRAME_REQUEST_ID, payload);
        this.framesSent += 1;
      }
      return true;
    } catch (err) {
      // An unencodable frame is DROPPED, not retried. Returning false would
      // leave it at the head of the ring and every following tick would throw
      // on the same frame — a permanent stall of the whole series to preserve
      // one minute of it. The loss joins the count the next frame carries, and
      // the line below is the operator's copy of it.
      this.encodeFailures += 1;
      this.#droppedBeforeWire = dropped + frames.length;
      console.warn(`[metrics] sample frame dropped, not encodable: ${(err as Error).message}`);
      return true;
    }
  }
}

export class TunnelClient {
  #config: AgentConfig;
  #target: KubeTarget | null = null;
  /**
   * The session of the socket `#connect` opened last — `null` before the
   * first attempt. Possibly already ended: between a 'close' and the next
   * attempt it is the session that just finished.
   *
   * Read ONLY by what is agent-wide by nature: the diagnostic counters, the
   * sample sink (whose frames go to whichever session is open, see
   * `SampleWire`) and `stop()`. Everything the control plane addressed by id —
   * requests, streams, their buffers and abort controllers — and everything a
   * session negotiated (`welcome.protocol`) lives on the `TunnelSession` that
   * carried it, and a handler holds that session (or its own record), never
   * this field. Until 12.10.2026 that state was four id-keyed maps here and a
   * `#send` whose default target was "the socket of the moment"; the four
   * failures that came out of it are the header of `session.ts`.
   */
  #session: TunnelSession | null = null;
  /**
   * Delay before the next reconnect attempt — exponential, reset only on a
   * CONFIRMED registration.
   *
   * Independent finding, 15.09.2026: this used to reset the moment the
   * SOCKET opened (`#connect`'s `open` handler), not when the control plane
   * actually accepted the agent. `open` only proves the TCP+TLS handshake
   * succeeded — `hello` is sent from that same handler, and core can still
   * close the connection over it (an unsupported protocol, an oversized
   * `hello`, a bad token) with no `welcome` ever arriving. Measured: a
   * control plane that closes every `hello` with 1008 made the agent
   * reconnect about once a second indefinitely, because each attempt's
   * `open` re-armed the very floor a `close`-without-`welcome` should have
   * been backing off from — a full TLS handshake, a token check on core's
   * side and a log line on both ends, roughly 86,000 times a day. The reset
   * now lives where `welcome` is handled (`#onControl`'s `"welcome"` case,
   * next to the `registered` log line) — the one point that proves the peer
   * actually accepted this agent — so a connection that opens and is then
   * rejected keeps climbing the exponential curve on its next attempt
   * instead of restarting from the floor every time. A session that DID
   * register and later drops (the ordinary case: a restart, a network blip)
   * still reconnects from `reconnectMinMs`, unchanged:
   * `#cleanupAfterDisconnect` does not touch this field, only the `welcome`
   * case does.
   */
  #backoff: number;
  #stopped = false;
  /** The one shutdown: `stop()` returns this same promise on every call (I9). */
  #stopping: Promise<void> | undefined;
  /**
   * The apiserver version this agent last read successfully, on any session —
   * `undefined` until the first successful read. What `hello` carries when a
   * session's own read runs past `VERSION_READ_TIMEOUT_MS` (see
   * `#readVersionFor`).
   */
  #lastKubernetesVersion: string | undefined;
  /** The pending reconnect attempt, so that `stop()` can cancel it rather than let it fire into a stopped client. */
  #reconnectTimer: NodeJS.Timeout | null = null;
  readonly #createCollector: CollectorFactory;
  readonly #sampleWire: SampleWire;
  /**
   * The collector, once started — and it is started AT MOST ONCE.
   *
   * It survives reconnects on purpose: its ring is the 30 minutes of history
   * K5 exists to keep, and rebuilding the collector on every reconnect would
   * throw that history away exactly when the outage that produced it ended. It
   * also holds three watches against the apiserver; restarting them per socket
   * would turn a flapping tunnel into a LIST storm on the customer's control
   * plane.
   *
   * The same reasoning covers the downgrade case, which is otherwise easy to
   * miss: if a reconnect lands on a control plane that negotiates v4 (a
   * rollback), the sink stops being ready and the collector keeps filling its
   * ring with nothing draining. That is bounded by construction — 60 frames,
   * oldest dropped, and the count rides the first frame that gets through when
   * v5 returns. Tearing the collector down for a peer that may be back in a
   * minute would cost the customer more than it saves.
   */
  #collector: MetricsCollector | undefined;
  #collectorStarting = false;
  /**
   * The organization's CA, once loaded — `undefined` when `YEKE_CORE_CA_FILE`
   * is not set, in which case `ca` is never passed to `WebSocket` at all (see
   * `#connect`).
   *
   * Once this is set it never goes back to `undefined`: a re-read that fails
   * on a later connection attempt (file deleted, briefly unreadable during a
   * ConfigMap update) keeps the LAST successfully loaded bundle rather than
   * dropping trust entirely. The one read that is allowed to bring the agent
   * down is the very first one — the same "an obstacle is reported, never
   * routed around" rule `kubeletInsecureTls` documents in `config.ts`, applied
   * to a file this agent is not free to silently distrust.
   */
  #coreCa: CoreCaBundle | undefined;
  /**
   * The root fingerprint SET the startup CA line was last printed for —
   * `undefined` before the first successful load.
   *
   * Independent finding, 15.09.2026: the original "print once, on the FIRST
   * successful load" rule (`#loadCoreCaForConnect` below) meant the line
   * never printed again, even across a full rotation (§3.10: the file's
   * roots change TWICE — old+new, then new alone — while the pod is never
   * restarted). §3.14 claims "which CA is distributed is auditable" from
   * this very line; measured against an actual rotation, that claim went
   * stale after the first certificate, which defeats the point of an
   * auditable line existing at all. Comparing against this field (not
   * against `#coreCa` itself, which is already the freshly loaded bundle by
   * the time the comparison would run) is what lets "the file was re-read
   * but nothing in it actually changed" — every ordinary reconnect — stay
   * silent, exactly as before.
   */
  #loggedCoreCaRootFingerprints: readonly string[] | undefined;
  /**
   * The root fingerprint SET the "too many roots for hello" warning was last
   * printed for — `undefined` when the loaded set is at or under
   * `CORE_CA_HELLO_ROOTS_LIMIT`, so a later climb back over the limit (even
   * with the SAME set that triggered it before) warns again rather than
   * staying silent from stale memory. Independent finding, 15.09.2026 — see
   * that constant's own comment.
   */
  #loggedOversizedRootFingerprints: readonly string[] | undefined;
  /**
   * The fingerprint SET the "skipping expired certificate(s)" warning was
   * last printed for — `undefined` when nothing is currently being skipped,
   * for the same reason as `#loggedOversizedRootFingerprints` above.
   * Independent finding, 15.09.2026: `loadCoreCa` used to print this warning
   * itself, once per skipped certificate, on EVERY call — and `#connect`
   * calls it on every reconnect (§3.10), so an unchanged file produced the
   * same line again and again (measured: 10 reconnects, 10 identical
   * lines). `loadCoreCa` now only reports what it skipped
   * (`CoreCaBundle.skippedExpired`); this field is what lets the actual
   * printing follow the same "once per SET, not once per read" rule as
   * `#loggedCoreCaRootFingerprints` above.
   */
  #loggedSkippedExpiredFingerprints: readonly string[] | undefined;

  constructor(config: AgentConfig, hooks: { readonly createCollector?: CollectorFactory } = {}) {
    this.#config = config;
    this.#backoff = config.reconnectMinMs;
    this.#createCollector = hooks.createCollector ?? inClusterCollector;
    this.#sampleWire = new SampleWire({ session: () => this.#session });
  }

  /** How many of the current session's records satisfy `which`; 0 when there is no session. */
  #count(which: (record: IdRecord) => boolean): number {
    let found = 0;
    for (const record of this.#session?.records() ?? []) if (which(record)) found += 1;
    return found;
  }

  /**
   * Diagnostic: the number of half-finished body buffers. Kept public so that
   * the cancellation/disconnect paths can be verified from the outside not to
   * leak buffers.
   */
  get pendingBodyCount(): number {
    return this.#count((record) => record instanceof RequestRecord && record.body !== undefined);
  }

  /** Diagnostic: requests waiting to be applied to the apiserver, or in progress. */
  get inFlightCount(): number {
    return this.#count((record) => record instanceof RequestRecord);
  }

  /** Diagnostic: streams open to the apiserver (so a leak can be measured from the outside). */
  get streamCount(): number {
    return this.#count((record) => record instanceof StreamRecord && record.upstream !== undefined);
  }

  /**
   * Diagnostic: the negotiated tunnel version the current session's `welcome`
   * reported — 0 between sessions and before `welcome`, since the number
   * belongs to the session, not to the agent.
   */
  get protocolVersion(): number {
    const session = this.#session;
    return session && !session.ended ? session.protocol : 0;
  }

  /** Diagnostic: sample frames written to the wire, and frames the encoder refused. */
  get metricsStats(): { readonly framesSent: number; readonly encodeFailures: number } {
    return {
      framesSent: this.#sampleWire.framesSent,
      encodeFailures: this.#sampleWire.encodeFailures,
    };
  }

  async start(): Promise<void> {
    this.#target = await resolveKubeTarget(this.#config);
    console.log(`[agent] apiserver: ${this.#target.baseUrl}`);
    this.#connect();
  }

  /**
   * Shuts the client down, once: every later call returns the same promise.
   *
   * `index.ts` can call this twice (SIGTERM and SIGINT are two handlers on one
   * shutdown), and a second run of the body used to call `KubeTarget.close()`
   * a second time, which undici's Agent rejects (`UND_ERR_DESTROYED`) — an
   * unhandled rejection on the way out.
   */
  stop(): Promise<void> {
    this.#stopping ??= this.#shutdown();
    return this.#stopping;
  }

  async #shutdown(): Promise<void> {
    this.#stopped = true;
    if (this.#reconnectTimer) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    // The session first: every request, stream, `/version` read and timer it
    // holds stops here, and from now on no message that still arrives on its
    // socket starts anything new (see the 'message' handler in `#connect`).
    // Measured on the base before this ordering: a watch sent while `stop()`
    // was waiting for the collector reached the apiserver, and a `/version`
    // read nobody aborted kept `target.close()` waiting.
    this.#session?.end();
    // Before the target closes: the collector's watches and kubelet reads go
    // through it, and stopping them after its dispatcher is gone would produce
    // a burst of connection errors on the way out.
    await this.#collector?.stop();
    this.#collector = undefined;
    this.#session?.socket.close();
    await this.#target?.close();
  }

  /**
   * Loads `YEKE_CORE_CA_FILE` before a connection attempt, keeping `#coreCa`
   * current.
   *
   * Called from `#connect` on EVERY attempt, not once at startup: a ConfigMap
   * update lands on the pod's mount without a restart (kubelet, ~1 minute) and
   * the rotation procedure this file supports (architecture decision §3.10)
   * completes without the pod ever being touched — the reconnect that follows
   * a certificate change is itself the moment the new root must be picked up.
   *
   * The first successful load is the one exception to "never bring the tunnel
   * down over this": before it, `#coreCa` is `undefined` and there is no last
   * known good set to fall back to, so a rule violation propagates out of
   * `start()` and `main()` (`index.ts`) reports it as `[agent] failed to
   * start: …` — the same reader-facing convention as `config.ts`'s
   * `required()`. After that first success, a read or parse failure (file
   * briefly missing during a ConfigMap swap, a truncated write) is caught here
   * and logged instead: the socket still connects with whatever CA is already
   * trusted, rather than the agent going down over a transient read.
   *
   * The startup CA line is printed whenever the loaded root SET changed since
   * the last time it was printed (`#loggedCoreCaRootFingerprints`) — not only
   * on the very first load. Independent finding, 15.09.2026: printing once
   * ever meant a full rotation (§3.10 — the file's roots change TWICE while
   * the pod is never restarted) produced no line at all past the first
   * certificate, which is exactly the case §3.14's "which CA is distributed
   * is auditable" claim exists for. An ordinary reconnect that re-reads the
   * SAME file still prints nothing, same as before.
   *
   * Two more warnings follow the exact same "once per changed SET" shape,
   * both independent findings from 15.09.2026: too many roots for
   * `hello.coreCaRoots` to carry (`CORE_CA_HELLO_ROOTS_LIMIT`), and
   * `loadCoreCa`'s own `skippedExpired` (K16) — see each field's own
   * comment for why a per-attempt warning was the wrong rate for either.
   */
  #loadCoreCaForConnect(): void {
    const file = this.#config.coreCaFile;
    if (!file) return;
    try {
      const bundle = loadCoreCa(file);
      this.#coreCa = bundle;

      const fingerprints = bundle.roots.map((root) => root.fingerprint256);
      const changed =
        !this.#loggedCoreCaRootFingerprints || !sameRootFingerprintSet(this.#loggedCoreCaRootFingerprints, fingerprints);
      if (changed) {
        console.log(describeCoreCa(file, bundle));
        this.#loggedCoreCaRootFingerprints = fingerprints;
      }

      if (fingerprints.length > CORE_CA_HELLO_ROOTS_LIMIT) {
        const oversizedChanged =
          !this.#loggedOversizedRootFingerprints ||
          !sameRootFingerprintSet(this.#loggedOversizedRootFingerprints, fingerprints);
        if (oversizedChanged) {
          console.warn(
            `[agent] core CA: ${fingerprints.length} valid root(s) loaded from ${file}, more than hello.coreCaRoots ` +
              `can report (${CORE_CA_HELLO_ROOTS_LIMIT}); the field is left out of hello until the file has ` +
              `${CORE_CA_HELLO_ROOTS_LIMIT} or fewer distinct roots`,
          );
          this.#loggedOversizedRootFingerprints = fingerprints;
        }
      } else {
        this.#loggedOversizedRootFingerprints = undefined;
      }

      if (bundle.skippedExpired.length > 0) {
        const skippedFingerprints = bundle.skippedExpired.map((cert) => cert.fingerprint256);
        const skippedChanged =
          !this.#loggedSkippedExpiredFingerprints ||
          !sameRootFingerprintSet(this.#loggedSkippedExpiredFingerprints, skippedFingerprints);
        if (skippedChanged) {
          console.warn(describeSkippedCoreCa(file, bundle.skippedExpired));
          this.#loggedSkippedExpiredFingerprints = skippedFingerprints;
        }
      } else {
        this.#loggedSkippedExpiredFingerprints = undefined;
      }
    } catch (err) {
      if (!this.#coreCa) throw err;
      console.warn(
        `[agent] core CA file could not be re-read, using the last known set: ${(err as Error).message}`,
      );
    }
  }

  #connect(): void {
    if (this.#stopped) return;

    this.#loadCoreCaForConnect();

    const coreCa = this.#coreCa;
    const socket = new WebSocket(this.#config.coreUrl, {
      headers: {
        [AGENT_TOKEN_HEADER]: this.#config.token,
        [AGENT_CLUSTER_HEADER]: this.#config.clusterId,
      },
      // An ADDITION to Node's own default trust store, never a replacement
      // (K2): the option is omitted entirely when no corporate CA is
      // configured, so a CA-less agent's TLS behaviour is byte-for-byte what
      // it was before this field existed — `ca: []` would not be equivalent,
      // since Node treats a `ca` option (even empty) as replacing the
      // default trust store rather than leaving it alone. The base of the
      // union is `defaultCoreCaCertificates()`, not `tls.rootCertificates` —
      // see that function's comment (`core-ca.ts`) for why the difference
      // matters: the bundled-roots-only list silently dropped an operator's
      // own `NODE_EXTRA_CA_CERTS` or `--use-system-ca` trust the moment this
      // option was also set.
      ...(coreCa ? { ca: [...defaultCoreCaCertificates(), ...coreCa.ca] } : {}),
      // Measured on the base (12.10.2026): against an address that accepts
      // the TCP connection and then never answers the upgrade (a stalled
      // proxy or load balancer), the attempt stayed CONNECTING with no log
      // line and no reconnect — `ws` sets no handshake deadline by default,
      // Node's HTTP client has none either, and the liveness check only
      // starts on 'open'. With a deadline the attempt fails like any other
      // ('error', then 'close') and the backoff path takes over.
      handshakeTimeout: this.#config.handshakeTimeoutMs ?? TUNNEL_LIVENESS_TIMEOUT_MS,
    });
    // One session per socket, created before any of its events can fire: every
    // handler below closes over THIS session, never over `this.#session`, which
    // will name a different session after the next reconnect.
    const session = new TunnelSession(socket);
    this.#session = session;

    socket.on("open", async () => {
      // `#backoff` is NOT reset here — see its own comment. `open` proves
      // only the TCP+TLS handshake; the reset waits for `welcome`.
      console.log("[agent] core connection opened");
      session.lastSeenAt = Date.now();
      this.#startLiveness(session);
      // K15 (architecture decision §3.15): the sha256 fingerprints of the
      // ROOTS this very connection's `ca` option carries — read from `coreCa`
      // above, the local binding `#loadCoreCaForConnect` just refreshed for
      // THIS attempt, not from `this.#coreCa` again (a later reconnect must
      // not relabel an earlier session's `hello`). `[]`, never omitted, when
      // no corporate CA is configured, so core can tell "an agent that knows
      // this field and has nothing to report" apart from "an agent that
      // predates the field" (which sends no `coreCaRoots` at all) — that
      // second case is also why the field is left OUT (not sent as an
      // over-long array) past `CORE_CA_HELLO_ROOTS_LIMIT`: an agent that
      // cannot fit what it loaded into the wire's limit is, from core's
      // side, indistinguishable from one that does not know the field yet,
      // and that is the correct fallback — sending the array anyway is the
      // independent finding this comment's neighbour constant fixes.
      //
      // Leaving the field OUT relies on `serializeControlMessage` being a
      // plain `JSON.stringify` (no validation on the way out), which drops a
      // property whose value is `undefined` — the mechanism `kubernetesVersion`
      // below relies on as well.
      //
      // History (corrected 12.10.2026): this field first shipped while the
      // repository was still pinned to `@nairotech/yeke-tunnel` 5.0.0, whose
      // `HelloMessage` type had no `coreCaRoots`, and this binding carried an
      // explicit intersection type to get past the excess-property check. The
      // pin has been 5.1.0 since 16.09.2026 (`c0e69c5`), whose `HelloMessage`
      // has the field, so the binding is the plain contract type again.
      const coreCaRootFingerprints = coreCa?.roots.map((root) => root.fingerprint256);
      const hello: HelloMessage = {
        t: "hello",
        protocol: TUNNEL_PROTOCOL_VERSION,
        agentVersion: AGENT_VERSION,
        kubernetesVersion: await this.#readVersionFor(session),
        coreCaRoots:
          coreCaRootFingerprints === undefined
            ? []
            : coreCaRootFingerprints.length > CORE_CA_HELLO_ROOTS_LIMIT
              ? undefined
              : coreCaRootFingerprints,
      };
      // The `/version` read above is the one await in this handler, and it
      // used to outlive the session it was started for: a slow exec credential
      // plugin or an apiserver that does not answer held it while the socket
      // dropped and `#connect` opened the next one. It is now abandoned when
      // its session ends (`#readVersionFor`), but this handler still resumes
      // after that, on a session that is over. Before 12.10.2026 the write
      // went to the socket OF THE MOMENT, so the stale handler's `hello`
      // landed on the NEXT session — measured: that session received two
      // `hello` messages. Core's handler (`case "hello"` in its
      // `tunnel/session.ts`) applies every one it gets: it overwrites the
      // session's k8s version and `coreCaRoots`, records the agent version
      // and answers with another `welcome` — so the stale one relabelled the
      // new session with the old one's CA roots and k8s version. A message is
      // written only to the session it belongs to, because core keys its
      // per-session state (ids, labels) on the session that carried it; this
      // `hello` belongs to the `session` this handler closes over, and
      // `session.send` cannot reach any other socket. The check below only
      // adds the log line: nothing is lost by dropping the `hello` (that
      // socket is closed, and the session that replaced it builds and sends
      // its own from its own `open`), but the one visible trace of a /version
      // read that took longer than a session would otherwise be nothing at all.
      if (!session.live) {
        console.warn("[agent] session closed before its hello was sent; not sending it");
        return;
      }
      session.send(hello);
    });

    socket.on("message", (data, isBinary) => {
      // A session the agent has already given up on (the liveness check,
      // `stop()`) or whose socket is closing starts nothing new: a `req` read
      // in that gap used to reach the apiserver — measured, a watch applied
      // after `stop()` had begun — with nobody left to read its answer.
      if (!session.live) return;
      // The criterion is "any message", not "pong": the control plane's `ping`,
      // its `req` or its `credit` — each of them is proof that it is alive.
      session.lastSeenAt = Date.now();
      if (isBinary) this.#onBodyFrame(data as Buffer, session);
      else this.#onControl(data, session);
    });

    socket.on("close", (code, reason) => {
      console.warn(`[agent] connection closed (${code}) ${reason.toString()}`);
      this.#cleanupAfterDisconnect(session);
      this.#scheduleReconnect();
    });

    socket.on("error", (err) => {
      // The remedy is appended, not substituted: Node's own text stays intact
      // and the hint rides alongside it, the same "foreign text is never
      // rewritten, only labelled" rule as `failure.ts`. Logged on every
      // attempt (not once per state change) — backoff already spaces retries
      // out, and that is today's behaviour for this line.
      const code = (err as NodeJS.ErrnoException).code;
      const hint = code && TLS_TRUST_ERROR_CODES.has(code) ? ` — ${TLS_TRUST_HINT}` : "";
      console.error(`[agent] connection error: ${err.message}${hint}`);
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
   *
   * The session is ended BEFORE the socket is terminated: the decision that it
   * is dead is the moment it is over, and the messages `ws` may still emit
   * between `terminate()` and 'close' are dropped by the 'message' handler
   * instead of starting work nobody will read. The timer is the session's
   * (`TunnelSession.own`), so it cannot outlive it either.
   */
  #startLiveness(session: TunnelSession): void {
    const timer = setInterval(() => {
      if (Date.now() - session.lastSeenAt <= TUNNEL_LIVENESS_TIMEOUT_MS) return;
      console.warn(
        `[agent] core silent for ${TUNNEL_LIVENESS_TIMEOUT_MS} ms; connection considered dead`,
      );
      session.end();
      session.socket.terminate();
    }, TUNNEL_PING_INTERVAL_MS);
    timer.unref();
    session.own(timer);
  }

  #cleanupAfterDisconnect(session: TunnelSession): void {
    // Open requests and streams belong to this session; when the control plane
    // reconnects it re-establishes the watches from scratch, so stopping all of
    // them is the correct behaviour. The negotiated version goes with the
    // session object: the next session starts at 0 until its own `welcome`.
    // The sample dictionary needs no call here: it follows the session's
    // identity (see `SampleWire`).
    session.end();
  }

  /**
   * Starts the metrics collector, if this session and this operator allow it.
   *
   * Four gates, in the order they can be answered:
   *
   *  1. `YEKE_METRICS_ENABLED=false` — the operator's own switch. Nothing is
   *     started, nothing is read, and no kubelet in the cluster sees a request.
   *  2. `shouldCollect(protocol)` — K5's rule, and the reason it is a call and
   *     not a remembered sentence (`collector.ts`).
   *  3. Already running, or already starting. A `welcome` arrives once per
   *     session and the collector outlives sessions.
   *  4. The factory's own answer: `undefined` means "not here" (a kubeconfig
   *     developer machine), and it has already said why.
   *
   * Nothing here may take the tunnel down. A collector that cannot start is a
   * cluster without monitoring; a tunnel that cannot start is an unmanageable
   * cluster, and the second is not an acceptable price for the first.
   */
  async #startCollector(session: TunnelSession): Promise<void> {
    if (!this.#config.metricsEnabled) return;
    if (!shouldCollect(session.protocol)) return;
    if (this.#collectorStarting) return;
    // A reconnect. The collector outlived the session on purpose (see the field
    // below), so there is nothing to start — but there IS a ring holding
    // everything the outage produced, and K5 says it drains when the wire comes
    // back. The line is the operator's copy of that: `started` happens once in
    // the life of a pod and `resumed` says how much history is on its way.
    if (this.#collector) {
      const queued = this.#collector.queuedFrames;
      console.log(`[metrics] collector resumed, ${queued} frames queued`);
      this.#collector.flush();
      return;
    }
    const target = this.#target;
    if (!target) return;

    this.#collectorStarting = true;
    try {
      const collector = await this.#createCollector({
        target,
        sink: this.#sampleWire,
        config: this.#config,
      });
      if (!collector) return;
      // `stop()` may have been called while the factory was reading the CA off
      // disk; starting now would leave watches running after shutdown.
      if (this.#stopped) {
        await collector.stop();
        return;
      }
      collector.start();
      this.#collector = collector;
      console.log(`[metrics] collector started (control plane protocol v${session.protocol})`);
    } catch (err) {
      console.error(`[metrics] collector not started: ${(err as Error).message}`);
    } finally {
      this.#collectorStarting = false;
    }
  }

  /**
   * The `/version` read for `session`'s `hello`: abandoned the moment the
   * session ends, and after `VERSION_READ_TIMEOUT_MS` (see the constant for
   * why `hello` does not wait longer).
   *
   * Past the deadline, `hello` carries the version this agent last read
   * successfully, if there is one. Core fills the cluster's version from
   * `hello` alone (`case "hello"` in its `tunnel/session.ts`), so a session
   * whose `hello` goes without it shows "unavailable" on the cluster card for
   * the WHOLE session. Measured by the independent tester (12.10.2026), per
   * session: `["v1.30.0", null, "v1.30.0"]` — the middle reconnect had to
   * refresh an expired exec token first, and the plugin alone outran the
   * deadline. An apiserver does not change version between two reconnects
   * often enough for the last known value to be the worse answer than none;
   * an agent that has never read it still sends the field absent.
   */
  async #readVersionFor(session: TunnelSession): Promise<string | undefined> {
    const target = this.#target;
    if (!target) return undefined;
    const limitMs = this.#config.versionReadTimeoutMs ?? VERSION_READ_TIMEOUT_MS;
    const deadline = AbortSignal.timeout(limitMs);
    const version = await readKubernetesVersion(target, AbortSignal.any([session.signal, deadline]));
    if (version !== undefined) {
      this.#lastKubernetesVersion = version;
      return version;
    }
    if (!deadline.aborted || session.ended) return undefined;
    const fallback = this.#lastKubernetesVersion;
    // "identity or /version": the deadline covers the credential plugin as
    // well as the request, and the slow half is as often the plugin.
    console.warn(
      `[agent] identity or apiserver /version did not answer within ${limitMs} ms; hello is sent ${
        fallback === undefined ? "without kubernetesVersion" : `with the last known kubernetesVersion ${fallback}`
      }`,
    );
    return fallback;
  }

  #scheduleReconnect(): void {
    if (this.#stopped) return;
    const delay = this.#backoff;
    this.#backoff = Math.min(this.#backoff * 2, this.#config.reconnectMaxMs);
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      this.#connect();
    }, delay);
  }

  /**
   * D3 (12.10.2026): a `req`/`stropen` for an id this session already holds —
   * as a request OR as a stream — is not taken (`TunnelSession.claim`), and
   * nothing goes on the wire for it: the closed failure code set has no
   * "duplicate id" branch, and adding one would be a wire change for a message
   * a correct control plane never sends. The line is the operator's only
   * trace that it happened.
   */
  #ignoreDuplicate(kind: "req" | "stropen", id: number): void {
    console.warn(`[agent] ${kind} for id ${id} ignored: this session already has a request or stream with that id`);
  }

  /** `session` is the session the message arrived on; every record it creates belongs to it. */
  #onControl(raw: RawData, session: TunnelSession): void {
    let message: ControlMessage;
    try {
      message = parseControlMessage(raw.toString());
    } catch (err) {
      console.error(`[agent] unparseable control message: ${(err as Error).message}`);
      return;
    }

    switch (message.t) {
      case "welcome":
        // A session applies ONE `welcome`. Core answers each `hello` with one,
        // and the agent sends one `hello` per session (#16); a second one would
        // otherwise rewrite the negotiated version under the session's feet
        // (measured: a second `welcome` with `protocol: 4` turned the sample
        // sink off on a v5 session) and re-run the collector's resume path.
        if (session.welcomed) {
          console.warn(
            `[agent] a second welcome on one session ignored (session=${message.sessionId} protocol=v${message.protocol ?? 3})`,
          );
          break;
        }
        session.welcomed = true;
        // Independent finding, 15.09.2026: the backoff reset lives HERE, not
        // in `#connect`'s `open` handler — see `#backoff`'s own comment for
        // why. `welcome` is the one message that proves core accepted this
        // agent's `hello`; resetting any earlier (on the socket merely
        // opening) meant a control plane that rejects every `hello` never
        // saw the exponential curve engage at all.
        this.#backoff = this.#config.reconnectMinMs;
        // No `protocol` means the peer is a v3 control plane (it never sends
        // the field), and 3 is the correct assumption: treating the unknown as
        // 4 would mean trying to send stream frames to a v3 peer.
        session.protocol = message.protocol ?? 3;
        console.log(
          `[agent] registered — cluster=${message.clusterId} session=${message.sessionId} protocol=v${session.protocol}`,
        );
        // The handshake is the ONLY place this decision is made: the collector
        // spends the customer's CPU and their kubelets' capacity, and a peer
        // that cannot read `sample` would drop every frame of it in silence.
        void this.#startCollector(session);
        break;
      case "req": {
        // The record — body buffer, abort controller, credit window — is
        // registered **here**, before the handler starts. In the time it takes
        // the handler to reach its first await, a body frame or a `cancel` may
        // arrive; had the registration been on that side, the body would be
        // orphaned and the `cancel` would be lost, leaving a watch on the
        // apiserver that never closes. The record itself is what the handler
        // holds, so `responding` is set on THIS request, never on a later
        // session's request that reuses the id.
        const record = session.claim(message.id, (owner) => new RequestRecord(owner, message.id, message.hasBody));
        if (!record) {
          this.#ignoreDuplicate("req", message.id);
          break;
        }
        void this.#handleRequest(message, record);
        break;
      }
      case "reqend": {
        const record = session.lookup(message.id);
        if (record instanceof RequestRecord) record.body?.complete();
        break;
      }
      case "cancel":
        // Either kind (the id space is shared): a request is aborted and its
        // half buffer dropped; a stream's upstream socket is closed — or, if it
        // is still resolving its credentials, never opened. Either way the
        // control plane has forgotten the id, and the record stops speaking.
        session.lookup(message.id)?.stop(1000, "cancelled");
        break;
      case "credit":
        // An id with no record is dropped silently: the late credit of a
        // cancelled request must not open a new window. In v4 the same message
        // also arrives for the stdout/stderr direction of a stream — that it
        // does not state a direction is by design: credit is always granted by
        // the **receiver**. The lookup is in the session the credit arrived on,
        // which holds nothing of any other session.
        session.lookup(message.id)?.grantCredit(message.bytes);
        break;
      case "stropen": {
        // Registered HERE, before the handler starts, for the same reason as
        // `req` above: the handler's first await is `authHeaders()`, which an
        // abort cannot interrupt, and a `cancel`/`strclose` arriving meanwhile
        // must find something to stop even though no upstream socket exists
        // yet. A duplicate id — a stream still opening, an open one, or a
        // request — is ignored: two handlers racing for one id would leave one
        // upstream socket nobody can address.
        const record = session.claim(message.id, (owner) => new StreamRecord(owner, message.id));
        if (!record) {
          this.#ignoreDuplicate("stropen", message.id);
          break;
        }
        void this.#openStream(message, record);
        break;
      }
      case "strclose": {
        const record = session.lookup(message.id);
        if (record instanceof StreamRecord) record.stop(message.code ?? 1000, message.reason);
        break;
      }
      case "ping":
        session.send({ t: "pong", ts: message.ts });
        break;
      default:
        break;
    }
  }

  #onBodyFrame(frame: Buffer, session: TunnelSession): void {
    const decoded = decodeBodyFrame(frame);
    if (!decoded) return;
    const record = session.lookup(decoded.requestId);
    // If it is a stream id, the payload is written straight to the apiserver:
    // its first byte is k8s's channel byte and the agent does **not** interpret
    // it (the one exception being the half-close gate, see
    // `UpstreamStream.write`). A stream still resolving its credentials has no
    // upstream yet, and the frame is dropped, as it always was.
    if (record instanceof StreamRecord) {
      record.upstream?.write(decoded.payload);
      return;
    }
    // Ids with no record are dropped silently: a late frame of a cancelled or
    // rejected request must not create a new map entry — in v1 that left buffers
    // that were never collected.
    if (record instanceof RequestRecord) record.body?.push(decoded.payload);
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
   *
   * The stream belongs to ONE session, the one its `stropen` arrived on, and
   * every message it ever sends goes through its `record` — so to that
   * session's socket only, and only while the control plane still waits for
   * the id. Stream ids are per session, exactly like request ids (the control
   * plane allocates them from 1 again on every connection, in the same id
   * space), and a stream can outlive what it was opened for in three ways,
   * each of them measured as a failure before the record existed:
   *
   *  - Still opening when the session drops: `await target.authHeaders()`
   *    cannot be interrupted (an exec plugin runs to completion), so the next
   *    session may already be connected when it returns. The stale handler
   *    used to open the exec upgrade on the apiserver, put the stream into
   *    the next session's map and send that session `strok` (or `err`) for an
   *    id it had never allocated — a pty nobody reads.
   *  - Open when the session drops: the session ends the stream, but the
   *    upstream close completes later, and its `onClose`/`onError` run then;
   *    deleting by id removed the next session's stream that reused the id,
   *    and "the socket of the moment" was by then the next session's.
   *  - Cancelled by the control plane (`cancel`/`strclose`) while its upstream
   *    WebSocket was still in its handshake: `ws` reports that as an error,
   *    and the agent answered with `err` for the id core had just forgotten.
   *
   * After `authHeaders()` a record that is no longer `live` is NOT opened
   * upstream, and nothing is sent for it: the control plane has forgotten the
   * id, or its session is gone.
   */
  async #openStream(message: StreamOpenMessage, record: StreamRecord): Promise<void> {
    const { id } = message;
    try {
      const target = this.#target;
      if (!target) {
        record.fail({ code: "NO_TARGET", params: {} });
        return;
      }
      if (!isAllowedPath(message.path)) {
        record.fail({ code: "PATH_NOT_ALLOWED", params: { path: message.path } });
        return;
      }
      if (message.protocols.length === 0) {
        // The wire schema already rejects this (`z.array().min(1)`); the gate is
        // here too because a stream opened with an empty list would fall back to
        // the unversioned `channel.k8s.io` and the failure would surface months
        // later as "exit codes are always 0".
        record.fail({ code: "STREAM_PROTOCOL_REQUIRED", params: {} });
        return;
      }

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
        // The one await is behind us; see the doc comment. From here to the
        // `upstream` assignment everything is synchronous, so no `cancel` and
        // no disconnect can slip in between this check and the registration.
        if (!record.live) return;
        const tls = target.tlsOptions();

        // `https:` → `wss:`. Rather than writing the scheme by hand we derive it
        // from the target.
        const base = target.baseUrl.replace(/^http/, "ws");
        const url = `${base}${message.path}${message.query ? `?${message.query}` : ""}`;

        // The hooks only ever run from the upstream socket's events, never
        // during construction. Each one writes through `record`, so a hook that
        // runs after the record stopped (a late frame, a late close or error)
        // writes nothing and needs no guard of its own.
        record.upstream = new UpstreamStream(
          { url, protocols: [...message.protocols], headers, tls },
          {
            onOpen: (protocol) => record.send({ t: "strok", id, protocol }),
            onFrame: (frame) => record.sendBody(frame),
            onStdinDelivered: (bytes) => record.send({ t: "credit", id, bytes }),
            onClose: (code, reason) => {
              record.send({ t: "strclose", id, code, reason });
              record.finish();
            },
            onError: (failure) => {
              record.fail(failure);
              record.finish();
            },
          },
        );
      } catch (err) {
        // `record.fail` writes nothing for a record that is no longer `live`,
        // which is the case this `catch` used to need its own abort check for:
        // `authHeaders()` REJECTING after a `cancel`/`strclose`/disconnect (the
        // plugin failed or timed out while the control plane gave up on the
        // id). Everything after the post-await check is synchronous, so a
        // throw from `tlsOptions()` or the constructor arrives with the record
        // still live and is reported.
        //
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
        record.fail(
          failureOf(err, (detail) => ({
            code: "EXEC_UPGRADE_UNREACHABLE",
            params: { origin: "node", detail },
          })),
        );
      }
    } finally {
      // A stream that never got an upstream is over here (rejected, failed, or
      // stopped while opening). One that did is over when its upstream closes
      // or fails, or when it is stopped.
      if (!record.upstream) record.finish();
    }
  }

  async #handleRequest(req: RequestMessage, record: RequestRecord): Promise<void> {
    const { credit, signal } = record;
    try {
      const target = this.#target;
      if (!target) {
        record.fail({ code: "NO_TARGET", params: {} });
        return;
      }

      if (!isAllowedPath(req.path)) {
        // Defense in depth: even if the control plane is compromised, the agent
        // only goes to apiserver paths.
        record.fail({ code: "PATH_NOT_ALLOWED", params: { path: req.path } });
        return;
      }

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
      const body = record.body;
      if (body) {
        await body.wait();
        // Cancelled or disconnected while waiting: the control plane has
        // forgotten this id, so there is no point sending an error either.
        if (body.state === "aborted" || !record.live) return;
        if (body.state === "overflow") {
          record.fail({
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
        signal,
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

      record.send({ t: "res", id: req.id, status: response.statusCode, headers: responseHeaders });
      // From here the request is a flowing response, not a queued one: it no
      // longer makes the sample sink `busy` (see `SampleWire`).
      record.responding = true;

      // Response-body flow control is applied here. Because the `await` is
      // inside the loop, `for await` is suspended when credit runs out; undici
      // does not pull the next chunk and backpressure travels over TCP all the
      // way to the apiserver. We do not take the chunk into memory and count it
      // as "sent" — no buffer is displaced, production really stops.
      for await (const chunk of response.body) {
        if (!record.live) break;
        const payload = chunk as Uint8Array;
        await credit.wait(signal);
        // The request may have been cancelled, or its session dropped, while
        // waiting; leave without trying to write to a closed one.
        if (!record.live) break;
        credit.consume(payload.byteLength);
        record.sendBody(payload);
      }

      record.send({ t: "end", id: req.id });
    } catch (err) {
      // The fallback branch is `UPSTREAM_ERROR` and `detail` is undici's/Node's
      // OWN text. The agent's own diagnostic sentence cannot enter here: the
      // failures the agent knows about (the identity family) arrive typed as
      // `AgentFailure` and `failureOf` passes them through untouched. A request
      // that was cancelled or whose session ended writes nothing (`record.fail`).
      record.fail(failureOf(err, (detail) => ({ code: "UPSTREAM_ERROR", params: { detail } })));
    } finally {
      // Whichever way we leave (success, upstream error, rejection,
      // cancellation) the record is released here; late frames now land on an
      // unregistered id.
      //
      // Only THIS record, and only in its own session. Request ids are per
      // session — the control plane allocates them from 1 again on every
      // connection — and this handler can outlive its session: the session's
      // end aborts it, but an abort cannot interrupt `await
      // target.authHeaders()` (an exec plugin runs to completion). Before the
      // records (#12, 12.10.2026) this `finally` deleted by id from maps that
      // outlived sessions, and erased the NEXT session's request that reused
      // the id (it dropped out of `busy`/`inFlightCount`, and its `reqend`
      // landed nowhere). `finish()` releases from `record.session`, by
      // identity, so it cannot reach another session's request at all.
      record.finish();
    }
  }
}
