/**
 * Connection resolution towards the downstream apiserver.
 *
 * Design note: the identity of requests going to the apiserver is built **in the
 * agent**, and the cluster credential (ServiceAccount token, CA) is never sent
 * to the control plane.
 *
 * The rejected alternative is the one that is easier to build: have each agent
 * hand its downstream token and CA to the centre, store them there, and let the
 * centre talk to every apiserver directly. That design concentrates the blast
 * radius — one compromised store yields standing, direct access to every managed
 * cluster. Keeping the credential where it already lives bounds the damage of a
 * control-plane compromise to what each ServiceAccount was granted, which the
 * cluster owner can inspect and revoke per cluster.
 *
 * ---------------------------------------------------------------------------
 * Why identity is built by hand (and why this bug stayed invisible for months)
 * ---------------------------------------------------------------------------
 * The first version of this file left the identity headers to
 * `KubeConfig.applyToFetchOptions()`. That call returns the headers **as
 * `node-fetch`'s `Headers` class** (see client-node 1.4 `dist/config.js`:
 * `import { Headers } from 'node-fetch'`), not Node's global `Headers`. Our
 * `headers instanceof Headers` check was therefore **always false**; the code
 * then took the object for a plain record and passed it straight back. Since a
 * `Headers` instance has no own-enumerable properties, `Object.assign(...)`
 * copied nothing and the request reached the apiserver **without any identity**
 * → 401.
 *
 * Measurement (probe, scratch directory):
 *   headers.constructor.name        -> "Headers"
 *   headers instanceof globalThis.Headers -> false
 *   headers.get("authorization")    -> "Bearer eyJhbGciOi..."   (so the data WAS there)
 *   Object.entries(headers)         -> []                        (but it did not look like it)
 *
 * The reason this went unnoticed: every live test was done with a k3s kubeconfig
 * that used a **client certificate**. Certificate identity is established during
 * the TLS handshake (undici `Agent`'s `connect.cert`/`connect.key`) — it never
 * goes near the header path. So the entire "produce identity headers" layer was
 * dead while certificate-based tests stayed green. In-cluster mode did not cover
 * it either, because it works through a different path (the
 * `/var/run/secrets/...` token file). To avoid falling into the same blind spot
 * again: **a certificate kubeconfig does not test the header identity path.**
 * The bearer/exec paths must be exercised separately.
 *
 * ---------------------------------------------------------------------------
 * What is taken from the library, and what is not
 * ---------------------------------------------------------------------------
 * TAKEN: locating the kubeconfig (KUBECONFIG/`~/.kube/config`), YAML parsing,
 * context→cluster/user resolution, making certificate file paths absolute.
 * These work correctly and rewriting them buys nothing.
 *
 * NOT TAKEN (written by hand) and why:
 *  1. `applyToFetchOptions()` — quite apart from the `Headers` realm mismatch
 *     above, it creates a `new https.Agent(...)` on every call and reads the
 *     CA/certificate files **synchronously** with `readFileSync`. On a path
 *     called once per request both are unacceptable (an Agent that is thrown
 *     away, plus IO that blocks the event loop).
 *  2. `tokenFile` — client-node does **not support** this field at all. The
 *     `findToken()` inside `config_types.js` looks for a key named `token-file`
 *     where the kubeconfig actually says `tokenFile`; the field does not even
 *     exist on the `User` type. A probe confirmed it: with a kubeconfig that has
 *     tokenFile, `Object.keys(user)` is only `["name"]`. And even if it found
 *     the field, it would read the file once at parse time — the wrong
 *     behaviour for rotating projected SA tokens.
 *  3. `ExecAuth` — its cache collapses when `expirationTimestamp` is missing
 *     (`Date.parse(undefined)` = NaN, `NaN > now` = false), so in that case the
 *     plugin is re-run **on every request**. It also does not deduplicate
 *     concurrent requests (10 parallel requests = 10 `gcloud` processes), has no
 *     timeout, and writes the returned client certificate into
 *     `https.RequestOptions` — not into our undici dispatcher.
 *
 * The only place that needs the raw kubeconfig is `tokenFile`; we read that with
 * the library's **public** `loadYaml()` API (no new dependency, no hand-written
 * YAML parsing).
 */
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter as PATH_DELIMITER, isAbsolute, join, resolve as resolvePath } from "node:path";
import { KubeConfig, loadYaml, type Cluster, type User } from "@kubernetes/client-node";
import { Agent, type Dispatcher } from "undici";
import type { AgentConfig } from "./config.js";
import { AgentFailure } from "./failure.js";

/**
 * Where the kubelet projects the pod's own identity.
 *
 * Exported because a SECOND reader appeared with the metrics collector: the
 * kubelet client authenticates with the same token and verifies the kubelet's
 * serving certificate against the same CA (K4). Writing the path twice would be
 * a twin, and the day a distribution moves the mount, one of the two copies
 * would keep pointing at nothing.
 */
export const SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";
/** Projected SA tokens rotate; they must be re-read before they expire. */
const TOKEN_TTL_MS = 60_000;

/**
 * How long before the expiry reported by an `exec` plugin we renew.
 *
 * It cannot be zero: between the instant the plugin reports and the moment the
 * request reaches the apiserver there is network latency and clock skew.
 * client-go leaves a margin for the same reason.
 */
const EXEC_EXPIRY_MARGIN_MS = 10_000;

/**
 * Upper bound for plugins that do not report an `expirationTimestamp`.
 *
 * The specification does not make the field mandatory (saying "never expires" is
 * allowed). client-go keeps such a credential for the lifetime of the process;
 * we apply a bounded freshness window instead, because the "never expires" claim
 * is usually the plugin's oversight and we do not want to sit on a silently
 * expired token.
 */
const EXEC_DEFAULT_TTL_MS = 5 * 60_000;

/** Upper bound that stops a stuck credential plugin from locking every request. */
const EXEC_TIMEOUT_MS = 60_000;

/** Buffer limit for plugin output; an ExecCredential JSON is a few KiB. */
const EXEC_MAX_OUTPUT_BYTES = 1024 * 1024;

/**
 * Minimum interval between forced refreshes triggered by an apiserver 401.
 *
 * A 401 can genuinely mean "the identity went stale" (refreshing is right), but
 * it can also mean "the credential is entirely invalid". In the second case, if
 * every request triggered a new refresh we would run `gcloud` dozens of times
 * per second.
 */
const UNAUTHORIZED_REFRESH_COOLDOWN_MS = 5_000;

/**
 * TLS material for the WebSocket upgrade.
 *
 * Why the `dispatcher` is not enough: undici's dispatcher is the connection pool
 * for HTTP requests; on the stream path the socket is created by `ws` and the
 * options have to be handed to it directly. It matters that both paths use the
 * **same** material — if they diverge you get a hard-to-diagnose difference like
 * "requests work but the terminal reports a TLS error". So the material is
 * resolved in one place and distributed to both paths.
 *
 * Must be read **after** `authHeaders()`: if the exec plugin returned a client
 * certificate, the swap happens there (see `syncDispatcher`).
 */
export interface KubeTlsOptions {
  ca?: Buffer;
  cert?: Buffer | string;
  key?: Buffer | string;
  rejectUnauthorized: boolean;
  servername?: string;
}

export interface KubeTarget {
  readonly baseUrl: string;
  /** Called before every request; makes token rotation invisible. */
  authHeaders(): Promise<Record<string, string>>;
  readonly dispatcher: Dispatcher;
  /** TLS material for the stream (WebSocket) path; read after `authHeaders()`. */
  tlsOptions(): KubeTlsOptions;
  /**
   * Called when the apiserver returns 401: the cached identity is dropped and
   * the next `authHeaders()` resolves it again.
   *
   * Without this hook, a credential with no declared expiry — or one revoked
   * early — would keep producing 401s until its TTL ran out.
   */
  invalidateCredential(reason: string): void;
  close(): Promise<void>;
}

/**
 * Reader for the in-cluster SA token — a read failure here is an **IDENTITY**
 * failure.
 *
 * ─── Why a separate function, and why it wraps (2026-08-08) ─────────────────
 *
 * This read used to sit bare inside `resolveInCluster`, and Node's `readFile`
 * error (deleted projected volume, permissions, full disk) escaped upwards.
 * Where it escaped to is known: the general `catch` on `tunnel-client.ts`'s
 * request path classified it with `failureOf(err, … UPSTREAM_ERROR …)`. So when
 * the agent's OWN token file could not be read, the operator was told
 * *"upstream returned an error"* and the user interface pointed them at the
 * apiserver — preventing exactly that misdirection is why the
 * `CREDENTIAL_UNAVAILABLE` branch exists (rationale in `CredentialCache`'s
 * `catch`).
 *
 * Why the wrapping is here and not in `CredentialCache`: the in-cluster path
 * does not go through that cache **at all**. `resolveInCluster` builds its own
 * mini cache (reading a file is cheap, there is no `exec` plugin), and the code
 * on that path was outside the identity family's protection. When a rule is
 * enforced in one place only, it leaks through the second path where it is not
 * (`config.ts`'s "an invariant that is not enforced" sentence).
 *
 * An empty file gets its own code (`TOKEN_FILE_EMPTY`) — same rationale as its
 * sibling on the `tokenFile` branch: the read succeeded, there is no identity;
 * this failure is **silent**, and putting it in the same box as an unreadable
 * file sends the diagnosis to the wrong place.
 *
 * `path` is a parameter because the test injects it: you cannot create and
 * destroy `/var/run/secrets/...` from a unit test.
 */
export function serviceAccountToken(
  path: string,
  options: { readonly ttlMs?: number; readonly now?: () => number } = {},
): { read(): Promise<string>; invalidate(): void } {
  const ttlMs = options.ttlMs ?? TOKEN_TTL_MS;
  const now = options.now ?? Date.now;
  let cached = "";
  // `readAt = 0` is NOT a "stale" marker: the old version treated it as one and
  // only worked because the real clock is a very large number (`Date.now() - 0`
  // always exceeds the TTL). The claim collapsed the moment the clock became
  // injectable — in the test the cache kept talking after `invalidate()`. The
  // emptiness is now carried by the type itself; no invariant leans on the
  // magnitude of a number.
  let readAt: number | null = null;
  return {
    async read() {
      if (cached && readAt !== null && now() - readAt <= ttlMs) return cached;
      let text: string;
      try {
        text = await readFile(path, "utf8");
      } catch (err) {
        throw new AgentFailure({
          code: "CREDENTIAL_UNAVAILABLE",
          params: { detail: err instanceof Error ? err.message : String(err) },
        });
      }
      const token = text.trim();
      if (!token) {
        console.error(`[agent] service account token file is empty: ${path}`);
        throw new AgentFailure({ code: "TOKEN_FILE_EMPTY", params: { path } });
      }
      cached = token;
      readAt = now();
      return token;
    },
    invalidate() {
      readAt = null;
    },
  };
}

async function resolveInCluster(): Promise<KubeTarget> {
  const host = process.env.KUBERNETES_SERVICE_HOST;
  const port = process.env.KUBERNETES_SERVICE_PORT ?? "443";
  if (!host) {
    // English and untyped: this error never reaches the wire. It is thrown at
    // startup, before the tunnel exists, and it brings the process down — its
    // reader is the operator running `kubectl logs yeke-agent`, not the user in
    // front of the user interface (see "Conventions" in README.md).
    throw new Error(
      "in-cluster mode requires KUBERNETES_SERVICE_HOST. Is the agent running inside a pod? " +
        "For local development use YEKE_KUBE_MODE=kubeconfig.",
    );
  }

  const ca = await readFile(`${SA_DIR}/ca.crt`);
  const dispatcher = new Agent({ connect: { ca } });

  const token = serviceAccountToken(`${SA_DIR}/token`);

  return {
    baseUrl: `https://${host}:${port}`,
    dispatcher,
    tlsOptions: () => ({ ca, rejectUnauthorized: true }),
    async authHeaders() {
      return { authorization: `Bearer ${await token.read()}` };
    },
    invalidateCredential(reason) {
      // The kubelet rotates the token in place; re-reading the file is enough.
      console.warn(`[agent] SA token will be re-read: ${reason}`);
      token.invalidate();
    },
    async close() {
      await dispatcher.close();
    },
  };
}

/** kubeconfig fields are either base64-inline (`*Data`) or a file path (`*File`). */
async function readPem(data?: string, file?: string): Promise<Buffer | undefined> {
  if (data) return Buffer.from(data, "base64");
  if (file) return readFile(file);
  return undefined;
}

/**
 * The single-round result of a resolved identity.
 *
 * Headers and TLS material travel in the **same** structure because `exec`
 * plugins may return either one: `status.token` (header) or
 * `status.clientCertificateData`/`clientKeyData` (TLS). Which one arrives is
 * only known at runtime.
 */
interface KubeCredential {
  headers: Record<string, string>;
  clientCertPem?: string;
  clientKeyPem?: string;
  /** Must be resolved again after this instant (ms epoch). `Infinity` = static identity. */
  validUntil: number;
  /** Short description shown in logs; the token itself is NEVER written. */
  describe: string;
}

type CredentialLoader = () => Promise<KubeCredential>;

/**
 * Identity cache: freshness check + deduplication of concurrent calls.
 *
 * Deduplication (`#inFlight`) is not an optional optimisation but a correctness
 * requirement: `authHeaders()` is called once per request and dozens of requests
 * are in flight through the tunnel at any moment. Without deduplication, a
 * single `exec` refresh would spawn N `gcloud` processes at once — the shortest
 * path to hitting a rate limit and to drowning the machine.
 */
class CredentialCache {
  #load: CredentialLoader;
  #current: KubeCredential | null = null;
  #inFlight: Promise<KubeCredential> | null = null;
  #lastForcedAt = 0;

  constructor(load: CredentialLoader) {
    this.#load = load;
  }

  async get(): Promise<KubeCredential> {
    const current = this.#current;
    if (current && Date.now() < current.validUntil) return current;
    // Calls arriving while a load is in progress join the same promise.
    if (this.#inFlight) return this.#inFlight;

    const pending = this.#load()
      .then((credential) => {
        this.#current = credential;
        return credential;
      })
      .catch((err: unknown) => {
        // ─── An unclassified identity error gets TYPED here ─────────────────
        //
        // Failures the loaders know about already throw `AgentFailure`; the rest
        // are Node's own errors (an unreadable `tokenFile`, an unresolvable
        // path). The reason for wrapping in a single place is where it would
        // land otherwise: the general `catch` in `tunnel-client.ts` would call
        // it `UPSTREAM_ERROR`, and with no "upstream" involved at all the
        // operator would go looking at the apiserver — while the fault is in the
        // agent's OWN kubeconfig. Since there are two callers (the request path
        // and the stream path), the wrapping is not inside them but here.
        if (err instanceof AgentFailure) throw err;
        const detail = err instanceof Error ? err.message : String(err);
        throw new AgentFailure({ code: "CREDENTIAL_UNAVAILABLE", params: { detail } });
      })
      .finally(() => {
        // Cleared on failure too: otherwise a single transient error would lock
        // the cache onto a permanently rejected promise.
        this.#inFlight = null;
      });

    this.#inFlight = pending;
    return pending;
  }

  /** Forced refresh after a 401; bounded by a cooldown window. */
  invalidate(reason: string): void {
    const now = Date.now();
    if (now - this.#lastForcedAt < UNAUTHORIZED_REFRESH_COOLDOWN_MS) return;
    this.#lastForcedAt = now;
    if (!this.#current) return;
    console.warn(`[agent] identity cache dropped (${reason})`);
    this.#current = null;
  }
}

/** The shape of the `exec` block in a kubeconfig (client.authentication.k8s.io). */
interface ExecConfig {
  command: string;
  args?: string[];
  env?: Array<{ name: string; value: string }>;
  apiVersion?: string;
  interactiveMode?: string;
  provideClusterInfo?: boolean;
}

interface ExecCredentialStatus {
  token?: string;
  clientCertificateData?: string;
  clientKeyData?: string;
  expirationTimestamp?: string;
}

/**
 * Runs an ExecCredential plugin (GKE `gke-gcloud-auth-plugin`, EKS
 * `aws eks get-token`, `kubelogin`, …).
 *
 * `KUBERNETES_EXEC_INFO` is always provided: plugins read the apiVersion from it
 * and v1 plugins fail when the variable is missing. Cluster information, on the
 * other hand, is only added when `provideClusterInfo: true` — that is what the
 * specification says, and we do not leak the server address into a child process
 * needlessly.
 *
 * Exported on purpose: the line that separates the TWO foreign texts of
 * `AUTH_PLUGIN_FAILED` (Node's message, the plugin's `stderr`) is here, and its
 * measurement (`kube.test.ts`) drives this function directly with a fake plugin.
 * Going through `KubeTarget` would require a kubeconfig file plus a cluster
 * record, and the thing under measurement would still be this line.
 */
export function runExecPlugin(
  exec: ExecConfig,
  cluster: Cluster,
): Promise<ExecCredentialStatus> {
  const apiVersion = exec.apiVersion ?? "client.authentication.k8s.io/v1beta1";

  if (exec.interactiveMode === "Always") {
    // The agent is a service; there is no TTY. Better to say so immediately than
    // to run it silently and hang.
    //
    // The sentence does NOT go on the wire, the code does
    // (`AUTH_PLUGIN_INTERACTIVE {command}`); the diagnostic text is written in
    // English to the agent's own stdout. The sentence on screen is composed by
    // the layer that knows the user's language.
    console.error(
      `[agent] credential plugin '${exec.command}' requires interactiveMode=Always, but the agent has no TTY. ` +
        "Configure the plugin for non-interactive use (for GKE: run `gcloud auth application-default login` first).",
    );
    return Promise.reject(
      new AgentFailure({ code: "AUTH_PLUGIN_INTERACTIVE", params: { command: exec.command } }),
    );
  }

  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const entry of exec.env ?? []) {
    if (entry?.name) env[entry.name] = entry.value;
  }
  env.KUBERNETES_EXEC_INFO = JSON.stringify({
    apiVersion,
    kind: "ExecCredential",
    spec: {
      interactive: false,
      ...(exec.provideClusterInfo
        ? {
            cluster: {
              server: cluster.server,
              "certificate-authority-data": cluster.caData,
              "insecure-skip-tls-verify": cluster.skipTLSVerify,
              "tls-server-name": cluster.tlsServerName,
            },
          }
        : {}),
    },
  });

  return new Promise<ExecCredentialStatus>((resolve, reject) => {
    const child = execFile(
      exec.command,
      exec.args ?? [],
      { env, timeout: EXEC_TIMEOUT_MS, maxBuffer: EXEC_MAX_OUTPUT_BYTES, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) {
          // ─── The two texts are NOT merged; they travel in SEPARATE fields ──
          //
          // Both are foreign texts, but they have different OWNERS:
          // `err.message` is Node's (`Command failed: …`, `spawn ENOENT`),
          // `stderr` is the plugin's ("no credentials"). For a while they were
          // merged as `` `${err.message} — ${stderr}` `` into a single `detail`,
          // and the schema branch called that "the plugin's OWN stderr"; the
          // user interface duly labelled it "what the plugin wrote to stderr:".
          // Even in the good case the label sat in front of Node's sentence, and
          // when `stderr` was empty (`ENOENT`, a timeout kill) the text was
          // Node's in its ENTIRETY — that is, the label claimed the plugin had
          // written something it never wrote.
          //
          // The rationale for merging ("neither is enough on its own") WAS
          // correct and is preserved: both still travel, just in separate fields,
          // each rendered under its own label. No diagnostic is lost; the only
          // thing lost is the wrong label.
          const stderrText = String(stderr).trim().slice(0, 500);
          // ─── MEASURED: Node echoes stderr into its OWN `message` ───────────
          //
          // `execFile`'s error is shaped `Command failed: <command>\n<stderr>`.
          // So dropping the merge is NOT enough on its own — putting `err.message`
          // into `detail` verbatim would print the plugin's text a second time
          // under Node's label, and the same line would appear twice on screen
          // with two different owners. This was found by measurement, not by
          // guesswork: the separation test broke on its very first run for
          // exactly this reason (`kube.test.ts`).
          //
          // The first line is Node's OWN frame (which command, how it ended);
          // the rest is the echo of the plugin and already travels verbatim in
          // the `stderr` field. If it comes out empty (should the format change
          // one day) we fall back to the whole message — showing extra text
          // beats losing a diagnostic.
          const nodeText = err.message.split("\n", 1)[0]?.trim() ?? "";
          const detail = nodeText || err.message.trim();
          console.error(
            `[agent] credential plugin '${exec.command}' failed: ${detail}` +
              (stderrText ? ` — ${stderrText}` : ""),
          );
          reject(
            new AgentFailure({
              code: "AUTH_PLUGIN_FAILED",
              // `stderr` may be an EMPTY STRING, and that is not a gap but a
              // fact: the plugin may never have run, or may have died silently.
              // The schema keeps it mandatory (`z.string()`), representing
              // absence with an empty string rather than `undefined` — the
              // renderer attaches no label to empty text, so no half-finished
              // "…:" line appears on screen.
              params: { command: exec.command, detail, stderr: stderrText },
            }),
          );
          return;
        }

        // ─── The four rejections below share the SAME code ───────────────────
        //
        // All four say "the plugin ran but produced no usable ExecCredential",
        // and the operator looks in the same place: the plugin's version and its
        // contract. `reason` is still carried separately — the difference
        // between the four cases helps when hunting a plugin version, and being
        // a machine token it can be turned into a sentence on screen.
        const badOutput = (reason: string): AgentFailure => {
          console.error(
            `[agent] credential plugin '${exec.command}' did not return a usable ExecCredential (${reason})`,
          );
          return new AgentFailure({
            code: "AUTH_PLUGIN_BAD_OUTPUT",
            params: { command: exec.command, reason },
          });
        };

        let parsed: { kind?: string; status?: ExecCredentialStatus };
        try {
          parsed = JSON.parse(stdout) as typeof parsed;
        } catch {
          reject(badOutput("not-json"));
          return;
        }

        if (parsed.kind && parsed.kind !== "ExecCredential") {
          reject(badOutput("wrong-kind"));
          return;
        }
        if (!parsed.status || typeof parsed.status !== "object") {
          reject(badOutput("no-status"));
          return;
        }
        resolve(parsed.status);
      },
    );
    // The plugin expects nothing on stdin; leaving an open pipe makes some
    // plugins (e.g. kubelogin) wait for interaction.
    child.stdin?.end();
  });
}

/**
 * Reads the raw `users[]` entry from the kubeconfig.
 *
 * It exists for a single field: `tokenFile`. client-node drops it (see the note
 * at the top of this file), so we read the file once more through the library's
 * public `loadYaml()` function and pull out just that field. No hand-written
 * YAML parsing and no new dependency required.
 *
 * The file list follows `KubeConfig.loadFromDefault()`'s behaviour: if
 * `KUBECONFIG` is set, the delimiter-separated list, otherwise `~/.kube/config`.
 * If the same user name appears in more than one file, the first file wins —
 * that is also the library's `mergeConfig` order.
 */
async function readRawUserEntry(userName: string): Promise<Record<string, unknown> | undefined> {
  const fromEnv = process.env.KUBECONFIG;
  const files = fromEnv
    ? fromEnv.split(PATH_DELIMITER).filter(Boolean)
    : [join(homedir(), ".kube", "config")];

  for (const file of files) {
    let text: string;
    try {
      text = await readFile(file, "utf8");
    } catch {
      continue; // An unreadable file is skipped on the library side as well.
    }

    let parsed: { users?: Array<{ name?: string; user?: Record<string, unknown> }> };
    try {
      parsed = loadYaml<typeof parsed>(text);
    } catch (err) {
      console.warn(`[agent] kubeconfig raw read failed (${file}): ${(err as Error).message}`);
      continue;
    }

    const entry = parsed.users?.find((u) => u?.name === userName);
    if (!entry?.user) continue;

    // Relative paths are relative to the directory containing the kubeconfig
    // file (the same rule the library applies in `makePathsAbsolute` for
    // certificate paths).
    const tokenFile = entry.user.tokenFile;
    if (typeof tokenFile === "string" && tokenFile && !isAbsolute(tokenFile)) {
      entry.user.tokenFile = resolvePath(join(file, ".."), tokenFile);
    }
    return entry.user;
  }
  return undefined;
}

/** Basic auth header; `username`/`password` is still a valid kubeconfig form. */
function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`;
}

/**
 * Picks the credential loader for a kubeconfig user.
 *
 * Returning `null` is not an error: a pure client-certificate identity produces
 * no header, the identity is established during the TLS handshake.
 */
function selectCredentialLoader(
  user: User,
  rawUser: Record<string, unknown> | undefined,
  cluster: Cluster,
): CredentialLoader | null {
  const authProvider = user.authProvider as
    | { name?: string; config?: Record<string, unknown> }
    | undefined
    | null;

  // Two sub-forms of the old `auth-provider` format can still be supported
  // mechanically; neither opens a new path, both hook into existing loaders.
  const providerExec = authProvider?.config?.exec as ExecConfig | undefined;
  const providerTokenFile = authProvider?.config?.tokenFile;

  const exec = (user.exec ?? providerExec) as ExecConfig | undefined | null;
  const tokenFile =
    (typeof rawUser?.tokenFile === "string" ? rawUser.tokenFile : undefined) ??
    (typeof providerTokenFile === "string" ? providerTokenFile : undefined);

  if (authProvider?.name && !providerExec && !providerTokenFile) {
    // `gcp`, `oidc`, `azure`: these providers were **removed from client-go in
    // 1.26**. We do not support them, because implementing them correctly
    // requires running the refresh-token flow and **writing the refreshed token
    // back into the kubeconfig file** — for a service process that is both wrong
    // and dangerous (modifying the user's file). Rather than dropping them
    // silently, we say so loudly at setup time so nobody goes hunting 401s.
    // English and untyped: a startup error, it never reaches the wire (see the
    // same rationale in `resolveInCluster`).
    throw new Error(
      `kubeconfig user '${user.name}' uses the unsupported auth-provider '${authProvider.name}'. ` +
        "These providers were removed from client-go in Kubernetes 1.26 and are not supported by the agent " +
        "because they require writing the refreshed token back into the kubeconfig file. Switch to an exec " +
        "credential plugin: gke-gcloud-auth-plugin for GKE (`gcloud components install gke-gcloud-auth-plugin` + " +
        "`gcloud container clusters get-credentials ...`), kubelogin for Azure/OIDC.",
    );
  }

  const configured = [
    exec ? "exec" : null,
    tokenFile ? "tokenFile" : null,
    user.token ? "token" : null,
    user.username ? "username/password" : null,
  ].filter(Boolean);
  if (configured.length > 1) {
    console.warn(
      `[agent] kubeconfig user '${user.name}' defines multiple credential forms ` +
        `(${configured.join(", ")}); priority order is exec > tokenFile > token > username/password.`,
    );
  }

  if (exec) {
    if (!exec.command) {
      // A startup error: thrown before the loader is even built, before the
      // tunnel is opened.
      throw new Error(`kubeconfig user '${user.name}' has no exec.command`);
    }
    return async () => {
      const startedAt = Date.now();
      const status = await runExecPlugin(exec, cluster);
      const elapsed = Date.now() - startedAt;

      // When `expirationTimestamp` is absent we apply a bounded window (see
      // EXEC_DEFAULT_TTL_MS). When present we use it with a margin; if a
      // timestamp in the past arrives, the cache is immediately considered stale
      // and the next request re-runs the plugin — that is the correct behaviour,
      // not an infinite loop, because a refresh is only triggered when a request
      // arrives.
      const expiresAt = status.expirationTimestamp
        ? Date.parse(status.expirationTimestamp)
        : Number.NaN;
      // The margin may not eat more than half of the remaining lifetime.
      // Otherwise a short-lived token (say 8 s) would always leave `validUntil`
      // in the past because of our margin, and the plugin would re-run **on
      // every request** — the very process storm we are trying to avoid. An
      // expired token is still never served: when the remaining lifetime is
      // ≤ 0 the margin is 0 too and the credential goes stale instantly.
      const remaining = expiresAt - Date.now();
      const margin = Math.min(EXEC_EXPIRY_MARGIN_MS, Math.max(0, remaining / 2));
      const validUntil = Number.isFinite(expiresAt)
        ? expiresAt - margin
        : Date.now() + EXEC_DEFAULT_TTL_MS;

      if (!status.token && !status.clientCertificateData) {
        // The same branch as its three siblings in `runExecPlugin`: the plugin
        // ran, its output parsed, but there is no identity inside.
        console.error(
          `[agent] credential plugin '${exec.command}' returned neither a token nor a client certificate`,
        );
        throw new AgentFailure({
          code: "AUTH_PLUGIN_BAD_OUTPUT",
          params: { command: exec.command, reason: "no-credential" },
        });
      }

      const headers: Record<string, string> = {};
      if (status.token) headers.authorization = `Bearer ${status.token}`;

      console.log(
        `[agent] exec credential plugin ran (${exec.command}, ${elapsed} ms) — ` +
          `${status.token ? "token" : "client certificate"}, expires ` +
          `${status.expirationTimestamp ?? "not reported"}`,
      );

      return {
        headers,
        clientCertPem: status.clientCertificateData,
        clientKeyPem: status.clientKeyData,
        validUntil,
        describe: `exec:${exec.command}`,
      };
    };
  }

  if (tokenFile) {
    return async () => {
      const token = (await readFile(tokenFile, "utf8")).trim();
      if (!token) {
        // An unreadable file is NOT a separate case: Node's `readFile` error is
        // wrapped into `CREDENTIAL_UNAVAILABLE` in `CredentialCache`. An empty
        // file gets its own code because it is silent: the read succeeded, there
        // is no identity.
        console.error(`[agent] tokenFile is empty: ${tokenFile}`);
        throw new AgentFailure({ code: "TOKEN_FILE_EMPTY", params: { path: tokenFile } });
      }
      // A token in a file carries no expiry of its own; the kubelet/projected
      // volume replaces it in place. client-go re-reads it on a fixed period for
      // the same reason.
      return {
        headers: { authorization: `Bearer ${token}` },
        validUntil: Date.now() + TOKEN_TTL_MS,
        describe: `tokenFile:${tokenFile}`,
      };
    };
  }

  if (user.token) {
    const headers = { authorization: `Bearer ${user.token}` };
    return async () => ({ headers, validUntil: Number.POSITIVE_INFINITY, describe: "token" });
  }

  if (user.username) {
    // The apiserver has not accepted basic auth since 1.19, but the kubeconfig
    // form is still valid and proxies placed in front of it (kube-oidc-proxy,
    // some managed control planes) do use it. Producing and sending the header
    // costs us nothing; not supporting it would mean a silent 401.
    const headers = { authorization: basicAuthHeader(user.username, user.password ?? "") };
    return async () => ({
      headers,
      validUntil: Number.POSITIVE_INFINITY,
      describe: "username/password",
    });
  }

  return null;
}

async function resolveKubeconfig(context?: string): Promise<KubeTarget> {
  const kc = new KubeConfig();
  kc.loadFromDefault();
  if (context) kc.setCurrentContext(context);

  const cluster = kc.getCurrentCluster();
  // A startup error: thrown before the tunnel exists, never reaches the wire.
  if (!cluster) throw new Error("no active cluster in kubeconfig");
  const user = kc.getCurrentUser();

  // We build the TLS material from the kubeconfig ourselves.
  const ca = await readPem(cluster.caData, cluster.caFile);
  const staticCert = await readPem(user?.certData, user?.certFile);
  const staticKey = await readPem(user?.keyData, user?.keyFile);

  const rawUser = user ? await readRawUserEntry(user.name) : undefined;
  const loader = user ? selectCredentialLoader(user, rawUser, cluster) : null;

  const buildDispatcher = (cert?: Buffer | string, key?: Buffer | string): Agent =>
    new Agent({
      connect: {
        ca,
        cert,
        key,
        rejectUnauthorized: !cluster.skipTLSVerify,
        servername: cluster.tlsServerName,
      },
    });

  let dispatcher = buildDispatcher(staticCert, staticKey);
  // The exec certificate currently installed on the dispatcher; when it changes
  // the dispatcher is rebuilt.
  let installedCertPem: string | undefined;
  let installedKeyPem: string | undefined;

  const cache = loader ? new CredentialCache(loader) : null;

  /**
   * If the `exec` plugin returned a client certificate instead of a token, the
   * identity has to be established at the TLS layer — meaning the dispatcher
   * must be recreated. This path never runs for plugins that return a token (the
   * common case: GKE, EKS).
   *
   * The old dispatcher is closed **gracefully** with `close()` and not awaited:
   * let the watch/log requests flowing over it run to their own end while new
   * requests go to the new one. With `destroy()` the open watches would be cut.
   */
  const syncDispatcher = (credential: KubeCredential): void => {
    if (!credential.clientCertPem && !credential.clientKeyPem) return;
    if (
      credential.clientCertPem === installedCertPem &&
      credential.clientKeyPem === installedKeyPem
    ) {
      return;
    }
    const previous = dispatcher;
    dispatcher = buildDispatcher(
      credential.clientCertPem ?? staticCert,
      credential.clientKeyPem ?? staticKey,
    );
    installedCertPem = credential.clientCertPem;
    installedKeyPem = credential.clientKeyPem;
    console.log("[agent] installed client certificate returned by the exec plugin");
    void previous.close().catch(() => {});
  };

  if (cache) {
    // We resolve once at startup: if the identity cannot be established at all
    // (missing plugin, unreadable tokenFile), let the agent fail here instead of
    // silently looking "connected". The apiserver **rejecting** the identity is a
    // different situation; that shows up at runtime as a 401 and the process
    // stays up.
    const initial = await cache.get();
    syncDispatcher(initial);
    console.log(`[agent] kubeconfig identity: ${initial.describe}`);
  } else {
    console.log(
      `[agent] kubeconfig identity: ${staticCert ? "client certificate (TLS)" : "no credential"}`,
    );
  }

  return {
    baseUrl: cluster.server,
    // A getter: an `exec` refresh can replace the dispatcher, so every read must
    // return the current one. Callers must read it AFTER awaiting
    // `authHeaders()` (see tunnel-client) — that is where the swap happens.
    get dispatcher(): Dispatcher {
      return dispatcher;
    },
    // The **same** material as the dispatcher: if the exec plugin returned a
    // certificate, that one applies here too; if it is static, the static one
    // does. Fed from separate sources, the two paths could silently connect with
    // different identities.
    tlsOptions: (): KubeTlsOptions => ({
      ...(ca ? { ca } : {}),
      ...(installedCertPem ?? staticCert ? { cert: installedCertPem ?? staticCert } : {}),
      ...(installedKeyPem ?? staticKey ? { key: installedKeyPem ?? staticKey } : {}),
      rejectUnauthorized: !cluster.skipTLSVerify,
      ...(cluster.tlsServerName ? { servername: cluster.tlsServerName } : {}),
    }),
    async authHeaders() {
      if (!cache) return {};
      const credential = await cache.get();
      syncDispatcher(credential);
      return credential.headers;
    },
    invalidateCredential(reason) {
      cache?.invalidate(reason);
    },
    async close() {
      await dispatcher.close();
    },
  };
}

export function resolveKubeTarget(config: AgentConfig): Promise<KubeTarget> {
  return config.kubeMode === "in-cluster"
    ? resolveInCluster()
    : resolveKubeconfig(config.kubeContext);
}

/** At startup the agent reads the apiserver version; the control plane shows it in the inventory. */
export async function readKubernetesVersion(target: KubeTarget): Promise<string | undefined> {
  try {
    const { request } = await import("undici");
    // The order matters: `authHeaders()` can replace the dispatcher during an
    // exec refresh, so the dispatcher is read AFTER it. Writing the
    // `dispatcher:` field first in the object literal would capture the old
    // dispatcher here.
    const headers = await target.authHeaders();
    const res = await request(`${target.baseUrl}/version`, {
      dispatcher: target.dispatcher,
      headers,
    });
    if (res.statusCode !== 200) {
      // A silent `undefined` was harmful at this point: in the control plane's
      // inventory the cluster looked "connected" but had no version, and the
      // reason was written nowhere.
      const detail = (await res.body.text()).trim().slice(0, 300);
      const hint =
        res.statusCode === 401
          ? " — apiserver did not accept our identity (invalid kubeconfig user / token?)"
          : res.statusCode === 403
            ? " — identity recognized but not authorized"
            : "";
      console.error(`[agent] apiserver /version ${res.statusCode}${hint}: ${detail}`);
      if (res.statusCode === 401) target.invalidateCredential("/version 401");
      return undefined;
    }
    const body = (await res.body.json()) as { gitVersion?: string };
    return body.gitVersion;
  } catch (err) {
    console.error(`[agent] could not read apiserver /version: ${(err as Error).message}`);
    return undefined;
  }
}
