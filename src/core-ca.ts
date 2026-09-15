/**
 * Loads and validates `YEKE_CORE_CA_FILE`: the certificate authority the agent
 * must trust IN ADDITION to the public roots bundled with Node.js, when core's
 * TLS certificate is signed by an organization's own CA rather than a publicly
 * trusted one.
 *
 * ─── Why this is a twin of core's `loadPublicCa`, not a shared package ───────
 *
 * `apps/core/src/http/public-ca.ts` (in the product monorepo) enforces the
 * same three rules on the same kind of file: the file must be readable, the
 * PEM must decode into at least one certificate, and at least one of those
 * certificates must be SELF-SIGNED (a root). This repository cannot import
 * that file — `boundary.test.ts` pins the agent's only YEKE dependency to the
 * tunnel wire contract — so the rule is re-implemented here, kept in sync by
 * hand, and each side's comment names the other. The same split-repository
 * pattern already exists for the shell preamble (`shell/protocol.ts` on the
 * core side, `apps/toolbox/bin/yeke-shell` on this one): a wire-adjacent rule
 * that cannot live in one file gets a paired comment in both.
 *
 * ─── Why a root is mandatory (measured, not assumed) ─────────────────────────
 *
 * Node's TLS client (which both this agent and the CLI use) will not anchor
 * trust on an intermediate certificate alone: handed only an intermediate, it
 * fails with `UNABLE_TO_GET_ISSUER_CERT` even though the intermediate's own
 * issuer (the root) may well be the thing the operator meant to trust. Go and
 * curl do not have this restriction, which is exactly why an operator's first
 * instinct — "export the chain nginx/my load balancer serves" — usually
 * produces a leaf+intermediate bundle that works everywhere except here. A
 * file with no self-signed certificate in it is therefore rejected at load
 * time, with a message that says so, rather than left to fail later at the TLS
 * handshake where the operator would see a generic verification error with no
 * file name attached to it.
 */
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";

/** The self-signed certificates found in the file — what the startup log names. */
export interface CoreCaRoot {
  readonly subject: string;
  readonly fingerprint256: string;
  readonly validTo: string;
}

export interface CoreCaBundle {
  /**
   * Every `CERTIFICATE` block in the file, in file order, each ending in
   * `\n`. Handed to `ws` as-is: `new WebSocket(url, { ca: [...tls.rootCertificates, ...bundle.ca] })`
   * (K2 in the architecture decision — an ADDITION to the default trust
   * store, never a replacement). Intermediates are harmless to include here
   * and can help Node assemble the chain, so they are kept rather than
   * filtered out; only `roots` below is restricted to self-signed entries.
   */
  readonly ca: readonly string[];
  /** The self-signed (root) certificates among `ca`, for the startup log. */
  readonly roots: readonly CoreCaRoot[];
}

export type CoreCaErrorCode =
  | "CORE_CA_FILE_UNREADABLE"
  | "CORE_CA_PEM_INVALID"
  | "CORE_CA_NO_ROOT"
  | "CORE_CA_EXPIRED";

/**
 * Thrown by `loadCoreCa`. English and ASCII, like every error this repository
 * throws at startup (`config.ts`'s `required()`): its reader is the operator
 * running `kubectl logs yeke-agent`, and `main()` (`index.ts`) prefixes it
 * with `[agent] failed to start: ` and brings the process down.
 */
export class CoreCaError extends Error {
  readonly code: CoreCaErrorCode;

  constructor(code: CoreCaErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "CoreCaError";
  }
}

const CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

/** A root: issued by itself, and its own signature verifies against its own key. */
function isSelfSigned(cert: X509Certificate): boolean {
  try {
    return cert.checkIssued(cert) && cert.verify(cert.publicKey);
  } catch {
    // `verify()` throws on a malformed key rather than returning false; such a
    // certificate is not usable as a root either way.
    return false;
  }
}

/**
 * Reads and validates `file` (the value of `YEKE_CORE_CA_FILE`).
 *
 * `now` is a seam for the expiry check, the same pattern `serviceAccountToken`
 * uses in `kube.ts` — a real clock by default, an injected one in tests, never
 * a frozen fixture (a certificate fixture carrying a fixed date is a clock
 * bomb: the test starts failing the day the fixture expires for real).
 */
export function loadCoreCa(file: string, now: () => number = Date.now): CoreCaBundle {
  let text: string;
  try {
    text = readFileSync(file, "utf8");
  } catch (err) {
    throw new CoreCaError(
      "CORE_CA_FILE_UNREADABLE",
      `YEKE_CORE_CA_FILE could not be read: ${file} (${(err as Error).message})`,
    );
  }

  const blocks = text.match(CERT_BLOCK) ?? [];
  if (blocks.length === 0) {
    throw new CoreCaError(
      "CORE_CA_PEM_INVALID",
      `YEKE_CORE_CA_FILE contains no CERTIFICATE block: ${file}`,
    );
  }

  const certificates: X509Certificate[] = [];
  for (const block of blocks) {
    try {
      certificates.push(new X509Certificate(block));
    } catch (err) {
      throw new CoreCaError(
        "CORE_CA_PEM_INVALID",
        `YEKE_CORE_CA_FILE contains a certificate that could not be parsed: ${file} (${(err as Error).message})`,
      );
    }
  }

  const roots = certificates.filter(isSelfSigned);
  if (roots.length === 0) {
    throw new CoreCaError(
      "CORE_CA_NO_ROOT",
      `YEKE_CORE_CA_FILE has no self-signed root certificate: ${file} — Node.js clients (agent, CLI) ` +
        "cannot anchor trust on an intermediate; add the root certificate to the file.",
    );
  }

  const nowMs = now();
  for (const cert of certificates) {
    const validTo = Date.parse(cert.validTo);
    if (Number.isFinite(validTo) && validTo < nowMs) {
      throw new CoreCaError(
        "CORE_CA_EXPIRED",
        `YEKE_CORE_CA_FILE contains an expired certificate: ${file} — ${cert.subject} valid until ${cert.validTo}`,
      );
    }
  }

  return {
    // Normalized so every element ends in exactly one newline: a file edited
    // by hand (or templated by a ConfigMap) commonly loses or duplicates the
    // trailing newline of the last block, and `ws`/`tls` tolerate both, but
    // normalizing here means a test comparing `ca` against the source text
    // does not have to special-case the last element.
    ca: blocks.map((block) => `${block.trim()}\n`),
    roots: roots.map((cert) => ({
      subject: cert.subject,
      fingerprint256: cert.fingerprint256,
      validTo: cert.validTo,
    })),
  };
}

/**
 * The startup log line: `[agent] core CA: 1 root(s) from /etc/yeke/core-ca/ca.crt; CN=… sha256:… valid until …`.
 *
 * Written once, when the CA is first loaded successfully (see
 * `TunnelClient.#connect`) — not on every reconnect's re-read, which would
 * turn a routine keepalive cycle into a log line every `reconnectMinMs`.
 */
export function describeCoreCa(file: string, bundle: CoreCaBundle): string {
  const roots = bundle.roots
    .map((root) => `${root.subject.replace(/\n/g, ", ")} sha256:${root.fingerprint256} valid until ${root.validTo}`)
    .join("; ");
  return `[agent] core CA: ${bundle.roots.length} root(s) from ${file}; ${roots}`;
}
