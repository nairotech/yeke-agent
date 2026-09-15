/**
 * Loads and validates `YEKE_CORE_CA_FILE`: the certificate authority the agent
 * must trust IN ADDITION to whatever this Node process already trusts by
 * default (see `defaultCoreCaCertificates` below — not just the roots
 * bundled with Node.js), when core's TLS certificate is signed by an
 * organization's own CA rather than a publicly trusted one.
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
 *
 * ─── K16: an expired certificate is SKIPPED here, not rejected ───────────────
 *
 * Core's `loadPublicCa` (this file's twin) brings the process down over an
 * expired certificate, and that is right for it: the file is the operator's
 * own, edited by hand, and the person who can fix it is right there at
 * startup. This file's rule is deliberately looser, for a reason specific to
 * WHO owns the file on this side: the agent does not own `YEKE_CORE_CA_FILE`,
 * it is a `ConfigMap` YEKE itself manages, and the rotation procedure this
 * repository supports (architecture decision, §3.10) leaves the OLD root in
 * that file for a while on purpose, as the safe transition state, before an
 * operator removes it in a later step. That old root expiring one day is
 * therefore a NORMAL event, not an incident — and until this rule changed,
 * it was a ticking time bomb: the running pod kept working, but the next time
 * it restarted for any unrelated reason (a node drain, an OOM kill, a
 * kubectl rollout) the agent refused to start at all, over a certificate
 * nothing downstream was still relying on. So here, an expired certificate
 * (root or intermediate) is skipped with a warning instead — `ca` only ever
 * carries certificates that are still valid, and `roots` only ever reports
 * roots that are still valid, so a caller cannot end up trusting or
 * publishing (`hello.coreCaRoots`, K15) a fingerprint that cannot verify
 * anything. `CORE_CA_NO_ROOT` still fires if, after expired certificates are
 * removed, no valid root is left — the message says which of the two ways
 * that happened (never had one, or all of them expired) since the operator's
 * fix differs: add a root vs. add a NEW root before the old one disappears.
 */
import { readFileSync } from "node:fs";
import { X509Certificate } from "node:crypto";
import * as tls from "node:tls";

/** The self-signed certificates found in the file — what the startup log names. */
export interface CoreCaRoot {
  readonly subject: string;
  readonly fingerprint256: string;
  readonly validTo: string;
}

export interface CoreCaBundle {
  /**
   * Every still-VALID, DISTINCT `CERTIFICATE` block in the file, in file
   * order, each ending in `\n`. Handed to `ws` as-is: `new WebSocket(url, { ca: [...defaultCoreCaCertificates(), ...bundle.ca] })`
   * (K2 in the architecture decision — an ADDITION to the default trust
   * store, never a replacement — see `defaultCoreCaCertificates` below for
   * why that base set is not simply `tls.rootCertificates`). Intermediates
   * are harmless to include here and can help Node assemble the chain, so
   * they are kept rather than filtered out; only `roots` below is restricted
   * to self-signed entries.
   * An EXPIRED block (root or intermediate) never reaches this array — see
   * "K16" in the file header — so a caller never has to filter it out again.
   * A block that is byte-identical to an EARLIER one (same fingerprint) is
   * also dropped here, keeping only the first occurrence — independent
   * finding, 15.09.2026: a ConfigMap edit or a rotation that concatenates
   * two files can easily produce the same certificate twice, and a caller
   * counting `roots.length` against a wire limit (K15's `hello.coreCaRoots`,
   * capped at 16) must count DISTINCT roots, not PEM blocks.
   */
  readonly ca: readonly string[];
  /** The self-signed (root) certificates among `ca`, for the startup log and for `hello.coreCaRoots` (K15). Only valid, deduplicated (unexpired, distinct-by-fingerprint) roots — see "K16" and the `ca` doc above. */
  readonly roots: readonly CoreCaRoot[];
}

export type CoreCaErrorCode = "CORE_CA_FILE_UNREADABLE" | "CORE_CA_PEM_INVALID" | "CORE_CA_NO_ROOT";

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
 * The set of certificates this Node process trusts by default — what
 * `tunnel-client.ts` builds `ca: [...defaultCoreCaCertificates(), ...bundle.ca]`
 * on top of, per K2 (an ADDITION to the default trust store, never a
 * replacement).
 *
 * NOT `tls.rootCertificates`: that constant is only the roots bundled with
 * this particular Node build (the same fixed Mozilla list every Node ships),
 * while `ca` is a TLS option that, the moment it is set AT ALL, replaces the
 * running process's actual default trust store rather than adding to it. So
 * building the corporate-CA addition on top of `rootCertificates` was itself
 * silently discarding two things an operator may already be relying on: a
 * `NODE_EXTRA_CA_CERTS` root (a corporate TLS-inspecting proxy's CA, most
 * commonly) and a Node binary built with `--use-system-ca` — verified
 * independently, 15.09.2026: a request that succeeded with only
 * `NODE_EXTRA_CA_CERTS` set failed with `SELF_SIGNED_CERT_IN_CHAIN` the
 * moment `YEKE_CORE_CA_FILE` was also configured, because `ca` had quietly
 * dropped the extra root instead of joining it.
 *
 * `tls.getCACertificates("default")` (Node 22.15 / 23.10+) is the ACTUAL
 * running set: bundled roots plus every extra source Node itself already
 * merged in. Building on that instead makes this option's own "addition,
 * never a replacement" promise hold at its outer edge too, not only for the
 * one corporate CA this file adds. A Node build without `getCACertificates`
 * falls back to the bundled set — the same limitation those older builds
 * already had before this fix, not a new one.
 */
export function defaultCoreCaCertificates(): readonly string[] {
  return typeof tls.getCACertificates === "function" ? tls.getCACertificates("default") : tls.rootCertificates;
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

  // K16: an expired certificate (root or intermediate) is dropped here,
  // BEFORE the root check below — not rejected. The agent does not own this
  // file (see the file header); a root going stale in a `ConfigMap` it did
  // not put there is an expected step of the rotation procedure, not an
  // operator's mistake for it to report and refuse to start over. Filtering
  // first, then checking for a surviving root, is what makes "an expired
  // root, alone in the file" and "an expired root next to a valid one"
  // resolve differently without duplicating the self-signed check.
  const nowMs = now();
  const validBlocks: string[] = [];
  const validCertificates: X509Certificate[] = [];
  for (const [index, cert] of certificates.entries()) {
    const validTo = Date.parse(cert.validTo);
    if (Number.isFinite(validTo) && validTo < nowMs) {
      // English/ASCII, like every line this repository logs (see the header):
      // its reader is the operator running `kubectl logs yeke-agent`, and this
      // is the one piece of the rotation procedure (architecture decision
      // §3.10) that is otherwise invisible — the old root is still in the
      // ConfigMap, still being read every reconnect, and now silently inert.
      console.warn(
        `[agent] core CA: skipping expired certificate ${cert.subject.replace(/\n/g, ", ")} valid until ${cert.validTo}`,
      );
      continue;
    }
    validBlocks.push(blocks[index]!);
    validCertificates.push(cert);
  }

  // Independent finding, 15.09.2026: dedupe the still-valid certificates by
  // fingerprint, keeping the FIRST occurrence — see `CoreCaBundle.ca`'s own
  // doc for why a repeated PEM block must count once, not once per copy.
  const seenFingerprints = new Set<string>();
  const dedupedBlocks: string[] = [];
  const dedupedCertificates: X509Certificate[] = [];
  for (const [index, cert] of validCertificates.entries()) {
    if (seenFingerprints.has(cert.fingerprint256)) continue;
    seenFingerprints.add(cert.fingerprint256);
    dedupedBlocks.push(validBlocks[index]!);
    dedupedCertificates.push(cert);
  }

  const roots = dedupedCertificates.filter(isSelfSigned);
  if (roots.length === 0) {
    // Which of the two ways there is no usable root matters to the operator's
    // fix: a file that never had one needs a root added; a file whose only
    // root(s) just expired needs a NEW root added before the old one is
    // removed (the rotation order this repository documents), not the same
    // root re-added — it would parse fine and still be just as expired.
    const hadAnyRoot = certificates.some(isSelfSigned);
    if (hadAnyRoot) {
      throw new CoreCaError(
        "CORE_CA_NO_ROOT",
        `YEKE_CORE_CA_FILE has no valid root certificate left: ${file} — all roots expired; add a new, ` +
          "unexpired root to the file (the rotation procedure keeps the old one in place until the new " +
          "one is confirmed working, then removes it — never the other way around).",
      );
    }
    throw new CoreCaError(
      "CORE_CA_NO_ROOT",
      `YEKE_CORE_CA_FILE has no self-signed root certificate: ${file} — Node.js clients (agent, CLI) ` +
        "cannot anchor trust on an intermediate; add the root certificate to the file.",
    );
  }

  return {
    // Normalized so every element ends in exactly one newline: a file edited
    // by hand (or templated by a ConfigMap) commonly loses or duplicates the
    // trailing newline of the last block, and `ws`/`tls` tolerate both, but
    // normalizing here means a test comparing `ca` against the source text
    // does not have to special-case the last element.
    ca: dedupedBlocks.map((block) => `${block.trim()}\n`),
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
 * Printed by `TunnelClient.#loadCoreCaForConnect` whenever the loaded root
 * SET changes — the first successful load, and again only if a later
 * reconnect's re-read turns up a different set (rotation, §3.10) — not on
 * every reconnect's re-read, which would turn a routine keepalive cycle
 * into a log line every `reconnectMinMs`.
 */
export function describeCoreCa(file: string, bundle: CoreCaBundle): string {
  const roots = bundle.roots
    .map((root) => `${root.subject.replace(/\n/g, ", ")} sha256:${root.fingerprint256} valid until ${root.validTo}`)
    .join("; ");
  return `[agent] core CA: ${bundle.roots.length} root(s) from ${file}; ${roots}`;
}
