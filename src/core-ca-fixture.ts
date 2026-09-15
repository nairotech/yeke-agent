/**
 * A root → intermediate → leaf certificate chain, generated with `openssl` at
 * test time.
 *
 * `metrics/fixture.ts` already builds CA+leaf pairs for the collector's TLS
 * tests, and for the same reason given there — no private key belongs in a
 * public repository, generating costs about a second and removes the
 * question — but that shape is not enough for this file's callers
 * (`core-ca.test.ts`, `tunnel-client.test.ts`). The architecture decision this
 * repository implements (`docs/architecture/2026-09-15-yeke-kurum-ca-guveni.md`,
 * measurement 5 in its baseline) turns on a THREE-certificate chain
 * specifically: Node.js clients refuse to anchor trust on an intermediate
 * alone, and a server that presents only a leaf can never exercise that rule.
 * This fixture produces a server chain of leaf+intermediate (no root — the
 * shape a reverse proxy or native TLS setup typically serves) so a test can
 * hand the agent the root ALONE and prove the chain still verifies.
 */
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

export { opensslAvailable } from "./metrics/fixture.js";

const run = promisify(execFile);

export interface ChainTlsFixture {
  readonly rootCert: Buffer;
  readonly rootKey: Buffer;
  readonly intermediateCert: Buffer;
  readonly intermediateKey: Buffer;
  readonly leafCert: Buffer;
  readonly leafKey: Buffer;
  /** leaf + intermediate, concatenated PEM — what the test HTTPS server presents; no root. */
  readonly serverChainPem: Buffer;
}

/**
 * Builds one independent root/intermediate/leaf chain under `directory`.
 *
 * `commonName` lets a test build TWO unrelated chains (a "right" one and a
 * "wrong" one) without their subjects colliding; the leaf's subject is always
 * `127.0.0.1` because that is the address every test server in this
 * repository binds to, and the SAN has to match it for Node's TLS client to
 * accept the certificate at all — a rule the collector's own fixture
 * (`metrics/fixture.ts`) already depends on.
 *
 * `intermediateDays` (default 3650, same as the root) exists for exactly one
 * caller: `core-ca.test.ts`'s K16 case "an expired intermediate is skipped
 * while a valid root is kept". The root and intermediate are otherwise
 * generated moments apart with the same `-days`, so their `validTo` values
 * are only milliseconds apart — not a usable window for an injected `now`
 * that must land after one and before the other. A short `intermediateDays`
 * opens that window to whatever size the test needs.
 */
export async function createChainTlsFixture(
  directory: string,
  options: { readonly commonName?: string; readonly intermediateDays?: number } = {},
): Promise<ChainTlsFixture> {
  const cn = options.commonName ?? "yeke-test";
  const path = (name: string): string => join(directory, name);

  await writeFile(
    path("intermediate.cnf"),
    "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n",
    "utf8",
  );
  await writeFile(
    path("leaf.cnf"),
    "basicConstraints=critical,CA:FALSE\n" +
      "keyUsage=critical,digitalSignature,keyEncipherment\n" +
      "extendedKeyUsage=serverAuth\n" +
      "subjectAltName=IP:127.0.0.1\n",
    "utf8",
  );

  // Root: self-signed, CA:TRUE — the certificate `loadCoreCa`'s root check
  // (`checkIssued(self) && verify(self.publicKey)`) must accept.
  await run("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", path("root.key"), "-out", path("root.crt"),
    "-days", "3650", "-subj", `/CN=${cn}-root`,
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ]);

  // Intermediate: signed BY the root, itself CA:TRUE (pathlen 0 — it may only
  // sign leaves, matching a real corporate PKI's issuing CA).
  await run("openssl", [
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", path("intermediate.key"), "-out", path("intermediate.csr"),
    "-subj", `/CN=${cn}-intermediate`,
  ]);
  await run("openssl", [
    "x509", "-req", "-in", path("intermediate.csr"),
    "-CA", path("root.crt"), "-CAkey", path("root.key"), "-CAcreateserial",
    "-out", path("intermediate.crt"), "-days", String(options.intermediateDays ?? 3650),
    "-extfile", path("intermediate.cnf"),
  ]);

  // Leaf: signed BY the intermediate — never by the root directly, so a test
  // that hands the agent only the intermediate (the `CORE_CA_NO_ROOT` case)
  // is handing it something that cannot verify this leaf on its own either.
  await run("openssl", [
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", path("leaf.key"), "-out", path("leaf.csr"),
    "-subj", "/CN=127.0.0.1",
  ]);
  await run("openssl", [
    "x509", "-req", "-in", path("leaf.csr"),
    "-CA", path("intermediate.crt"), "-CAkey", path("intermediate.key"), "-CAcreateserial",
    "-out", path("leaf.crt"), "-days", "3650",
    "-extfile", path("leaf.cnf"),
  ]);

  const [rootCert, rootKey, intermediateCert, intermediateKey, leafCert, leafKey] = await Promise.all([
    readFile(path("root.crt")),
    readFile(path("root.key")),
    readFile(path("intermediate.crt")),
    readFile(path("intermediate.key")),
    readFile(path("leaf.crt")),
    readFile(path("leaf.key")),
  ]);

  return {
    rootCert,
    rootKey,
    intermediateCert,
    intermediateKey,
    leafCert,
    leafKey,
    // Leaf first: the order `https.createServer({ cert })` and every real
    // "fullchain.pem" expect — the subject's own certificate first, then the
    // certificates that vouch for it, root last (and the root is omitted
    // here entirely, on purpose — see the file header).
    serverChainPem: Buffer.concat([leafCert, intermediateCert]),
  };
}

/**
 * A single self-signed root certificate with a caller-chosen validity
 * window, unrelated to any chain `createChainTlsFixture` builds.
 *
 * Exists for K16's "a valid root alongside an expired root" case in
 * `core-ca.test.ts`: that test needs TWO independent roots with two
 * DIFFERENT expiry times so a single injected `now` can land after one's
 * `validTo` and before the other's. `createChainTlsFixture`'s own root is
 * always long-lived (3650 days) and tied to an intermediate and leaf this
 * caller does not need.
 */
export async function createRootCert(
  directory: string,
  options: { readonly commonName?: string; readonly days?: number } = {},
): Promise<Buffer> {
  const cn = options.commonName ?? "yeke-test-root";
  const certPath = join(directory, `${cn}.crt`);
  await run("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", join(directory, `${cn}.key`), "-out", certPath,
    "-days", String(options.days ?? 3650),
    "-subj", `/CN=${cn}`,
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  return readFile(certPath);
}

/**
 * A self-signed root certificate that is ALREADY expired on the real clock,
 * generated with openssl's absolute `-not_before`/`-not_after` dates rather
 * than a `-days` offset — so it stays expired forever, rather than expiring
 * "eventually" the way a short `-days` fixture would (itself a clock bomb on
 * any run more than that many days after generation).
 *
 * Used only by `tunnel-client.test.ts`'s K16 integration test. `core-ca.ts`'s
 * own unit tests use the injectable `now` seam on `loadCoreCa` instead (see
 * `core-ca.test.ts`) and never need an actually-expired certificate — but
 * `TunnelClient` has no `now` seam of its own (`#loadCoreCaForConnect` calls
 * `loadCoreCa(file)` with no override, deliberately: production has no
 * business injecting a clock), so the only way to exercise "an
 * already-expired certificate in the file" at that layer is a certificate
 * that really is expired.
 */
export async function createExpiredRootCert(
  directory: string,
  options: { readonly commonName?: string } = {},
): Promise<Buffer> {
  const cn = options.commonName ?? "yeke-test-expired-root";
  const certPath = join(directory, `${cn}.crt`);
  await run("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", join(directory, `${cn}.key`), "-out", certPath,
    "-subj", `/CN=${cn}`,
    "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    // A fixed window in 2020: definitely expired, and will stay that way.
    "-not_before", "20200101000000Z",
    "-not_after", "20200102000000Z",
  ]);
  return readFile(certPath);
}
