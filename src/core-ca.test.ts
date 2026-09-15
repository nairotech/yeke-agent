/**
 * The twin of core's `public-ca.test.ts` (architecture decision, §7.1/§7.3):
 * measures the same three rules (readability, PEM validity, the root
 * requirement) against THIS repository's `loadCoreCa`. The two repositories
 * cannot share code (`boundary.test.ts` pins the agent's only YEKE
 * dependency to the tunnel contract), so the rule is implemented twice and
 * has to be measured twice — this file is that second measurement.
 *
 * The expiry rule is where the two files deliberately DIVERGE (K16,
 * architecture decision §3.16, "P6 düzeltmesi"): core's `loadPublicCa`
 * refuses to start over an expired certificate; this repository's
 * `loadCoreCa` skips one with a warning and only fails (`CORE_CA_NO_ROOT`)
 * if no valid root survives the filtering — see the "K16" section of
 * `core-ca.ts`'s own file header for why. The tests below measure THIS
 * file's rule, not core's.
 *
 * Certificate fixtures are generated with `openssl` at test time (root →
 * intermediate → leaf); a fixture with a fixed date would be a clock bomb —
 * it really does expire one day. When `openssl` is missing the tests FAIL and
 * say so BY NAME, the same rule `metrics/kubelet-client.test.ts` follows. The
 * one exception is `createExpiredRootCert` (K16's "only an expired root" and
 * "valid + expired root" cases use the `now` seam instead, precisely to
 * avoid a fixture that is only accidentally still expired) — see
 * `core-ca-fixture.ts`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { CoreCaError, defaultCoreCaCertificates, describeCoreCa, loadCoreCa } from "./core-ca.js";
import {
  type ChainTlsFixture,
  createChainTlsFixture,
  createRootCert,
  opensslAvailable,
} from "./core-ca-fixture.js";

const run = promisify(execFile);

let cached: { fixture: ChainTlsFixture; directory: string } | undefined;

async function chain(): Promise<ChainTlsFixture> {
  if (cached) return cached.fixture;
  assert.ok(
    await opensslAvailable(),
    "NOT MEASURED: openssl is not on PATH, so the CA-loading claims of the agent were not checked " +
      "on this machine. Install openssl and run the gate again.",
  );
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  cached = { fixture: await createChainTlsFixture(directory, { commonName: "core-ca-test" }), directory };
  return cached.fixture;
}

async function withFile(directory: string, name: string, content: Buffer | string): Promise<string> {
  const path = join(directory, name);
  await writeFile(path, content);
  return path;
}

test("a missing file is CORE_CA_FILE_UNREADABLE and names the path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const missing = join(directory, "does-not-exist.crt");
    assert.throws(
      () => loadCoreCa(missing),
      (err: unknown) => {
        assert.ok(err instanceof CoreCaError);
        assert.equal(err.code, "CORE_CA_FILE_UNREADABLE");
        assert.ok(err.message.includes(missing), "the message must name the unreadable path");
        return true;
      },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a file with no CERTIFICATE block is CORE_CA_PEM_INVALID", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const file = await withFile(directory, "garbage.crt", "this is not a certificate\n");
    assert.throws(
      () => loadCoreCa(file),
      (err: unknown) => {
        assert.ok(err instanceof CoreCaError);
        assert.equal(err.code, "CORE_CA_PEM_INVALID");
        return true;
      },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("an unparseable CERTIFICATE block is CORE_CA_PEM_INVALID", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const file = await withFile(
      directory,
      "corrupt.crt",
      "-----BEGIN CERTIFICATE-----\nbm90IHJlYWxseSBhIGNlcnRpZmljYXRl\n-----END CERTIFICATE-----\n",
    );
    assert.throws(
      () => loadCoreCa(file),
      (err: unknown) => {
        assert.ok(err instanceof CoreCaError);
        assert.equal(err.code, "CORE_CA_PEM_INVALID");
        return true;
      },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("NEGATIVE PROBE: an intermediate alone (no self-signed certificate) is CORE_CA_NO_ROOT", async () => {
  const fixture = await chain();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    // This is exactly the file an operator produces by exporting "the chain
    // my reverse proxy serves" — leaf+intermediate, no root — and it must be
    // rejected with a message that tells them what is missing.
    const file = await withFile(directory, "intermediate-only.crt", fixture.intermediateCert);
    assert.throws(
      () => loadCoreCa(file),
      (err: unknown) => {
        assert.ok(err instanceof CoreCaError);
        assert.equal(err.code, "CORE_CA_NO_ROOT");
        assert.match(err.message, /intermediate/);
        return true;
      },
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("root + intermediate: both blocks are kept in `ca`, exactly the root is in `roots`, and the fingerprint matches openssl's", async () => {
  const fixture = await chain();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const file = await withFile(
      directory,
      "root-and-intermediate.crt",
      Buffer.concat([fixture.rootCert, fixture.intermediateCert]),
    );
    const bundle = loadCoreCa(file);
    assert.equal(bundle.ca.length, 2, "both PEM blocks are carried through, intermediate included");
    assert.equal(bundle.roots.length, 1);

    const { stdout } = await run("openssl", ["x509", "-in", join(directory, "root-and-intermediate.crt"), "-fingerprint", "-sha256", "-noout"]);
    const opensslFingerprint = stdout.trim().split("=")[1];
    assert.equal(bundle.roots[0]?.fingerprint256, opensslFingerprint);

    const rootCert = new X509Certificate(fixture.rootCert);
    assert.equal(bundle.roots[0]?.subject, rootCert.subject);
    assert.equal(bundle.roots[0]?.validTo, rootCert.validTo);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("K16: only an expired root is CORE_CA_NO_ROOT and names the all-roots-expired case (the `now` seam, not a stale fixture)", async () => {
  const fixture = await chain();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const file = await withFile(directory, "root.crt", fixture.rootCert);
    const rootCert = new X509Certificate(fixture.rootCert);
    const afterExpiry = () => Date.parse(rootCert.validTo) + 1_000;
    assert.throws(
      () => loadCoreCa(file, afterExpiry),
      (err: unknown) => {
        assert.ok(err instanceof CoreCaError);
        // Not CORE_CA_EXPIRED (that code no longer exists, K16): the root is
        // SKIPPED, and what remains to report is that none is left.
        assert.equal(err.code, "CORE_CA_NO_ROOT");
        assert.match(err.message, /all roots expired/);
        return true;
      },
    );
    // The same file, read with today's real seam, still passes — the fixture
    // is not actually expired; only the injected clock says so.
    assert.doesNotThrow(() => loadCoreCa(file));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("K16: a valid root alongside an expired root — only the valid one survives, and the skip is warned exactly once", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const shortLived = await createRootCert(directory, { commonName: "core-ca-test-short", days: 1 });
    const longLived = await createRootCert(directory, { commonName: "core-ca-test-long", days: 3650 });
    const file = await withFile(directory, "mixed.crt", Buffer.concat([shortLived, longLived]));

    const shortCert = new X509Certificate(shortLived);
    const longCert = new X509Certificate(longLived);
    const afterShortExpiry = () => Date.parse(shortCert.validTo) + 1_000;
    // Sanity on the fixture itself: the long-lived root must still be valid
    // at the moment the test injects, or the test would not be measuring
    // what its name says.
    assert.ok(Date.parse(longCert.validTo) > afterShortExpiry());

    const originalWarn = console.warn;
    const warnLines: string[] = [];
    console.warn = (...args: unknown[]) => void warnLines.push(args.join(" "));
    let bundle;
    try {
      bundle = loadCoreCa(file, afterShortExpiry);
    } finally {
      console.warn = originalWarn;
    }

    assert.equal(bundle.roots.length, 1, "the expired root must not appear in `roots`");
    assert.equal(bundle.ca.length, 1, "the expired root's PEM block must not appear in `ca` either");
    assert.equal(bundle.roots[0]?.fingerprint256, longCert.fingerprint256);
    assert.equal(
      warnLines.filter((line) => line.includes("skipping expired certificate")).length,
      1,
      `expected exactly one skip warning:\n${JSON.stringify(warnLines, null, 2)}`,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("K16: an expired intermediate is skipped while a valid root is kept", async () => {
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-mixed-"));
  try {
    // A dedicated chain, not the shared `chain()` fixture: this is the one
    // caller that needs the root and intermediate to expire at DIFFERENT
    // times (see `createChainTlsFixture`'s `intermediateDays` doc).
    const fixture = await createChainTlsFixture(directory, {
      commonName: "core-ca-test-mixed",
      intermediateDays: 1,
    });
    const file = await withFile(
      directory,
      "root-and-expiring-intermediate.crt",
      Buffer.concat([fixture.rootCert, fixture.intermediateCert]),
    );
    const intermediateCert = new X509Certificate(fixture.intermediateCert);
    const rootCert = new X509Certificate(fixture.rootCert);
    const afterIntermediateExpiry = () => Date.parse(intermediateCert.validTo) + 1_000;
    assert.ok(
      Date.parse(rootCert.validTo) > afterIntermediateExpiry(),
      "the root must still be valid at the moment the intermediate expires",
    );

    const bundle = loadCoreCa(file, afterIntermediateExpiry);
    assert.equal(bundle.ca.length, 1, "only the still-valid root block remains; the expired intermediate is dropped");
    assert.equal(bundle.roots.length, 1);
    assert.equal(bundle.roots[0]?.fingerprint256, rootCert.fingerprint256);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("loadCoreCa dedupes a repeated root certificate by fingerprint (independent finding, 15.09.2026): the SAME block twice counts once in both `ca` and `roots`", async () => {
  const fixture = await chain();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    // The exact same PEM block, twice — the shape an operator's ConfigMap
    // edit or a rotation that concatenates two files can easily produce.
    // `hello.coreCaRoots` (K15) counts `roots.length` against a 16-item wire
    // limit, so a duplicate must count once, not once per copy.
    const file = await withFile(directory, "duplicated-root.crt", Buffer.concat([fixture.rootCert, fixture.rootCert]));
    const bundle = loadCoreCa(file);
    assert.equal(bundle.roots.length, 1, "a repeated root must count once, not twice");
    assert.equal(bundle.ca.length, 1, "its PEM block must appear once in `ca` too");
    const rootCert = new X509Certificate(fixture.rootCert);
    assert.equal(bundle.roots[0]?.fingerprint256, rootCert.fingerprint256);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("root alone is accepted (K1b: only the root is required, an intermediate helps but is optional)", async () => {
  const fixture = await chain();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const file = await withFile(directory, "root-only.crt", fixture.rootCert);
    const bundle = loadCoreCa(file);
    assert.equal(bundle.ca.length, 1);
    assert.equal(bundle.roots.length, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("describeCoreCa names the file, the root count and the fingerprint", async () => {
  const fixture = await chain();
  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-core-ca-"));
  try {
    const file = await withFile(directory, "root.crt", fixture.rootCert);
    const bundle = loadCoreCa(file);
    const line = describeCoreCa(file, bundle);
    assert.match(line, /^\[agent\] core CA: 1 root\(s\) from /);
    assert.ok(line.includes(file));
    assert.ok(line.includes(bundle.roots[0]!.fingerprint256));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("defaultCoreCaCertificates returns a non-empty list in this process (the bundled roots at minimum)", () => {
  const list = defaultCoreCaCertificates();
  assert.ok(list.length > 0);
  assert.ok(list.every((pem) => pem.includes("BEGIN CERTIFICATE")));
});

/**
 * Independent finding, 15.09.2026: `tls.rootCertificates` (this file's old
 * base for the `ca` union, before this change) is ONLY the roots bundled
 * with the running Node build — it does not see `NODE_EXTRA_CA_CERTS` or a
 * `--use-system-ca` Node build's system store. `NODE_EXTRA_CA_CERTS` is read
 * once, at process startup, so this can only be measured in a SEPARATE
 * process started with the variable already set — the same pattern
 * `apps/cli/src/ca.test.ts`'s equivalent measurement uses in the product
 * monorepo (`resolveCaList` there, `defaultCoreCaCertificates` here).
 */
test("defaultCoreCaCertificates includes the operator's NODE_EXTRA_CA_CERTS root, not only the bundled set", async () => {
  assert.ok(
    await opensslAvailable(),
    "NOT MEASURED: openssl is not on PATH, so this finding was not checked on this machine. Install openssl and run the gate again.",
  );

  const directory = await mkdtemp(join(tmpdir(), "yeke-agent-extra-ca-"));
  try {
    const extraRoot = await createRootCert(directory, { commonName: "extra-default-root" });
    const extraRootFile = join(directory, "extra-default-root.crt");
    await writeFile(extraRootFile, extraRoot);

    const script =
      'import { defaultCoreCaCertificates } from "./src/core-ca.ts";' +
      'const norm = (pem) => pem.replace(/\\s+/g, "");' +
      "const list = defaultCoreCaCertificates();" +
      'process.stdout.write(String(list.some((pem) => norm(pem) === norm(process.env.EXTRA_PEM))));';

    const projectRoot = join(import.meta.dirname, "..");
    const out = execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
      cwd: projectRoot,
      env: {
        ...process.env,
        // Read only at startup: must already be set before this child's own
        // Node begins, which is exactly why this cannot be measured in-process.
        NODE_EXTRA_CA_CERTS: extraRootFile,
        EXTRA_PEM: extraRoot.toString("utf8"),
      },
      encoding: "utf8",
    });
    assert.equal(
      out.trim(),
      "true",
      "defaultCoreCaCertificates() must include the NODE_EXTRA_CA_CERTS root, not only the Node-bundled set",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
