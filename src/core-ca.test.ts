/**
 * The twin of core's `public-ca.test.ts` (architecture decision, §7.1/§7.3):
 * measures the same three rules (readability, PEM validity, the root
 * requirement) and the expiry check that core's `loadPublicCa` enforces,
 * against THIS repository's `loadCoreCa`. The two repositories cannot share
 * code (`boundary.test.ts` pins the agent's only YEKE dependency to the
 * tunnel contract), so the rule is implemented twice and has to be measured
 * twice — this file is that second measurement.
 *
 * Certificate fixtures are generated with `openssl` at test time (root →
 * intermediate → leaf); a fixture with a fixed date would be a clock bomb —
 * it really does expire one day. When `openssl` is missing the tests FAIL and
 * say so BY NAME, the same rule `metrics/kubelet-client.test.ts` follows.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { CoreCaError, describeCoreCa, loadCoreCa } from "./core-ca.js";
import { type ChainTlsFixture, createChainTlsFixture, opensslAvailable } from "./core-ca-fixture.js";

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

test("an expired root is CORE_CA_EXPIRED (the `now` seam, not a stale fixture)", async () => {
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
        assert.equal(err.code, "CORE_CA_EXPIRED");
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
