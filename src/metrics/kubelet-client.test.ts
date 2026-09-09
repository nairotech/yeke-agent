/**
 * The two disciplines that make the collector safe to run in someone else's
 * cluster: TLS verification and token freshness.
 *
 * Both are measured against a REAL TLS server on the loopback interface, not
 * against a mock. A mocked TLS failure asserts that the code handles the error
 * object a test author imagined; what matters here is that Node's actual
 * verification failure is classified as `tls-unverified` and produces no data.
 *
 * `openssl` is required. When it is absent these tests FAIL rather than skip:
 * a security claim that quietly reports success on a machine that could not
 * check it is worse than no claim, and this repository's convention is that a
 * gate which cannot measure says so by name.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:https";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { serviceAccountToken } from "../kube.js";
import { type TlsFixture, createTlsFixture, opensslAvailable } from "./fixture.js";
import { KubeletClient, type TokenReader } from "./kubelet-client.js";

let cached: { fixture: TlsFixture; directory: string } | undefined;

async function tls(): Promise<TlsFixture> {
  if (cached) return cached.fixture;
  assert.ok(
    await opensslAvailable(),
    "NOT MEASURED: openssl is not on PATH, so the TLS claims of the metrics collector were not " +
      "checked on this machine. Install openssl and run the gate again.",
  );
  const directory = await mkdtemp(join(tmpdir(), "yeke-kubelet-tls-"));
  cached = { fixture: await createTlsFixture(directory), directory };
  return cached.fixture;
}

interface Handled {
  readonly url: string;
  readonly authorization: string | undefined;
}

interface Fake {
  readonly port: number;
  readonly seen: Handled[];
  close(): Promise<void>;
}

async function fakeKubelet(
  options: { cert: Buffer; key: Buffer },
  handler: (request: Handled, index: number) => { status: number; body: string } | "hang",
): Promise<Fake> {
  const seen: Handled[] = [];
  const server: Server = createServer({ cert: options.cert, key: options.key }, (req, res) => {
    const entry: Handled = {
      url: req.url ?? "",
      authorization: req.headers.authorization,
    };
    seen.push(entry);
    const answer = handler(entry, seen.length - 1);
    if (answer === "hang") return; // never responds: exercises the timeout
    res.writeHead(answer.status, { "content-type": "application/json" });
    res.end(answer.body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    seen,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

function staticToken(value: string): TokenReader {
  return { read: async () => value, invalidate: () => undefined };
}

const TARGET = { node: "node-a", address: "127.0.0.1" };

test("a certificate signed by the cluster CA is read normally", async () => {
  const fixture = await tls();
  const kubelet = await fakeKubelet({ cert: fixture.serverCert, key: fixture.serverKey }, () => ({
    status: 200,
    body: JSON.stringify({ node: { nodeName: "node-a" } }),
  }));
  const client = new KubeletClient({
    token: staticToken("tok-1"),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    const result = await client.summary<{ node: { nodeName: string } }>(TARGET);
    assert.equal(result.state, "ok");
    assert.equal(result.state === "ok" ? result.value.node.nodeName : "", "node-a");
    assert.equal(kubelet.seen[0]?.url, "/stats/summary");
    assert.equal(kubelet.seen[0]?.authorization, "Bearer tok-1");
    assert.equal(client.counters.tlsUnverified, 0);
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("NEGATIVE PROBE: an unsigned certificate produces NO data, not a partial reading", async () => {
  const fixture = await tls();
  // A self-signed kubelet certificate: the kubeadm default, which is why
  // metrics-server ships `--kubelet-insecure-tls` in most guides.
  const kubelet = await fakeKubelet({ cert: fixture.rogueCert, key: fixture.rogueKey }, () => ({
    status: 200,
    body: JSON.stringify({ node: { nodeName: "node-a" } }),
  }));
  const client = new KubeletClient({
    token: staticToken("tok-1"),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    const result = await client.summary(TARGET);
    assert.equal(result.state, "tls-unverified");
    assert.equal("value" in result, false, "a node that failed verification produced data");
    assert.equal(client.counters.tlsUnverified, 1);
    // The server never saw a request: verification fails during the handshake.
    assert.equal(kubelet.seen.length, 0);
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("the flag turns the same node into data, and says so once at startup", async () => {
  const fixture = await tls();
  const kubelet = await fakeKubelet({ cert: fixture.rogueCert, key: fixture.rogueKey }, () => ({
    status: 200,
    body: JSON.stringify({ node: { nodeName: "node-a" } }),
  }));
  const warnings: string[] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => {
    warnings.push(args.join(" "));
  };
  let client: KubeletClient | undefined;
  try {
    client = new KubeletClient({
      token: staticToken("tok-1"),
      insecureTls: true,
      port: kubelet.port,
    });
    console.warn = original;
    const result = await client.summary(TARGET);
    assert.equal(result.state, "ok");
    assert.equal(warnings.length, 1, "the acceptance must be announced exactly once");
    assert.match(warnings[0] ?? "", /YEKE_KUBELET_INSECURE_TLS/);
    // ASCII only: an operator greps the plain spelling (README, "Conventions").
    // eslint-disable-next-line no-control-regex
    assert.ok(/^[\x00-\x7F]*$/.test(warnings[0] ?? ""), "the warning carries non-ASCII characters");
  } finally {
    console.warn = original;
    await client?.close();
    await kubelet.close();
  }
});

test("the token is read from the FILE on every request", async () => {
  const fixture = await tls();
  const directory = await mkdtemp(join(tmpdir(), "yeke-token-"));
  const path = join(directory, "token");
  await writeFile(path, "first-token\n", "utf8");

  const kubelet = await fakeKubelet({ cert: fixture.serverCert, key: fixture.serverKey }, () => ({
    status: 200,
    body: "{}",
  }));
  // The SAME reader `kube.ts` uses on the apiserver path, with its 60 second
  // TTL cache: if the collector did not invalidate before each read, the second
  // request below would still carry the first token.
  const client = new KubeletClient({
    token: serviceAccountToken(path),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    await client.summary(TARGET);
    await writeFile(path, "rotated-token\n", "utf8");
    await client.summary(TARGET);

    assert.equal(kubelet.seen[0]?.authorization, "Bearer first-token");
    assert.equal(
      kubelet.seen[1]?.authorization,
      "Bearer rotated-token",
      "the rotated token did not reach the kubelet; a cached token starts returning 401",
    );
  } finally {
    await client.close();
    await kubelet.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a 401 is retried exactly once, with a token read again", async () => {
  const fixture = await tls();
  // A reader that hands out a different token on every read. The apiserver-side
  // reader is exercised by the previous test; what is measured here is that the
  // retry goes through the reader AGAIN rather than reusing the value it
  // already had -- which is the whole point of retrying a 401.
  let reads = 0;
  const token: TokenReader = {
    read: async () => `tok-${(reads += 1)}`,
    invalidate: () => undefined,
  };

  const kubelet = await fakeKubelet(
    { cert: fixture.serverCert, key: fixture.serverKey },
    (_request, index) =>
      index === 0
        ? { status: 401, body: "Unauthorized" }
        : { status: 200, body: JSON.stringify({ node: { nodeName: "node-a" } }) },
  );
  const client = new KubeletClient({
    token,
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    const result = await client.summary(TARGET);
    assert.equal(result.state, "ok");
    assert.equal(kubelet.seen.length, 2);
    assert.equal(client.counters.tokenRetries, 1);
    assert.equal(kubelet.seen[0]?.authorization, "Bearer tok-1");
    assert.equal(
      kubelet.seen[1]?.authorization,
      "Bearer tok-2",
      "the retry reused the token that had just been refused",
    );
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("a credential that is invalid rather than stale is not retried in a loop", async () => {
  const fixture = await tls();
  const kubelet = await fakeKubelet({ cert: fixture.serverCert, key: fixture.serverKey }, () => ({
    status: 401,
    body: "Unauthorized",
  }));
  const client = new KubeletClient({
    token: staticToken("tok"),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    const result = await client.summary(TARGET);
    assert.equal(result.state, "unauthorized");
    // Exactly two: one attempt, one retry. A component that keeps re-presenting
    // a rejected credential gets itself rate-limited by the server it needs.
    assert.equal(kubelet.seen.length, 2);
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("a 403 is the 'manifest not re-applied' state, not an unreachable node", async () => {
  const fixture = await tls();
  const kubelet = await fakeKubelet({ cert: fixture.serverCert, key: fixture.serverKey }, () => ({
    status: 403,
    body: "forbidden",
  }));
  const client = new KubeletClient({
    token: staticToken("tok"),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    const result = await client.summary(TARGET);
    // K5 gives this its own state because its remedy is specific: the agent's
    // ClusterRole gained `nodes/stats` with this feature and the agent cannot
    // widen its own RBAC.
    assert.equal(result.state, "forbidden");
    assert.equal(client.counters.forbidden, 1);
    assert.equal(kubelet.seen.length, 1, "a 403 must not be retried");
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("cAdvisor text arrives as a line stream, never as one string", async () => {
  const fixture = await tls();
  const kubelet = await fakeKubelet({ cert: fixture.serverCert, key: fixture.serverKey }, () => ({
    status: 200,
    body: "# TYPE x counter\nline-one\nline-two\nno-trailing-newline",
  }));
  const client = new KubeletClient({
    token: staticToken("tok"),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
  });
  try {
    const result = await client.cadvisor(TARGET, async (lines) => {
      const collected: string[] = [];
      for await (const line of lines) collected.push(line);
      return collected;
    });
    assert.equal(result.state, "ok");
    assert.deepEqual(result.state === "ok" ? result.value : [], [
      "# TYPE x counter",
      "line-one",
      "line-two",
      // The last line arrives without a newline; dropping it would silently lose
      // one series on every node.
      "no-trailing-newline",
    ]);
    assert.equal(kubelet.seen[0]?.url, "/metrics/cadvisor");
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("a kubelet that never answers becomes unreachable, not a hung tick", async () => {
  const fixture = await tls();
  const kubelet = await fakeKubelet(
    { cert: fixture.serverCert, key: fixture.serverKey },
    () => "hang",
  );
  const client = new KubeletClient({
    token: staticToken("tok"),
    ca: fixture.ca,
    insecureTls: false,
    port: kubelet.port,
    timeoutMs: 300,
  });
  try {
    const result = await client.summary(TARGET);
    assert.equal(result.state, "unreachable");
    assert.equal(client.counters.timeout, 1);
  } finally {
    await client.close();
    await kubelet.close();
  }
});

test("the TLS material is cleaned up", async () => {
  if (cached) await rm(cached.directory, { recursive: true, force: true });
});
