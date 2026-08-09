/**
 * **Classification** of the in-cluster identity read.
 *
 * The claim under measurement is one sentence: the failure that surfaces when
 * the agent's own ServiceAccount token cannot be read is an IDENTITY failure,
 * not an upstream failure.
 *
 * ─── Why this test had to exist ─────────────────────────────────────────────
 *
 * `authHeaders()` was not wrapped: a `readFile` error fell into the general
 * `catch` of `tunnel-client.ts` and was classified as `UPSTREAM_ERROR`. With no
 * upstream involved, the operator would go looking at the apiserver. The
 * measurement here looks at the CODE of the `AgentFailure` — not at its
 * sentence; the sentence is `describeFailure`'s machine-readable line and may
 * change one day, the code must not.
 *
 * This file is the agent's FIRST test; the way to run it (the `test` script) was
 * added along with it. Until that day none of the agent's claims were measured
 * mechanically.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Cluster } from "@kubernetes/client-node";
import { foreignTextsOf, type TunnelFailure } from "@nairotech/yeke-tunnel";
import { AgentFailure } from "./failure.js";
import { runExecPlugin, serviceAccountToken } from "./kube.js";

async function codeOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (err) {
    assert.ok(err instanceof AgentFailure, `expected an AgentFailure, got: ${String(err)}`);
    return err.failure.code;
  }
  return "";
}

async function failureOf(run: () => Promise<unknown>): Promise<TunnelFailure> {
  try {
    await run();
  } catch (err) {
    assert.ok(err instanceof AgentFailure, `expected an AgentFailure, got: ${String(err)}`);
    return err.failure;
  }
  throw new Error("expected a failure");
}

test("an unreadable SA token file is CREDENTIAL_UNAVAILABLE (not UPSTREAM_ERROR)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "yeke-sa-"));
  try {
    const token = serviceAccountToken(join(dir, "no-such-file"));
    assert.equal(await codeOf(() => token.read()), "CREDENTIAL_UNAVAILABLE");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an empty SA token file has its OWN code: TOKEN_FILE_EMPTY", async () => {
  const dir = await mkdtemp(join(tmpdir(), "yeke-sa-"));
  try {
    const path = join(dir, "token");
    await writeFile(path, "   \n");
    const token = serviceAccountToken(path);
    // The read succeeded, there is no identity — it must not land in the same
    // box as an unreadable file: one sends you to "where is the file", the other
    // to "why is the file empty".
    assert.equal(await codeOf(() => token.read()), "TOKEN_FILE_EMPTY");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ─── `AUTH_PLUGIN_FAILED`: two foreign texts, two separate owners ────────────
//
// For one round the branch carried a SINGLE `detail` and the schema called it
// "the plugin's OWN `stderr`". The line producing it, however, merged the two:
// `` `${err.message} — ${stderr}` ``. So the on-screen label "what the plugin
// wrote to stderr:" pointed at a string with Node's sentence in front of it; and
// when `stderr` was empty the text was Node's in its ENTIRETY — the label was
// claiming the plugin had written something it never wrote.
//
// The measurement drives both states and asks `foreignTextsOf` every time: is
// the payload consistent with the owners the schema declares?

const CLUSTER = {
  name: "example",
  server: "https://apiserver.example:6443",
  skipTLSVerify: false,
} as Cluster;

/**
 * The text does not appear ON THE COMMAND LINE — that is the criterion this
 * fixture carries.
 *
 * Node's `Command failed:` line echoes the command and its arguments verbatim.
 * Had we written the text inside `sh -c 'echo … >&2'`, the claim "`detail` does
 * not carry the plugin's text" would produce a FALSE POSITIVE because of the
 * copy in the argument, and the measurement would measure nothing. Passing it
 * through an environment variable keeps the same string away from the command
 * line.
 */
const PLUGIN_STDERR = "Unable to locate credentials";

test("CRITICAL: when the plugin writes to stderr, the TWO texts separate into TWO fields", async () => {
  const failure = await failureOf(() =>
    runExecPlugin(
      {
        command: "/bin/sh",
        args: ["-c", 'printf "%s\\n" "$YEKE_TEST_STDERR" >&2; exit 1'],
        env: [{ name: "YEKE_TEST_STDERR", value: PLUGIN_STDERR }],
      },
      CLUSTER,
    ),
  );

  assert.equal(failure.code, "AUTH_PLUGIN_FAILED");
  const params = failure.params as { command: string; detail: string; stderr: string };
  assert.equal(params.stderr, PLUGIN_STDERR);
  // Node's own frame (which command, how it ended) is not lost.
  assert.match(params.detail, /Command failed/);
  // THEY DO NOT MERGE: each field carries only its own owner's text. In the old
  // shape `detail` carried both and one of the labels was necessarily a lie.
  // That Node's `message` ECHOES stderr is measured here as well: if the echo
  // were not stripped, this line would break (and it did on the first run).
  assert.doesNotMatch(params.detail, new RegExp(PLUGIN_STDERR));
  assert.doesNotMatch(params.stderr, /Command failed/);

  assert.deepEqual(foreignTextsOf(failure.code, params), [
    { owner: "node", text: params.detail },
    { owner: "plugin", text: PLUGIN_STDERR },
  ]);
});

test("CRITICAL: when stderr stays EMPTY, the plugin label is NEVER produced", async () => {
  // `spawn ENOENT` — the plugin never ran, so it wrote nothing at all. In the
  // old shape `detail` was 100% Node's text and the screen said "what the plugin
  // wrote to stderr:". This is the most blatant of the four failures that were
  // fixed.
  const failure = await failureOf(() =>
    runExecPlugin({ command: join(tmpdir(), "yeke-no-such-plugin") }, CLUSTER),
  );

  assert.equal(failure.code, "AUTH_PLUGIN_FAILED");
  const params = failure.params as { command: string; detail: string; stderr: string };
  // The field is mandatory IN THE SCHEMA: its absence is represented by an empty
  // string rather than `undefined`, so the wire schema (`z.string()`) still
  // holds.
  assert.equal(params.stderr, "");
  assert.match(params.detail, /ENOENT/);

  const texts = foreignTextsOf(failure.code, params);
  assert.deepEqual(texts, [{ owner: "node", text: params.detail }]);
  assert.ok(
    !texts.some((text) => text.owner === "plugin"),
    "if the plugin never wrote anything, there must be no plugin label either",
  );
});

test("the token is served from cache for the TTL; invalidate() forces a re-read", async () => {
  const dir = await mkdtemp(join(tmpdir(), "yeke-sa-"));
  try {
    const path = join(dir, "token");
    await writeFile(path, "first\n");
    let clock = 1_000;
    const token = serviceAccountToken(path, { ttlMs: 60_000, now: () => clock });

    assert.equal(await token.read(), "first");
    await writeFile(path, "second\n");
    // The TTL has not elapsed: even if the file changed, the cache speaks.
    assert.equal(await token.read(), "first");

    // The 401 hook's path: it must be able to force a re-read before the TTL
    // elapses, otherwise a token revoked early would keep producing 401s until
    // the TTL ran out.
    token.invalidate();
    assert.equal(await token.read(), "second");

    await writeFile(path, "third\n");
    clock += 60_001;
    assert.equal(await token.read(), "third");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
