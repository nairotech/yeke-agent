/**
 * BOUNDARY GATE — "the agent depends only on the pinned protocol package".
 *
 * ─── What this gate replaced, and why it had to be rewritten ────────────────
 *
 * The agent used to live inside the product monorepo, next to the control plane
 * and the web application. The gate there scanned the sibling `packages/*` and
 * `apps/*` manifests, learned the workspace package names from them, and failed
 * if the agent's source imported any of them except the tunnel contract. That
 * mechanism is meaningless in a standalone repository: there are no siblings to
 * scan, and a scan that finds nothing accuses nobody — the gate would have gone
 * quietly green while measuring exactly zero.
 *
 * The invariant it protected is still in force and is now more critical, not
 * less: **the agent's only YEKE dependency is the tunnel contract, and the
 * version it speaks is pinned exactly.** Two things changed shape:
 *
 *  · The contract no longer resolves through a workspace link but from the
 *    public registry. "Which package" is therefore a question about the
 *    manifest, not about a directory tree.
 *  · A version range would be a silent wire drift. In the monorepo, the control
 *    plane and the agent were compiled from the same checkout, so they could not
 *    disagree about the wire — that safety was a build accident, and splitting
 *    the repository removed it. A pin of `^4` says "any minor of protocol v4",
 *    and the day a minor changes a frame, an agent built from an unchanged
 *    commit starts speaking a different wire. Only an exact pin makes the wire a
 *    property of the commit.
 *
 * ─── Blacklist, not whitelist ───────────────────────────────────────────────
 *
 * The agent has legitimate third-party dependencies (`ws`, `undici`,
 * `@kubernetes/client-node`) and maintaining a second copy of that list here
 * would make every new library edit this file — a list nobody looks at is
 * eventually widened with a `// FIXME`. What is measured is the `@nairotech/*`
 * and `@yeke/*` surface plus the shape of the pin.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { TUNNEL_PROTOCOL_VERSION } from "@nairotech/yeke-tunnel";

/** `src` — cwd is not trusted; the root is derived from the test's own location. */
const SRC = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SRC, "..");

/** The one YEKE package the agent may depend on. */
const ALLOWED_PROTOCOL_PACKAGE = "@nairotech/yeke-tunnel";

/**
 * Scopes that belong to the product rather than to the ecosystem.
 *
 * `@yeke/*` never reached a registry — those are the monorepo's internal
 * packages, and an import of one of them can only mean the agent has been wired
 * back into a tree that does not exist here. Keeping the name in the gate after
 * the split is deliberate: the gate has to fail on the copy-paste, not only on
 * the packages that exist today.
 */
const PRODUCT_SCOPES = ["@nairotech/", "@yeke/"];

/**
 * An exact version: `4.0.1`, optionally with a prerelease/build suffix.
 *
 * Everything else is a range — `^4.0.1`, `~4.0`, `>=4`, `4.x`, `*`, `latest`,
 * and also the non-registry protocols (`workspace:`, `file:`, `link:`,
 * `portal:`, a git URL). The last group matters as much as the first: they
 * resolve to whatever happens to be on the machine that runs the install, which
 * is precisely the property this repository gave up when it left the monorepo.
 */
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

interface Manifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

function manifest(): Manifest {
  return JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8")) as Manifest;
}

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      found.push(...sourceFiles(full));
      continue;
    }
    if (entry.endsWith(".ts")) found.push(full);
  }
  return found;
}

/**
 * Comments are blanked before scanning, with the line count preserved.
 *
 * Measured in the monorepo, on this gate's ancestor: a scan that does not strip
 * comments mistakes the comment explaining the rule for a violation of the rule.
 * The first run of that gate produced four findings and all four were the gate's
 * own header.
 */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\n]/g, " "))
    .replace(/(^|[^:])\/\/[^\n]*/g, (line, lead: string) => lead + " ".repeat(line.length - lead.length));
}

/**
 * The three positions in which a module specifier can appear.
 *
 * The ancestor of this gate used one loose pattern — `(from|import|require)`
 * followed by any quote — and the first run here proved that is not enough:
 * stripping comments does not strip STRINGS, and one of the assertion messages
 * below ends with the word "import" immediately before its closing quote. The
 * scanner read that closing quote as an opening one and reported a specifier
 * made of prose.
 *
 * The patterns are narrowed to the actual grammar instead of rewording the
 * message: a side-effect import only appears at statement position, and `from`,
 * `import(` and `require(` must be followed IMMEDIATELY by the quote. Prose can
 * contain any of those words; what it does not contain is the word welded to a
 * quotation mark.
 */
const SPECIFIER_PATTERNS = [
  /(?:^|\n)\s*import\s+["']([^"'\n]+)["']/g,
  /\bfrom\s*["']([^"'\n]+)["']/g,
  /\b(?:import|require)\s*\(\s*["']([^"'\n]+)["']/g,
];

function specifiersOf(source: string): string[] {
  const stripped = stripComments(source);
  return SPECIFIER_PATTERNS.flatMap((pattern) => [
    ...stripped.matchAll(pattern),
  ]).map((match) => match[1]!);
}

/** `@scope/name/sub/path` → `@scope/name`; `pkg/sub` → `pkg`. */
function packageOf(specifier: string): string {
  return specifier.startsWith("@")
    ? specifier.split("/").slice(0, 2).join("/")
    : (specifier.split("/")[0] ?? specifier);
}

test("boundary: the agent's source imports no product package other than the tunnel contract", () => {
  const files = sourceFiles(SRC);

  assert.ok(files.length >= 5, `the scan saw ${files.length} files; the root may be wrong`);
  assert.ok(
    files.some((file) => file.endsWith("tunnel-client.ts")),
    "the scan does not see `tunnel-client.ts`",
  );

  const leaks: string[] = [];
  for (const file of files) {
    for (const specifier of specifiersOf(readFileSync(file, "utf8"))) {
      // A subpath import counts too: `@yeke/shared/dist/…` is the same dependency.
      const pkg = packageOf(specifier);
      if (!PRODUCT_SCOPES.some((scope) => pkg.startsWith(scope))) continue;
      if (pkg === ALLOWED_PROTOCOL_PACKAGE) continue;
      leaks.push(`${relative(SRC, file)} → ${specifier}`);
    }
  }

  assert.deepEqual(
    leaks,
    [],
    "the agent bound itself to a product package other than the wire contract; that import " +
      `is only resolvable inside the monorepo this repository was split out of:\n${leaks.join("\n")}`,
  );
});

test("boundary: no source file reaches outside the repository", () => {
  const escapes: string[] = [];
  for (const file of sourceFiles(SRC)) {
    for (const specifier of specifiersOf(readFileSync(file, "utf8"))) {
      if (!specifier.startsWith(".")) continue;
      const target = resolve(dirname(file), specifier);
      if (target === REPO_ROOT || target.startsWith(REPO_ROOT + sep)) continue;
      escapes.push(`${relative(SRC, file)} → ${specifier}`);
    }
  }

  assert.deepEqual(
    escapes,
    [],
    "a relative import climbed above the repository root; in the monorepo such a path " +
      `resolved to a sibling package, here it resolves to nothing:\n${escapes.join("\n")}`,
  );
});

test("boundary: every bare import is declared in package.json", () => {
  const pkg = manifest();
  const declared = new Set([
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.devDependencies ?? {}),
  ]);

  const undeclared: string[] = [];
  for (const file of sourceFiles(SRC)) {
    for (const specifier of specifiersOf(readFileSync(file, "utf8"))) {
      if (specifier.startsWith(".") || specifier.startsWith("node:")) continue;
      const name = packageOf(specifier);
      if (declared.has(name)) continue;
      undeclared.push(`${relative(SRC, file)} → ${name}`);
    }
  }

  // An undeclared import is not a type error and not a runtime error either, as
  // long as some other package happens to hoist it into `node_modules`. It
  // becomes an error on the day that other package drops it — which is a day
  // nobody is watching, and in a customer's cluster.
  assert.deepEqual(
    undeclared,
    [],
    `imported but not declared as a dependency:\n${undeclared.join("\n")}`,
  );
});

test("pin: the tunnel contract is pinned to an EXACT version, not a range", () => {
  const pkg = manifest();
  const range = pkg.dependencies?.[ALLOWED_PROTOCOL_PACKAGE];

  assert.ok(
    range,
    `${ALLOWED_PROTOCOL_PACKAGE} is not among the dependencies; the agent cannot speak the wire without it`,
  );
  assert.match(
    range,
    EXACT_VERSION,
    `${ALLOWED_PROTOCOL_PACKAGE} is pinned as '${range}'. A range lets the wire contract move without a ` +
      "commit in this repository: two builds of the same source would speak two different wires, and the " +
      "mismatch surfaces as a tunnel closed with 1008 — an unmanageable cluster",
  );

  // Every other dependency must come from the registry too. A `workspace:` or
  // `link:` protocol left behind here would mean the split is only nominal.
  const local = Object.entries({
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  }).filter(([, spec]) => /^(workspace|link|file|portal):/.test(spec));

  assert.deepEqual(
    local.map(([name, spec]) => `${name}@${spec}`),
    [],
    "a dependency resolves from outside the registry; it would install differently on every machine",
  );
});

test("pin: the pinned major equals the tunnel protocol version the agent speaks", () => {
  const range = manifest().dependencies?.[ALLOWED_PROTOCOL_PACKAGE] ?? "";
  // The leading digits, not `split(".")[0]`: with a range in place that would be
  // `^4` and the failure would report a major of NaN, sending the reader looking
  // for a parsing bug instead of at the range.
  const major = Number(/^\D*(\d+)/.exec(range)?.[1]);

  // The package's own contract: its major IS the wire protocol version, which is
  // why the pin can be read as "the upper end of the handshake window". If the
  // two ever diverge, the number in the manifest stops meaning what every reader
  // takes it to mean.
  assert.equal(
    major,
    TUNNEL_PROTOCOL_VERSION,
    `the pin says major ${major} but the agent speaks protocol v${TUNNEL_PROTOCOL_VERSION}`,
  );
});

/**
 * The installed package's own manifest.
 *
 * `require.resolve("<pkg>/package.json")` would be the short way and it does not
 * work: the contract's `exports` map declares `"."` only, so Node refuses the
 * subpath with `ERR_PACKAGE_PATH_NOT_EXPORTED` (measured on 4.0.1). So we
 * resolve the entry point instead and climb until we find the manifest that
 * names this package — climbing rather than trusting a fixed depth, because
 * `main` may point anywhere inside the package.
 */
function installedManifestPath(packageName: string): string {
  const require = createRequire(join(REPO_ROOT, "package.json"));
  let dir = dirname(require.resolve(packageName));
  for (;;) {
    const candidate = join(dir, "package.json");
    try {
      const { name } = JSON.parse(readFileSync(candidate, "utf8")) as { name?: string };
      if (name === packageName) return candidate;
    } catch {
      // No manifest at this level, or an unreadable one: keep climbing.
    }
    const parent = dirname(dir);
    if (parent === dir) throw new Error(`could not locate the manifest of ${packageName}`);
    dir = parent;
  }
}

test("pin: the installed contract is the pinned version, resolved inside this repository", () => {
  const pinned = manifest().dependencies?.[ALLOWED_PROTOCOL_PACKAGE] ?? "";

  const installedManifest = installedManifestPath(ALLOWED_PROTOCOL_PACKAGE);
  const installed = JSON.parse(readFileSync(installedManifest, "utf8")) as { version?: string };

  assert.equal(
    installed.version,
    pinned,
    `the installed contract is ${installed.version} while the manifest pins ${pinned}; the lockfile is stale`,
  );

  // Where it resolved FROM matters as much as which version it is: the whole
  // point of leaving the monorepo is that this package arrives from the
  // registry, not from a checkout sitting next to this one. `realpath` sees
  // through pnpm's store symlink, so what is asserted here is the final
  // location on disk.
  const real = realpathSync(installedManifest);
  assert.ok(
    real.startsWith(realpathSync(REPO_ROOT) + sep),
    `the contract resolved outside this repository (${real}); it is being linked from another tree ` +
      "instead of installed from the registry",
  );
});
