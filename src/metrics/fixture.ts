/**
 * Fixture generators for the collector's tests and its measurement harness.
 *
 * ─── Why this is hand-written and not a captured file ───────────────────────
 *
 * K3's acceptance criteria ask for "a real-sized Summary JSON (a sample taken
 * from a live node)". No live node was available in the round that wrote this
 * file, so the documents here are BUILT to the upstream shape rather than
 * copied from a cluster. That distinction matters and is the reason for this
 * paragraph: a generated fixture proves that the reader handles the shape it
 * was given, and it cannot prove that the shape is the one a kubelet emits.
 * Everything measured against these documents is a statement about the reader.
 *
 * What is defended: every field name below is written to match
 * `k8s.io/kubelet/pkg/apis/stats/v1alpha1` exactly, including
 * `ephemeral-storage`, `process_stats`, `curproc` and `usageNanoCores`. A typo
 * here would produce a fixture that a broken reader passes, which is worse than
 * no fixture — so the generator and the reader are deliberately NOT written
 * against a shared type alias for the field names: the reader declares its own
 * interfaces and this file writes literals. If the two ever disagree, a test
 * fails; if they shared a symbol, a rename would move both and nothing would.
 *
 * ─── Why it lives under `src/` ──────────────────────────────────────────────
 *
 * So that `tsc --noEmit`, the boundary gate and the import scan all see it.
 * A fixture that escapes the gates is a fixture that goes stale the first time
 * a type moves, and this product has already measured that class of failure
 * (the harness type-check gate in the monorepo's CLAUDE.md section 2).
 */

export interface FixturePod {
  readonly namespace: string;
  readonly name: string;
  readonly uid: string;
}

/** Deterministic pod identities for a node: same input, same uids, every run. */
export function fixturePods(node: string, count: number): FixturePod[] {
  const pods: FixturePod[] = [];
  for (let index = 0; index < count; index += 1) {
    const namespace = index % 3 === 0 ? "kube-system" : index % 3 === 1 ? "ornek" : "izleme";
    pods.push({
      namespace,
      name: `${namespace}-app-${index}-${node}`,
      uid: `${node}-uid-${String(index).padStart(4, "0")}`,
    });
  }
  return pods;
}

export interface SummaryFixtureOptions {
  readonly node: string;
  readonly pods: readonly FixturePod[];
  /** Tick number; counters grow with it so a rate can be derived. */
  readonly tick: number;
  /** Milliseconds between ticks, used to stamp the blocks. */
  readonly periodMs?: number;
  readonly startMs?: number;
  /** K3: PSI is conditional. `false` produces a document with no `psi` anywhere. */
  readonly psi?: boolean;
  /** `psi.io` `some.avg60` for the node; the IO zero probe reads it. */
  readonly psiIo?: number;
}

function stamp(ms: number): string {
  return new Date(ms).toISOString();
}

function psiBlock(some: number): Record<string, unknown> {
  return {
    full: { total: 0, avg10: 0, avg60: 0, avg300: 0 },
    some: { total: Math.round(some * 1e6), avg10: some, avg60: some, avg300: some },
  };
}

/**
 * A Summary document in the upstream shape.
 *
 * Counter fields (`rxBytes`, `txBytes`, `rxErrors`, `txErrors`) grow linearly
 * with `tick` so that the derived rate is a number a test can predict exactly
 * rather than assert loosely.
 */
export function summaryFixture(options: SummaryFixtureOptions): unknown {
  const periodMs = options.periodMs ?? 30_000;
  const startMs = options.startMs ?? Date.parse("2026-09-09T00:00:00.000Z");
  const at = startMs + options.tick * periodMs;
  const time = stamp(at);
  const psi = options.psi ?? true;
  const withPsi = (some: number): Record<string, unknown> =>
    psi ? { psi: psiBlock(some) } : {};

  const pods = options.pods.map((pod, index) => ({
    podRef: { name: pod.name, namespace: pod.namespace, uid: pod.uid },
    startTime: stamp(startMs - 3_600_000),
    cpu: {
      time,
      usageNanoCores: 12_000_000 + index * 1_000_000,
      usageCoreNanoSeconds: (12_000_000 + index * 1_000_000) * options.tick,
      ...withPsi(0.4),
    },
    memory: {
      time,
      availableBytes: 268_435_456 - index * 1_048_576,
      usageBytes: 157_286_400 + index * 2_097_152,
      workingSetBytes: 134_217_728 + index * 1_048_576,
      rssBytes: 100_663_296 + index * 1_048_576,
      pageFaults: 12_000 + index,
      majorPageFaults: 3,
      ...withPsi(0.2),
    },
    io: { time, ...withPsi(options.psiIo ?? 0.1) },
    network: {
      time,
      name: "eth0",
      rxBytes: 1_000_000 + options.tick * (30_000 + index * 100),
      rxErrors: index % 7 === 0 ? options.tick : 0,
      txBytes: 800_000 + options.tick * (24_000 + index * 80),
      txErrors: 0,
      interfaces: [
        {
          name: "eth0",
          rxBytes: 1_000_000 + options.tick * (30_000 + index * 100),
          rxErrors: index % 7 === 0 ? options.tick : 0,
          txBytes: 800_000 + options.tick * (24_000 + index * 80),
          txErrors: 0,
        },
      ],
    },
    // The exact upstream key, hyphen and all.
    "ephemeral-storage": {
      time,
      availableBytes: 10_737_418_240,
      capacityBytes: 21_474_836_480,
      usedBytes: 41_943_040 + index * 1_048_576,
      inodesFree: 1_200_000,
      inodes: 1_310_720,
      inodesUsed: 110_720,
    },
    process_stats: { process_count: 4 + (index % 5) },
    // Container-level stats exist in a real document and the reader must ignore
    // them (K3: the container list is not summed). A fixture without them would
    // never exercise that rule.
    containers: [
      {
        name: "app",
        startTime: stamp(startMs - 3_600_000),
        cpu: { time, usageNanoCores: 9_000_000, usageCoreNanoSeconds: 9_000_000 * options.tick },
        memory: { time, workingSetBytes: 100_663_296, rssBytes: 83_886_080 },
        rootfs: { time, availableBytes: 10_737_418_240, capacityBytes: 21_474_836_480, usedBytes: 24_576 },
        logs: { time, availableBytes: 10_737_418_240, capacityBytes: 21_474_836_480, usedBytes: 8_192 },
      },
    ],
  }));

  return {
    node: {
      nodeName: options.node,
      startTime: stamp(startMs - 86_400_000),
      cpu: {
        time,
        usageNanoCores: 1_450_000_000,
        usageCoreNanoSeconds: 1_450_000_000 * options.tick,
        ...withPsi(1.5),
      },
      memory: {
        time,
        availableBytes: 6_442_450_944,
        usageBytes: 9_663_676_416,
        workingSetBytes: 8_589_934_592,
        rssBytes: 7_516_192_768,
        pageFaults: 900_000,
        majorPageFaults: 120,
        ...withPsi(0.8),
      },
      io: { time, ...withPsi(options.psiIo ?? 0.1) },
      network: {
        time,
        name: "eth0",
        rxBytes: 50_000_000 + options.tick * 1_500_000,
        rxErrors: 0,
        txBytes: 40_000_000 + options.tick * 1_200_000,
        txErrors: 0,
        interfaces: [
          {
            name: "eth0",
            rxBytes: 50_000_000 + options.tick * 1_500_000,
            rxErrors: 0,
            txBytes: 40_000_000 + options.tick * 1_200_000,
            txErrors: 0,
          },
          // Loopback: the reader must not count it (see `networkTotals`).
          { name: "lo", rxBytes: 999_999_999, rxErrors: 0, txBytes: 999_999_999, txErrors: 0 },
        ],
      },
      fs: {
        time,
        availableBytes: 32_212_254_720,
        capacityBytes: 107_374_182_400,
        usedBytes: 75_161_927_680,
        inodesFree: 5_000_000,
        inodes: 6_553_600,
        inodesUsed: 1_553_600,
      },
      runtime: {
        imageFs: {
          time,
          availableBytes: 32_212_254_720,
          capacityBytes: 107_374_182_400,
          usedBytes: 12_884_901_888,
          inodesFree: 5_000_000,
          inodes: 6_553_600,
          inodesUsed: 1_553_600,
        },
        containerFs: {
          time,
          availableBytes: 32_212_254_720,
          capacityBytes: 107_374_182_400,
          usedBytes: 12_884_901_888,
        },
      },
      rlimit: { time, maxpid: 4_194_304, curproc: 421 },
      // Present in a real document, and not an entity the product draws.
      systemContainers: [
        {
          name: "kubelet",
          startTime: stamp(startMs - 86_400_000),
          cpu: { time, usageNanoCores: 45_000_000 },
          memory: { time, workingSetBytes: 83_886_080 },
        },
      ],
    },
    pods,
  };
}

export interface CadvisorFixtureOptions {
  readonly node: string;
  readonly pods: readonly FixturePod[];
  readonly tick: number;
  /** `zero` produces the broken-counter case the IO zero probe exists for. */
  readonly io?: "normal" | "zero";
  readonly startMs?: number;
  readonly periodMs?: number;
  /** Lines from other families, to prove the filter actually filters. */
  readonly noise?: number;
}

/**
 * The cAdvisor exposition text, in the kubelet's shape.
 *
 * Includes, deliberately:
 *  · the machine root (`id="/"`), which is the node total;
 *  · a pod-level cgroup line with an EMPTY container label;
 *  · a pause container line (`container="POD"`);
 *  · two devices per container, so the summing is exercised;
 *  · `# HELP` / `# TYPE` comments and unrelated families as noise.
 */
export function cadvisorFixture(options: CadvisorFixtureOptions): string {
  const periodMs = options.periodMs ?? 30_000;
  const startMs = options.startMs ?? Date.parse("2026-09-09T00:00:00.000Z");
  const at = startMs + options.tick * periodMs;
  const zero = options.io === "zero";
  const out: string[] = [];

  out.push("# HELP container_fs_reads_bytes_total Cumulative count of bytes read");
  out.push("# TYPE container_fs_reads_bytes_total counter");

  const reads = (base: number): number => (zero ? 0 : base);
  out.push(
    `container_fs_reads_bytes_total{device="/dev/sda",id="/"} ${reads(4_000_000 + options.tick * 200_000)} ${at}`,
  );
  out.push(
    `container_fs_writes_bytes_total{device="/dev/sda",id="/"} ${reads(2_000_000 + options.tick * 100_000)} ${at}`,
  );

  options.pods.forEach((pod, index) => {
    const cgroup = `/kubepods/burstable/pod${pod.uid}`;
    const labels = `namespace="${pod.namespace}",pod="${pod.name}"`;
    // The pod-level cgroup slice: empty container label.
    out.push(
      `container_fs_reads_bytes_total{container="",device="/dev/sda",id="${cgroup}",image="",${labels}} ${reads(999_000_000)} ${at}`,
    );
    // The pause container.
    out.push(
      `container_fs_reads_bytes_total{container="POD",device="/dev/sda",id="${cgroup}/pause",image="registry.k8s.io/pause:3.9",${labels}} ${reads(888_000_000)} ${at}`,
    );

    for (const device of ["/dev/sda", "/dev/sdb"]) {
      out.push(
        `container_fs_reads_bytes_total{container="app",device="${device}",id="${cgroup}/app",image="ornek/app:1",name="k8s_app_${pod.name}",${labels}} ${reads(100_000 + options.tick * (1_000 + index))} ${at}`,
      );
      out.push(
        `container_fs_writes_bytes_total{container="app",device="${device}",id="${cgroup}/app",image="ornek/app:1",name="k8s_app_${pod.name}",${labels}} ${reads(50_000 + options.tick * (500 + index))} ${at}`,
      );
    }
    out.push(
      `container_cpu_cfs_periods_total{container="app",id="${cgroup}/app",image="ornek/app:1",name="k8s_app_${pod.name}",${labels}} ${1_000 + options.tick * 300} ${at}`,
    );
    // The base (700) is deliberately far from the per-tick increment (30): the
    // ratio of the TOTALS and the ratio of the DELTAS then differ by a factor
    // of five, so a test can tell which one the reader computed. With a base
    // proportional to the increment both would agree and the assertion would
    // measure nothing.
    out.push(
      `container_cpu_cfs_throttled_periods_total{container="app",id="${cgroup}/app",image="ornek/app:1",name="k8s_app_${pod.name}",${labels}} ${700 + options.tick * 30} ${at}`,
    );
  });

  // Families the filter must drop. A real endpoint carries hundreds of these.
  const noise = options.noise ?? options.pods.length * 20;
  for (let index = 0; index < noise; index += 1) {
    const pod = options.pods[index % Math.max(1, options.pods.length)];
    const labels = pod ? `namespace="${pod.namespace}",pod="${pod.name}"` : 'id="/"';
    out.push(`container_memory_working_set_bytes{container="app",${labels}} ${100_000 + index} ${at}`);
    out.push(`container_network_receive_packets_dropped_total{${labels}} 0 ${at}`);
    out.push(`container_spec_cpu_shares{container="app",${labels}} 1024 ${at}`);
  }
  out.push("");
  return out.join("\n");
}

/* ─── TLS material for the negative probe and the measurement harness ─────── */

export interface TlsFixture {
  /** The "cluster CA" the collector is configured with. */
  readonly ca: Buffer;
  /** A serving certificate signed by that CA — the well-configured kubelet. */
  readonly serverCert: Buffer;
  readonly serverKey: Buffer;
  /** A self-signed certificate — the kubeadm default, which must produce no data. */
  readonly rogueCert: Buffer;
  readonly rogueKey: Buffer;
}

/**
 * Builds a CA and two serving certificates with `openssl`.
 *
 * Generated rather than checked in. A committed private key in a PUBLIC
 * repository is a thing a security reader has to stop and evaluate every time
 * they meet it, and "it is only a test key" is a sentence that has to be
 * believed rather than verified. Generating costs a second per run and removes
 * the question.
 *
 * Node cannot issue an X.509 certificate on its own, so this depends on the
 * `openssl` binary. When it is missing the caller must SAY the measurement did
 * not happen — see the TLS tests, which fail loudly rather than passing quietly
 * (this repository's rule: a gate that cannot measure says so by name).
 */
export async function createTlsFixture(directory: string): Promise<TlsFixture> {
  const { execFile } = await import("node:child_process");
  const { readFile, writeFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { promisify } = await import("node:util");
  const run = promisify(execFile);
  const path = (name: string): string => join(directory, name);

  await writeFile(path("san.cnf"), "subjectAltName=IP:127.0.0.1\n", "utf8");

  await run("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", path("ca.key"), "-out", path("ca.crt"),
    "-days", "3650", "-subj", "/CN=yeke-test-ca",
  ]);
  await run("openssl", [
    "req", "-newkey", "rsa:2048", "-nodes",
    "-keyout", path("server.key"), "-out", path("server.csr"),
    "-subj", "/CN=127.0.0.1",
  ]);
  await run("openssl", [
    "x509", "-req", "-in", path("server.csr"),
    "-CA", path("ca.crt"), "-CAkey", path("ca.key"), "-CAcreateserial",
    "-out", path("server.crt"), "-days", "3650",
    "-extfile", path("san.cnf"),
  ]);
  await run("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", path("rogue.key"), "-out", path("rogue.crt"),
    "-days", "3650", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1",
  ]);

  return {
    ca: await readFile(path("ca.crt")),
    serverCert: await readFile(path("server.crt")),
    serverKey: await readFile(path("server.key")),
    rogueCert: await readFile(path("rogue.crt")),
    rogueKey: await readFile(path("rogue.key")),
  };
}

/** True when `openssl` can be executed; the TLS tests refuse to run without it. */
export async function opensslAvailable(): Promise<boolean> {
  try {
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    await promisify(execFile)("openssl", ["version"]);
    return true;
  } catch {
    return false;
  }
}
