/**
 * Measurement harness for the collector: 50 fake kubelets, real HTTP, real TLS.
 *
 * ─── What is being measured, and what is not ────────────────────────────────
 *
 * The roof document's section 8 sets two numbers for this component: at 50
 * nodes and 1500 pods the collector must cost at most 50 millicores on average
 * and 64 MiB of RSS with a full ring. Those are the numbers this harness
 * produces.
 *
 * It measures the COLLECTOR. It does not measure a kubelet, a cluster, or a
 * network: the fixtures are generated (`fixture.ts` says what that does and
 * does not prove) and everything runs on the loopback interface. A live cluster
 * is the only thing that can confirm the shape of a real Summary document, and
 * K3 lists that as one of Phase 1's open measurements.
 *
 * ─── Why the fake kubelets run in a SEPARATE process ────────────────────────
 *
 * Serving 50 Summary documents and 50 cAdvisor texts every 30 seconds costs
 * more CPU than reading them. Run in the same process, that cost lands in
 * `process.cpuUsage()` and the harness would report the fixture generator's
 * appetite as the collector's. The servers are therefore forked; the parent
 * measures only itself. This is the difference between a measurement and a
 * number.
 *
 * Two runs, because the two targets are in tension:
 *
 *  · DRAIN — the sink accepts every frame. Average CPU over wall-clock time.
 *  · FILL  — the sink is never ready, so the ring reaches its 60-frame ceiling.
 *    Peak RSS. This is the state the memory target is about: an agent that has
 *    been disconnected for half an hour.
 *
 * Usage (from the repository root, after `pnpm build` is not required -- it
 * runs under tsx too):
 *
 *   pnpm exec tsx src/metrics/measure.ts --nodes 50 --pods 30 --minutes 5
 */
import { fork } from "node:child_process";
import { createServer, type Server } from "node:https";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type { AddressInfo } from "node:net";
import { Collector } from "./collector.js";
import { type FixturePod, cadvisorFixture, createTlsFixture, fixturePods, summaryFixture } from "./fixture.js";
import { KubeletClient } from "./kubelet-client.js";
import type { InternalFrame, SampleSink } from "./types.js";
import type { KubeTarget } from "../kube.js";

interface Argv {
  nodes: number;
  pods: number;
  minutes: number;
  periodMs: number;
}

function parseArgv(argv: readonly string[]): Argv {
  const read = (name: string, fallback: number): number => {
    const index = argv.indexOf(`--${name}`);
    if (index < 0) return fallback;
    return Number(argv[index + 1] ?? fallback);
  };
  return {
    nodes: read("nodes", 50),
    pods: read("pods", 30),
    minutes: read("minutes", 5),
    periodMs: read("period", 30_000),
  };
}

/* ─── Child: the fake kubelets ─────────────────────────────────────────────── */

interface ServeRequest {
  readonly nodes: number;
  readonly pods: number;
  readonly certPath: string;
  readonly keyPath: string;
  readonly periodMs: number;
}

async function serve(config: ServeRequest): Promise<void> {
  const { readFile } = await import("node:fs/promises");
  const cert = await readFile(config.certPath);
  const key = await readFile(config.keyPath);
  const startMs = Date.parse("2026-09-09T00:00:00.000Z");
  const ports: { node: string; port: number }[] = [];

  for (let index = 0; index < config.nodes; index += 1) {
    const name = `node-${String(index).padStart(3, "0")}`;
    const pods: FixturePod[] = fixturePods(name, config.pods);
    // The tick advances per request pair so counters move and the collector
    // derives real rates rather than a stream of NO READING.
    let requests = 0;
    const server: Server = createServer({ cert, key }, (req, res) => {
      const tick = Math.floor(requests / 2);
      requests += 1;
      if (req.url === "/stats/summary") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            summaryFixture({ node: name, pods, tick, periodMs: config.periodMs, startMs }),
          ),
        );
        return;
      }
      if (req.url === "/metrics/cadvisor") {
        res.writeHead(200, { "content-type": "text/plain" });
        res.end(cadvisorFixture({ node: name, pods, tick, periodMs: config.periodMs, startMs }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    ports.push({ node: name, port: (server.address() as AddressInfo).port });
  }

  process.send?.({ ports });
}

/* ─── Parent: the collector under measurement ──────────────────────────────── */

class CountingSink implements SampleSink {
  ready: boolean;
  busy = false;
  frames = 0;
  /**
   * Two wire estimates, because K5's frame has two halves and only one of them
   * repeats.
   *
   * `steadyBytes` is the binary frame: four bytes per value, which is what a
   * frame costs once the control plane already knows the entities. `firstBytes`
   * adds a budget for the entity dictionary, which K5 sends as a DELTA -- so it
   * is paid in full once and then only for pods that came or went.
   */
  steadyBytes = 0;
  firstBytes = 0;

  constructor(ready: boolean) {
    this.ready = ready;
  }

  push(frame: InternalFrame): boolean {
    if (!this.ready) return false;
    this.frames += 1;
    this.steadyBytes += frame.values.length * 4;
    this.firstBytes += frame.values.length * 4 + frame.layout.entities.length * 120;
    return true;
  }
}

const NO_APISERVER: KubeTarget = {
  baseUrl: "https://127.0.0.1:1",
  authHeaders: async () => ({}),
  dispatcher: undefined as never,
  tlsOptions: () => ({ rejectUnauthorized: true }),
  invalidateCredential: () => undefined,
  close: async () => undefined,
};

function millicores(cpu: NodeJS.CpuUsage, wallMs: number): number {
  const cpuMs = (cpu.user + cpu.system) / 1000;
  return (cpuMs / wallMs) * 1000;
}

function mib(bytes: number): number {
  return bytes / 1024 ** 2;
}

/**
 * Live memory is NOT measured here, and that is a decision with a measurement
 * behind it.
 *
 * The obvious way to separate the collector's live set from the heap V8 has not
 * handed back is to force a collection and read `heapUsed`. That needs
 * `globalThis.gc`, which needs either `--expose-gc` on the command line or
 * `v8.setFlagsFromString` at runtime. MEASURED (09.09.2026, this machine):
 * with `NODE_OPTIONS=--expose-gc` the harness stopped making progress at 10 and
 * 50 nodes -- the process sat under two seconds of CPU for 27 minutes -- and
 * flipping the flag from inside the process reproduced the same stall. The
 * identical runs without it completed. The cause was not established.
 *
 * What replaces it is better for the question actually being asked. The 64 MiB
 * target is about what the 30-minute ring HOLDS, and `SampleRing.retained()`
 * counts that exactly: the bytes of every `Float32Array` in the ring, plus how
 * many distinct layout objects those frames share. No collector, no
 * approximation, and no dependence on when V8 feels like sweeping. RSS is
 * printed beside it as the high-water mark, which is the number a container
 * memory limit has to respect.
 */

async function main(): Promise<void> {
  const argv = parseArgv(process.argv.slice(2));
  const directory = await mkdtemp(join(tmpdir(), "yeke-measure-"));
  const fixture = await createTlsFixture(directory);

  const child = fork(fileURLToPath(import.meta.url), ["--serve"], { stdio: "inherit" });
  const ports = await new Promise<{ node: string; port: number }[]>((resolve, reject) => {
    child.once("message", (message) => resolve((message as { ports: typeof ports }).ports));
    child.once("error", reject);
    child.send({
      nodes: argv.nodes,
      pods: argv.pods,
      certPath: join(directory, "server.crt"),
      keyPath: join(directory, "server.key"),
      periodMs: argv.periodMs,
    } satisfies ServeRequest);
  });

  const kubelet = new KubeletClient({
    token: { read: async () => "measurement-token", invalidate: () => undefined },
    ca: fixture.ca,
    insecureTls: false,
  });

  const build = (sink: SampleSink, periodMs: number): Collector => {
    const collector = new Collector({ target: NO_APISERVER, kubelet, sink, periodMs });
    for (const entry of ports) {
      collector.seedNode({
        name: entry.node,
        address: "127.0.0.1",
        port: entry.port,
        ready: true,
        attributes: { "cpu.allocatable": 4, "mem.allocatable": 16 * 1024 ** 3 },
      });
    }
    return collector;
  };

  console.log(
    `[measure] ${argv.nodes} kubelets x ${argv.pods} pods, period ${argv.periodMs} ms, ` +
      `${argv.minutes} minute(s); servers in pid ${child.pid}`,
  );

  /* Run A -- DRAIN: average CPU over wall-clock time. */
  const drainSink = new CountingSink(true);
  const drain = build(drainSink, argv.periodMs);
  // One warm-up tick outside the measurement: the first reading of every
  // counter produces no rate, so it is not a representative tick and it also
  // pays for every TLS handshake at once.
  await drain.tick();
  // The baseline is taken after the client and the collector exist but before
  // anything has been collected. The target in the roof document is the agent's
  // ADDITIONAL memory, so the number that matters is the delta; the absolute is
  // printed beside it because a delta with no baseline cannot be checked.
  const baselineRss = process.memoryUsage().rss;

  const startCpu = process.cpuUsage();
  const startWall = Date.now();
  let peakRssDrain = process.memoryUsage().rss;
  const ticks = Math.max(1, Math.round((argv.minutes * 60_000) / argv.periodMs));
  for (let index = 0; index < ticks; index += 1) {
    const tickStart = Date.now();
    // Progress goes to stderr, one line per tick: a harness that prints only at
    // the end is a harness you cannot tell apart from a hung one.
    process.stderr.write(`[measure] drain tick ${index + 1}/${ticks}\n`);
    await drain.tick();
    peakRssDrain = Math.max(peakRssDrain, process.memoryUsage().rss);
    const remaining = argv.periodMs - (Date.now() - tickStart);
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  }
  const drainCpu = process.cpuUsage(startCpu);
  const drainWall = Date.now() - startWall;
  const drainStats = drain.stats();
  await drain.stop();

  /* Run B -- FILL: peak RSS with the ring at its ceiling. */
  const fillSink = new CountingSink(false);
  const fill = build(fillSink, argv.periodMs);
  let peakRssFill = 0;
  // The ring's capacity, driven as fast as the fake kubelets answer: the target
  // is about how much memory 30 minutes of frames occupy, not about how long
  // they took to arrive.
  for (let index = 0; index < 60; index += 1) {
    if (index % 10 === 0) process.stderr.write(`[measure] fill tick ${index + 1}/60\n`);
    await fill.tick();
    peakRssFill = Math.max(peakRssFill, process.memoryUsage().rss);
  }
  const fillStats = fill.stats();
  await fill.stop();

  const perFrameSteady = drainSink.frames > 0 ? drainSink.steadyBytes / drainSink.frames : 0;
  const perFrameFirst = drainSink.frames > 0 ? drainSink.firstBytes / drainSink.frames : 0;
  const lines = [
    "",
    "=== collector measurement =======================================",
    `nodes                 ${argv.nodes}`,
    `pods per node         ${argv.pods}  (total ${argv.nodes * argv.pods})`,
    `period                ${argv.periodMs} ms`,
    "",
    "--- run A: sink draining ---------------------------------------",
    `wall clock            ${(drainWall / 1000).toFixed(1)} s over ${ticks} ticks`,
    `cpu (user+sys)        ${((drainCpu.user + drainCpu.system) / 1000).toFixed(0)} ms`,
    `cpu average           ${millicores(drainCpu, drainWall).toFixed(1)} m   (target <= 50m)` +
      (argv.periodMs === 30_000
        ? ""
        : "  <- NOT COMPARABLE: the average divides by wall time, so only the production 30000 ms period gives the figure the target is about"),
    `cpu per tick          ${((drainCpu.user + drainCpu.system) / 1000 / ticks).toFixed(0)} ms` +
      `  (= ${(((drainCpu.user + drainCpu.system) / 1000 / ticks) / 30_000 * 1000).toFixed(1)} m at a 30 s period)`,
    `rss high water        ${mib(peakRssDrain).toFixed(1)} MiB absolute, ` +
      `${mib(peakRssDrain - baselineRss).toFixed(1)} MiB above baseline (${mib(baselineRss).toFixed(1)} MiB)`,
    `entities per frame    ${drainStats.entitiesLastFrame}`,
    `samples per frame     ${drainStats.samplesLastFrame}`,
    `frames to the sink    ${drainSink.frames}`,
    `frame, steady state   ${(perFrameSteady / 1024).toFixed(1)} KiB (values only, uncompressed)`,
    `frame, dictionary too ${(perFrameFirst / 1024).toFixed(1)} KiB (values + every entity; K5 sends the dictionary as a delta)`,
    "",
    "--- run B: sink down, ring at its ceiling ----------------------",
    `frames held           ${fillStats.ringSize} of ${60}`,
    `frames dropped        ${fillStats.droppedPending}`,
    `rss high water        ${mib(peakRssFill).toFixed(1)} MiB absolute, ` +
      `${mib(peakRssFill - baselineRss).toFixed(1)} MiB above baseline`,
    `ring holds            ${mib(fillStats.ringValueBytes).toFixed(1)} MiB of sample values (exact), ` +
      `${fillStats.ringLayouts} distinct layout(s)   (target <= 64 MiB)`,
    "",
    "NOT MEASURED: no live kubelet, no live apiserver, no cluster network.",
    "The fixtures are generated to the upstream shape; a real Summary document",
    "may differ in size and in which optional fields it carries. The baseline",
    "also carries this harness itself (TLS material, the fork, the runner), so",
    "the delta is an upper bound on the collector's own cost, not a floor.",
    "================================================================",
    "",
  ];
  console.log(lines.join("\n"));

  await kubelet.close();
  child.kill();
  await rm(directory, { recursive: true, force: true });
}

if (process.argv.includes("--serve")) {
  process.once("message", (message) => {
    void serve(message as ServeRequest);
  });
} else {
  main().catch((err) => {
    console.error(`[measure] failed: ${(err as Error).message}`);
    process.exit(1);
  });
}
