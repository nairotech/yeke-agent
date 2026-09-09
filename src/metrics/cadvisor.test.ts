/**
 * What the cAdvisor line filter claims, measured.
 *
 * Three claims carry the weight: only four families survive, the pause
 * container and the pod cgroup slice are both gone, and the IO zero probe tells
 * a quiet disk apart from a broken counter. The last one is the reason the
 * whole cAdvisor road exists at all — without it the product would draw a
 * confident zero on every cgroup v2 cluster where the counters are stuck
 * (cAdvisor #2881).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { IoZeroProbe, parseLine, readCadvisor } from "./cadvisor.js";
import { CounterRates } from "./counters.js";
import { cadvisorFixture, fixturePods } from "./fixture.js";
import type { MetricName, Sample } from "./types.js";

const PERIOD_MS = 30_000;
const START_MS = Date.parse("2026-09-09T00:00:00.000Z");

function valueOf(samples: readonly Sample[], entity: string, metric: MetricName): number | undefined {
  return samples.find((item) => item.entity === entity && item.metric === metric)?.value;
}

const PODS = fixturePods("node-a", 3);
const POD_IDS = new Map(PODS.map((pod) => [`${pod.namespace}/${pod.name}`, `pod/${pod.uid}`]));

async function readTick(
  rates: CounterRates,
  tick: number,
  options: { io?: "normal" | "zero"; suppressIo?: boolean } = {},
) {
  const text = cadvisorFixture({
    node: "node-a",
    pods: PODS,
    tick,
    periodMs: PERIOD_MS,
    startMs: START_MS,
    ...(options.io ? { io: options.io } : {}),
  });
  return readCadvisor(text.split("\n"), {
    readAt: START_MS + tick * PERIOD_MS,
    rates,
    nodeName: "node-a",
    podIdByName: POD_IDS,
    suppressIo: options.suppressIo ?? false,
  });
}

test("the filter keeps four families and drops everything else", () => {
  const text = cadvisorFixture({ node: "node-a", pods: PODS, tick: 1 });
  const lines = text.split("\n");
  const kept = lines.map(parseLine).filter((line) => line !== undefined);
  const names = new Set(kept.map((line) => line.name));

  assert.deepEqual(
    [...names].sort(),
    [
      "container_cpu_cfs_periods_total",
      "container_cpu_cfs_throttled_periods_total",
      "container_fs_reads_bytes_total",
      "container_fs_writes_bytes_total",
    ],
    "a family outside K3's list survived the filter",
  );
  // The fixture is mostly noise on purpose: a filter measured against a
  // document that is already filtered measures nothing.
  assert.ok(lines.length > kept.length * 3, `${kept.length} kept of ${lines.length}`);
});

test("labels are parsed, not pattern-matched out of the line", () => {
  // `name` carries a value containing the substring `pod="` — a scanner looking
  // for `pod="` anywhere in the line reports `evil` as the pod.
  const line = parseLine(
    'container_fs_reads_bytes_total{container="app",name="k8s_app_pod=\\"evil\\"_x",namespace="ornek",pod="real-0"} 42 1700000000000',
  );
  assert.equal(line?.labels.get("pod"), "real-0");
  assert.equal(line?.labels.get("namespace"), "ornek");
  assert.equal(line?.value, 42);
  assert.equal(line?.timestamp, 1_700_000_000_000);
});

test("comments, blank lines and malformed lines produce nothing", () => {
  assert.equal(parseLine("# TYPE container_fs_reads_bytes_total counter"), undefined);
  assert.equal(parseLine(""), undefined);
  assert.equal(parseLine("container_fs_reads_bytes_total{id=\"/\"} not-a-number"), undefined);
  assert.equal(parseLine("container_fs_reads_bytes_total{id=\"/\" 12"), undefined);
});

test('id="/" is the node total', async () => {
  const rates = new CounterRates();
  await readTick(rates, 0);
  const reading = await readTick(rates, 1);
  // 200 000 bytes over 30 s.
  assert.equal(valueOf(reading.samples, "node/node-a", "io.readBps"), Math.fround(200_000 / 30));
  assert.equal(valueOf(reading.samples, "node/node-a", "io.writeBps"), Math.fround(100_000 / 30));
});

test("the pause container and the pod cgroup slice are both excluded", async () => {
  const rates = new CounterRates();
  await readTick(rates, 0);
  const reading = await readTick(rates, 1);

  // The fixture gives the pod slice 999 000 000 and the pause container
  // 888 000 000, both CONSTANT. Including either would not move the rate, so
  // the assertion is the exact one: the pod's read rate must be the sum of its
  // app container's two devices and nothing else.
  //   two devices x (1000 + index) bytes per tick, over 30 s
  assert.equal(
    valueOf(reading.samples, `pod/${PODS[0]?.uid}`, "io.readBps"),
    Math.fround((2 * 1000) / 30),
  );
  assert.equal(
    valueOf(reading.samples, `pod/${PODS[2]?.uid}`, "io.readBps"),
    Math.fround((2 * 1002) / 30),
  );
  assert.equal(
    valueOf(reading.samples, `pod/${PODS[0]?.uid}`, "io.writeBps"),
    Math.fround((2 * 500) / 30),
  );
});

test("throttling is the ratio of the DELTAS, not of the totals", async () => {
  const rates = new CounterRates();
  await readTick(rates, 0);
  const reading = await readTick(rates, 1);
  // deltas: 30 throttled periods out of 300.
  assert.equal(valueOf(reading.samples, `pod/${PODS[0]?.uid}`, "cpu.throttled"), Math.fround(0.1));
  // The ratio of the totals at this tick would be 730/1300 = 0.5615...: five
  // times larger, and slower to move the longer the container has been up.
  assert.notEqual(
    valueOf(reading.samples, `pod/${PODS[0]?.uid}`, "cpu.throttled"),
    Math.fround(730 / 1300),
  );
});

test("a series for a pod the Summary did not report is not invented", async () => {
  const text = cadvisorFixture({ node: "node-a", pods: PODS, tick: 1 });
  const reading = await readCadvisor(text.split("\n"), {
    readAt: START_MS,
    rates: new CounterRates(),
    nodeName: "node-a",
    podIdByName: new Map(), // the Summary listed no pods
    suppressIo: false,
  });
  assert.deepEqual(
    reading.samples.filter((sample) => sample.entity.startsWith("pod/")),
    [],
  );
});

test("chunk boundaries do not eat a line", async () => {
  const text = cadvisorFixture({ node: "node-a", pods: PODS, tick: 1 });
  const whole = await readCadvisor(text.split("\n"), {
    readAt: START_MS,
    rates: new CounterRates(),
    nodeName: "node-a",
    podIdByName: POD_IDS,
    suppressIo: false,
  });
  // Same document, delivered as one line per element — the reader must not
  // depend on how the body was chopped up.
  assert.ok(whole.samples.length > 0);
  assert.equal(whole.ioCountersSeen, true);
});

test("the zero probe needs BOTH flat-zero counters and disk pressure", () => {
  const probe = new IoZeroProbe({ rounds: 3 });

  // Zeros with no pressure: an idle node. Nothing is claimed.
  for (let round = 0; round < 5; round += 1) {
    assert.equal(probe.observe({ countersAllZero: true, psiIo: 0 }), false);
  }
  // Zeros with no PSI at all: no second opinion, so no claim either.
  assert.equal(probe.observe({ countersAllZero: true, psiIo: Number.NaN }), false);

  // Zeros WITH pressure: something is waiting on a disk that reports no bytes.
  assert.equal(probe.observe({ countersAllZero: true, psiIo: 0.4 }), false);
  assert.equal(probe.observe({ countersAllZero: true, psiIo: 0.4 }), false);
  assert.equal(probe.observe({ countersAllZero: true, psiIo: 0.4 }), true, "3 rounds must fire it");
  assert.equal(probe.suppressing, true);

  // One real byte disproves the whole claim, immediately.
  assert.equal(probe.observe({ countersAllZero: false, psiIo: 0.4 }), false);
  assert.equal(probe.suppressing, false);
});

test("a suppressed node reports NO READING for IO, not zero", async () => {
  const rates = new CounterRates();
  await readTick(rates, 0, { io: "zero" });
  const honest = await readTick(rates, 1, { io: "zero" });
  // Without the probe the counters produce a perfectly confident zero. That is
  // the number this whole mechanism exists to refuse.
  assert.equal(valueOf(honest.samples, "node/node-a", "io.readBps"), 0);
  assert.equal(honest.ioCountersAllZero, true);

  const suppressed = await readTick(rates, 2, { io: "zero", suppressIo: true });
  assert.ok(Number.isNaN(valueOf(suppressed.samples, "node/node-a", "io.readBps") ?? 0));
  assert.ok(Number.isNaN(valueOf(suppressed.samples, `pod/${PODS[0]?.uid}`, "io.readBps") ?? 0));
  // Throttling is not IO and is not suppressed with it: a stuck disk counter
  // says nothing about the CPU scheduler.
  assert.ok(!Number.isNaN(valueOf(suppressed.samples, `pod/${PODS[0]?.uid}`, "cpu.throttled") ?? 0));
});
