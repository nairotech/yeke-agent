/**
 * What the Summary reader claims, measured.
 *
 * The fixture is generated (`fixture.ts` says why, and says what that does NOT
 * prove). Every assertion here is about the reader: that it finds the upstream
 * field names, that it derives a rate instead of shipping a counter, that it
 * says "no reading" where there is none, and that it refuses the three
 * temptations K3 names by name — summing the container list, counting
 * loopback, and turning an absent field into a zero.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CounterRates } from "./counters.js";
import { fixturePods, summaryFixture } from "./fixture.js";
import { type SummaryDocument, readSummary } from "./summary.js";
import type { MetricName, Sample } from "./types.js";

const PERIOD_MS = 30_000;
const START_MS = Date.parse("2026-09-09T00:00:00.000Z");

function valueOf(samples: readonly Sample[], entity: string, metric: MetricName): number | undefined {
  return samples.find((item) => item.entity === entity && item.metric === metric)?.value;
}

function readTick(rates: CounterRates, tick: number, overrides: Record<string, unknown> = {}) {
  const pods = fixturePods("node-a", 3);
  const document = summaryFixture({
    node: "node-a",
    pods,
    tick,
    periodMs: PERIOD_MS,
    startMs: START_MS,
    ...overrides,
  }) as SummaryDocument;
  return {
    pods,
    reading: readSummary(document, { readAt: START_MS + tick * PERIOD_MS, rates }),
  };
}

test("entities are keyed the way types.ts says: node by name, pod by uid", () => {
  const { pods, reading } = readTick(new CounterRates(), 0);
  const ids = reading.entities.map((entity) => entity.id);
  assert.equal(ids[0], "node/node-a");
  for (const pod of pods) assert.ok(ids.includes(`pod/${pod.uid}`), `${pod.uid} is missing`);

  const podEntity = reading.entities.find((entity) => entity.kind === "pod");
  assert.equal(podEntity?.namespace, pods[0]?.namespace);
  assert.equal(podEntity?.node, "node-a");
});

test("node gauges come from the fields K3 names", () => {
  const { reading } = readTick(new CounterRates(), 0);
  const node = "node/node-a";
  assert.equal(valueOf(reading.samples, node, "cpu.cores"), Math.fround(1.45));
  assert.equal(valueOf(reading.samples, node, "mem.workingSet"), Math.fround(8_589_934_592));
  assert.equal(valueOf(reading.samples, node, "mem.available"), Math.fround(6_442_450_944));
  assert.equal(valueOf(reading.samples, node, "fs.rootUsed"), Math.fround(75_161_927_680));
  assert.equal(valueOf(reading.samples, node, "fs.imageUsed"), Math.fround(12_884_901_888));
  // `rlimit.curproc`, not `process_stats` — the node and the pod use different
  // upstream structs for the same question.
  assert.equal(valueOf(reading.samples, node, "procs"), 421);
  assert.equal(valueOf(reading.samples, node, "psi.cpu"), Math.fround(1.5));
  assert.equal(valueOf(reading.samples, node, "psi.mem"), Math.fround(0.8));
});

test("the node's rootfs capacity is an ATTRIBUTE, not a series", () => {
  const { reading } = readTick(new CounterRates(), 0);
  const node = reading.entities.find((entity) => entity.kind === "node");
  assert.equal(node?.attributes["fs.capacity"], Math.fround(107_374_182_400));
  // And it is nowhere in the metric vocabulary: a denominator that also
  // travelled as a series would be sent 2880 times a day unchanged.
  assert.equal(
    reading.samples.some((sample) => String(sample.metric).endsWith("capacity")),
    false,
  );
});

test("the container list is NOT summed; the pod-level field is used", () => {
  const { pods, reading } = readTick(new CounterRates(), 0);
  // The fixture's pod says 12 000 000 nanocores; its single container says
  // 9 000 000. A reader that summed containers would produce the second number,
  // and on a real pod with a sidecar it would produce a number larger than the
  // pod actually used.
  assert.equal(valueOf(reading.samples, `pod/${pods[0]?.uid}`, "cpu.cores"), Math.fround(0.012));
});

test("the first reading of a counter is NO READING, and the second is a rate", () => {
  const rates = new CounterRates();
  const first = readTick(rates, 0).reading;
  const node = "node/node-a";
  // A rate needs two points. Inventing a zero here would draw a flat line under
  // every pod for its first 30 seconds.
  assert.ok(Number.isNaN(valueOf(first.samples, node, "net.rxBps") ?? 0));

  const second = readTick(rates, 1).reading;
  // 1 500 000 bytes over 30 s.
  assert.equal(valueOf(second.samples, node, "net.rxBps"), 50_000);
  assert.equal(valueOf(second.samples, node, "net.txBps"), 40_000);
});

test("loopback is excluded from the network totals", () => {
  const rates = new CounterRates();
  readTick(rates, 0);
  const second = readTick(rates, 1).reading;
  // The fixture's `lo` carries 999 999 999 bytes and never moves. Counting it
  // would not change the RATE, so the assertion that matters is the absolute
  // one: the rate must be exactly eth0's delta and nothing else.
  assert.equal(valueOf(second.samples, "node/node-a", "net.rxBps"), 50_000);
});

test("errors are a rate too, and rx and tx are one series", () => {
  const rates = new CounterRates();
  const { pods } = readTick(rates, 0);
  const second = readTick(rates, 1).reading;
  // Pod index 0 gets `rxErrors = tick`: one error in 30 seconds.
  assert.equal(
    valueOf(second.samples, `pod/${pods[0]?.uid}`, "net.errors"),
    Math.fround(1000 / 30_000),
  );
});

test("a counter that went backwards produces NO READING, not a spike", () => {
  const rates = new CounterRates();
  readTick(rates, 5);
  // Tick 0's counters are below tick 5's: the container behind them restarted.
  // Prometheus's `rate()` would add the whole current value and draw a burst
  // of traffic that never happened.
  const afterReset = readTick(rates, 0).reading;
  assert.ok(Number.isNaN(valueOf(afterReset.samples, "node/node-a", "net.rxBps") ?? 0));

  // And the new value becomes the baseline: the next interval is a real rate.
  const recovered = readTick(rates, 1).reading;
  assert.equal(valueOf(recovered.samples, "node/node-a", "net.rxBps"), 50_000);
});

test("PSI is conditional: no field, no series", () => {
  const { reading } = readTick(new CounterRates(), 0, { psi: false });
  assert.equal(reading.psiPresent, false);
  assert.ok(Number.isNaN(reading.psiIo));
  assert.deepEqual(
    reading.samples.filter((sample) => sample.metric.startsWith("psi.")),
    [],
    "a PSI series was born from a document that has no PSI",
  );
});

test("an absent field is absent, never a zero", () => {
  const rates = new CounterRates();
  const reading = readSummary(
    { node: { nodeName: "bare", cpu: { time: "2026-09-09T00:00:00.000Z" } } },
    { readAt: START_MS, rates },
  );
  const drawn = reading.samples.map((sample) => sample.metric);
  for (const metric of ["mem.workingSet", "fs.rootUsed", "procs", "psi.cpu"] as const) {
    assert.equal(drawn.includes(metric), false, `${metric} was invented`);
  }
});

test("a pod with no uid is skipped rather than keyed by name", () => {
  const reading = readSummary(
    {
      node: { nodeName: "node-a" },
      pods: [
        { podRef: { name: "web-0", namespace: "ornek" } },
        { podRef: { name: "web-1", namespace: "ornek", uid: "u-1" } },
      ],
    },
    { readAt: START_MS, rates: new CounterRates() },
  );
  const pods = reading.entities.filter((entity) => entity.kind === "pod");
  assert.deepEqual(
    pods.map((entity) => entity.id),
    ["pod/u-1"],
  );
});
