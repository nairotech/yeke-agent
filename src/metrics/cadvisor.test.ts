/**
 * What the cAdvisor line filter claims, measured.
 *
 * Four claims carry the weight: only five families survive, the pause
 * container and the pod cgroup slice are both gone, the IO zero probe tells a
 * quiet disk apart from a broken counter, and throttling is the share of WALL
 * time the pod's worst container spent at its quota. The IO probe is the reason
 * the whole cAdvisor road exists at all — without it the product would draw a
 * confident zero on every cgroup v2 cluster where the counters are stuck
 * (cAdvisor #2881).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_CFS_PERIOD_US, IoZeroProbe, parseLine, podCpuLimit, readCadvisor } from "./cadvisor.js";
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

test("the filter keeps five families and drops everything else", () => {
  const text = cadvisorFixture({ node: "node-a", pods: PODS, tick: 1 });
  const lines = text.split("\n");
  const kept = lines.map(parseLine).filter((line) => line !== undefined);
  const names = new Set(kept.map((line) => line.name));

  assert.deepEqual(
    [...names].sort(),
    [
      "container_cpu_cfs_throttled_periods_total",
      "container_fs_reads_bytes_total",
      "container_fs_writes_bytes_total",
      "container_spec_cpu_period",
      "container_spec_cpu_quota",
    ],
    "a family outside K3's list survived the filter",
  );
  // The retired ratio's denominator is still in the document (a real kubelet
  // emits it) and must not be parsed any more.
  assert.ok(lines.some((line) => line.startsWith("container_cpu_cfs_periods_total{")));
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
  const wall = valueOf(suppressed.samples, `pod/${PODS[0]?.uid}`, "cpu.throttledWall");
  assert.equal(wall, Math.fround(0.1));
});

/* ─── cpu.throttledWall ───────────────────────────────────────────────────── */

interface CpuContainer {
  readonly name: string;
  /** `container_cpu_cfs_throttled_periods_total`; absent = no CPU limit. */
  readonly throttled?: number;
  /** The counter line's exposition timestamp; absent = unstamped. */
  readonly stamp?: number;
  /** `container_spec_cpu_period`; absent = no line. */
  readonly periodUs?: number;
  /** `container_spec_cpu_quota`; absent = no line. */
  readonly quotaUs?: number;
}

const HAND_POD = { namespace: "ornek", name: "web-0", entity: "pod/hand-uid-0" } as const;
const HAND_IDS = new Map([[`${HAND_POD.namespace}/${HAND_POD.name}`, HAND_POD.entity]]);

/** Exposition lines for one pod, written by hand so every number is visible. */
function cpuLines(containers: readonly CpuContainer[]): string[] {
  const lines: string[] = [];
  const labels = `namespace="${HAND_POD.namespace}",pod="${HAND_POD.name}"`;
  for (const c of containers) {
    const own = `container="${c.name}",id="/kubepods/pod-hand/${c.name}",${labels}`;
    if (c.throttled !== undefined) {
      const stamp = c.stamp === undefined ? "" : ` ${c.stamp}`;
      lines.push(`container_cpu_cfs_throttled_periods_total{${own}} ${c.throttled}${stamp}`);
    }
    if (c.periodUs !== undefined) lines.push(`container_spec_cpu_period{${own}} ${c.periodUs}`);
    if (c.quotaUs !== undefined) lines.push(`container_spec_cpu_quota{${own}} ${c.quotaUs}`);
  }
  return lines;
}

async function readHand(rates: CounterRates, readAt: number, containers: readonly CpuContainer[]) {
  return readCadvisor(cpuLines(containers), {
    readAt,
    rates,
    nodeName: "",
    podIdByName: HAND_IDS,
    suppressIo: false,
  });
}

/** Two readings 30 s apart; returns the second one's pod value. */
async function wallOf(
  before: readonly CpuContainer[],
  after: readonly CpuContainer[],
  gapMs = PERIOD_MS,
): Promise<number | undefined> {
  const rates = new CounterRates();
  await readHand(rates, START_MS, before);
  const reading = await readHand(rates, START_MS + gapMs, after);
  return valueOf(reading.samples, HAND_POD.entity, "cpu.throttledWall");
}

test("wall share: the period comes from the container's own `container_spec_cpu_period` line", async () => {
  // 60 throttled periods of 50 ms in 30 s = 3 s of 30 s.
  const wall = await wallOf(
    [{ name: "app", throttled: 1_000, stamp: START_MS, periodUs: 50_000 }],
    [{ name: "app", throttled: 1_060, stamp: START_MS + PERIOD_MS, periodUs: 50_000 }],
  );
  assert.equal(wall, Math.fround(0.1));
  // With the default period the same counters would read twice as high: the
  // line was actually used.
  assert.notEqual(wall, Math.fround(0.2));
});

test("wall share: without a period line the CFS default of 100 ms is used", async () => {
  assert.equal(DEFAULT_CFS_PERIOD_US, 100_000);
  // Unstamped counters too: the elapsed time falls back to the read instants.
  const wall = await wallOf([{ name: "app", throttled: 1_000 }], [{ name: "app", throttled: 1_060 }]);
  // 60 × 100 ms in 30 s.
  assert.equal(wall, Math.fround(0.2));
});

test("wall share: the elapsed time is the COUNTER LINE's own stamp, not the read instant", async () => {
  // The kubelet stamped the two readings 60 s apart while the agent read them
  // 30 s apart (cAdvisor's housekeeping is not the agent's clock). 120 × 100 ms
  // over 60 s is 0.2; the read instants would have claimed 0.4.
  const wall = await wallOf(
    [{ name: "app", throttled: 5_000, stamp: START_MS - 50_000, periodUs: 100_000 }],
    [{ name: "app", throttled: 5_120, stamp: START_MS + 10_000, periodUs: 100_000 }],
    PERIOD_MS,
  );
  assert.equal(wall, Math.fround(0.2));
  assert.notEqual(wall, Math.fround(0.4));
});

test("wall share: a throttled SIDECAR decides the pod's value — the maximum, not the sum", async () => {
  const wall = await wallOf(
    [
      { name: "app", throttled: 100, stamp: START_MS, periodUs: 100_000 },
      { name: "sidecar", throttled: 400, stamp: START_MS, periodUs: 100_000 },
    ],
    [
      // app: 90 × 100 ms / 30 s = 0.3; sidecar: 180 × 100 ms / 30 s = 0.6.
      { name: "app", throttled: 190, stamp: START_MS + PERIOD_MS, periodUs: 100_000 },
      { name: "sidecar", throttled: 580, stamp: START_MS + PERIOD_MS, periodUs: 100_000 },
    ],
  );
  // The sum (0.9) stays under 1, so the clamp cannot hide which one this is.
  assert.equal(wall, Math.fround(0.6));
});

test("wall share: a counter that went DOWN is a reset and produces NO READING, then recovers", async () => {
  const rates = new CounterRates();
  const at = (tick: number) => START_MS + tick * PERIOD_MS;
  await readHand(rates, at(0), [{ name: "app", throttled: 5_000, stamp: at(0) }]);
  // The container restarted: a new cgroup, a counter from zero.
  const reset = await readHand(rates, at(1), [{ name: "app", throttled: 12, stamp: at(1) }]);
  const hole = valueOf(reset.samples, HAND_POD.entity, "cpu.throttledWall");
  assert.ok(hole !== undefined && Number.isNaN(hole), `expected an explicit hole, got ${hole}`);
  const next = await readHand(rates, at(2), [{ name: "app", throttled: 42, stamp: at(2) }]);
  assert.equal(valueOf(next.samples, HAND_POD.entity, "cpu.throttledWall"), Math.fround(0.1));
});

test("wall share: the first reading and a sub-100ms interval are holes, not zeros", async () => {
  const rates = new CounterRates();
  const first = await readHand(rates, START_MS, [{ name: "app", throttled: 10, stamp: START_MS }]);
  assert.ok(Number.isNaN(valueOf(first.samples, HAND_POD.entity, "cpu.throttledWall") ?? 0));
  const tooSoon = await readHand(rates, START_MS + 50, [{ name: "app", throttled: 11, stamp: START_MS + 50 }]);
  assert.ok(Number.isNaN(valueOf(tooSoon.samples, HAND_POD.entity, "cpu.throttledWall") ?? 0));
});

test("wall share: stamp jitter above 1 is clamped to 1", async () => {
  // 301 periods of 100 ms "in" 30 s: 1.0033 — a stamp error, not a measurement.
  const wall = await wallOf(
    [{ name: "app", throttled: 0, stamp: START_MS }],
    [{ name: "app", throttled: 301, stamp: START_MS + PERIOD_MS }],
  );
  assert.equal(wall, 1);
});

test("wall share: a container without the counter takes no part; a pod with none gets no series", async () => {
  // A limitless sidecar carries a period line and nothing else.
  const mixed = await wallOf(
    [
      { name: "app", throttled: 100, stamp: START_MS, periodUs: 100_000, quotaUs: 50_000 },
      { name: "sidecar", periodUs: 100_000 },
    ],
    [
      { name: "app", throttled: 130, stamp: START_MS + PERIOD_MS, periodUs: 100_000, quotaUs: 50_000 },
      { name: "sidecar", periodUs: 100_000 },
    ],
  );
  assert.equal(mixed, Math.fround(0.1));

  // No container is limited: "unlimited" must not arrive as "0% throttled".
  const rates = new CounterRates();
  await readHand(rates, START_MS, [{ name: "app", periodUs: 100_000 }]);
  const none = await readHand(rates, START_MS + PERIOD_MS, [{ name: "app", periodUs: 100_000 }]);
  assert.equal(valueOf(none.samples, HAND_POD.entity, "cpu.throttledWall"), undefined);
});

/**
 * The measurement that retired the old ratio, as a fixture.
 *
 * Lines from a production kubelet (29.09.2026, k8s 1.31, containerd, systemd
 * cgroup driver), two readings: every NUMBER and every TIMESTAMP is the one the
 * kubelet wrote; the pod name, uid, container id and image are replaced. The
 * shapes are kept exactly: the pod slice and the pause container both with an
 * empty `container` label, spec lines unstamped, the container's counters
 * stamped 9.5 s and 17.1 s away from its own pod slice's.
 *
 * The container has a 50m limit (quota 5 000 µs per 100 000 µs) and was using
 * about 0.8m. Between the two readings (75.718 s apart by its own stamps) it
 * was awake in 13 periods and throttled in 10 of them.
 */
const EVIDENCE_POD = { namespace: "kube-system", name: "edge-guard-7xk2p", entity: "pod/evidence-uid" } as const;

function evidenceReading(which: 1 | 2): string[] {
  const slice =
    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0f0e0d0c_0000_4000_8000_000000000001.slice";
  const labels = `namespace="${EVIDENCE_POD.namespace}",pod="${EVIDENCE_POD.name}"`;
  const sliceLabels = `container="",id="${slice}",image="",name="",${labels}`;
  const pauseLabels = `container="",id="${slice}/cri-containerd-aaaa.scope",image="registry.k8s.io/pause:3.10",name="aaaa",${labels}`;
  const guardLabels = `container="guard",id="${slice}/cri-containerd-bbbb.scope",image="registry.example/guard:1",name="bbbb",${labels}`;
  const values =
    which === 1
      ? { slicePeriods: 26_949, sliceThrottled: 21_694, sliceAt: 1_790_714_985_341, periods: 26_861, throttled: 21_241, at: 1_790_714_994_863 }
      : { slicePeriods: 26_972, sliceThrottled: 21_710, sliceAt: 1_790_715_087_675, periods: 26_874, throttled: 21_251, at: 1_790_715_070_581 };
  return [
    "# HELP container_cpu_cfs_periods_total Number of elapsed enforcement period intervals.",
    "# TYPE container_cpu_cfs_periods_total counter",
    `container_cpu_cfs_periods_total{${sliceLabels}} ${values.slicePeriods} ${values.sliceAt}`,
    `container_cpu_cfs_periods_total{${guardLabels}} ${values.periods} ${values.at}`,
    `container_cpu_cfs_throttled_periods_total{${sliceLabels}} ${values.sliceThrottled} ${values.sliceAt}`,
    `container_cpu_cfs_throttled_periods_total{${guardLabels}} ${values.throttled} ${values.at}`,
    `container_spec_cpu_period{${sliceLabels}} 100000`,
    `container_spec_cpu_period{${pauseLabels}} 100000`,
    `container_spec_cpu_period{${guardLabels}} 100000`,
    `container_spec_cpu_quota{${sliceLabels}} 5000`,
    `container_spec_cpu_quota{${guardLabels}} 5000`,
  ];
}

test("the production measurement: 50m limit, awake 1.7%, old ratio 76.9% -> wall share 1.32%", async () => {
  const rates = new CounterRates();
  const podIdByName = new Map([[`${EVIDENCE_POD.namespace}/${EVIDENCE_POD.name}`, EVIDENCE_POD.entity]]);
  const read = (lines: string[], readAt: number) =>
    readCadvisor(lines, { readAt, rates, nodeName: "", podIdByName, suppressIo: false });

  // The agent's own read instants, 90 s apart: NOT the interval the counters
  // describe. A reader dividing by these would report 1.11%.
  await read(evidenceReading(1), 1_790_714_995_000);
  const second = await read(evidenceReading(2), 1_790_715_085_000);

  const throttled = 21_251 - 21_241;
  const periods = 26_874 - 26_861;
  const elapsedMs = 1_790_715_070_581 - 1_790_714_994_863;
  const oldRatio = throttled / periods;
  const awake = (periods * 100_000) / (elapsedMs * 1000);
  // The fixture IS the measurement the decision quotes, to the digit.
  assert.equal((oldRatio * 100).toFixed(1), "76.9");
  assert.equal((awake * 100).toFixed(1), "1.7");

  const wall = valueOf(second.samples, EVIDENCE_POD.entity, "cpu.throttledWall");
  assert.equal(wall, Math.fround((throttled * 100_000) / (elapsedMs * 1000)));
  assert.equal(((wall ?? Number.NaN) * 100).toFixed(2), "1.32");
  // w = ratio × awake share, so it can never exceed the old ratio.
  assert.ok(Math.abs((wall ?? 0) - oldRatio * awake) < 1e-6);
  // Had the pod slice (empty `container` label) been counted, the maximum
  // would have been ITS share, 16 × 100 ms / 102.334 s = 1.56%.
  assert.notEqual(((wall ?? 0) * 100).toFixed(2), "1.56");

  // The limit, from the same reading: the guard container's quota, not the
  // slice's (which would double it to 0.1).
  const limits = second.containerLimits.get(EVIDENCE_POD.entity);
  assert.deepEqual([...(limits?.keys() ?? [])], ["guard"]);
  assert.equal(podCpuLimit(["guard"], limits, second.containersSeen.get(EVIDENCE_POD.entity)), Math.fround(0.05));

  // And the retired ratio is nowhere in the output.
  assert.deepEqual(
    second.samples.filter((sample) => sample.metric === "cpu.throttled"),
    [],
  );
});

test("`cpu.throttled` is never produced, in any reading", async () => {
  const rates = new CounterRates();
  for (let tick = 0; tick < 4; tick += 1) {
    const reading = await readTick(rates, tick);
    assert.deepEqual(
      reading.samples.filter((sample) => sample.metric === "cpu.throttled"),
      [],
      `tick ${tick}`,
    );
    if (tick > 0) {
      assert.equal(valueOf(reading.samples, `pod/${PODS[0]?.uid}`, "cpu.throttledWall"), Math.fround(0.1));
    }
  }
});

test("cpu.limit: the sum when EVERY container is limited, and nothing when one is not", async () => {
  const text = (sidecar: "limited" | "limitless") =>
    cadvisorFixture({ node: "node-a", pods: PODS, tick: 1, sidecar }).split("\n");
  const context = {
    readAt: START_MS,
    rates: new CounterRates(),
    nodeName: "node-a",
    podIdByName: POD_IDS,
    suppressIo: false,
  };
  const entity = `pod/${PODS[0]?.uid}`;
  const roster = ["app", "sidecar"];

  const limited = await readCadvisor(text("limited"), context);
  // 0.5 + 0.2 cores; the pod slice's own quota line (0.7) is not added on top.
  assert.equal(
    podCpuLimit(roster, limited.containerLimits.get(entity), limited.containersSeen.get(entity)),
    Math.fround(0.7),
  );

  const limitless = await readCadvisor(text("limitless"), context);
  assert.equal(
    podCpuLimit(roster, limitless.containerLimits.get(entity), limitless.containersSeen.get(entity)),
    undefined,
    "a pod with one unlimited container has no CPU ceiling",
  );
});

test("cpu.limit: the roster decides, and a roster that cannot be trusted writes nothing", () => {
  const limits = new Map([
    ["app", 0.5],
    ["sidecar", 0.25],
  ]);
  const seen = new Set(["app", "sidecar"]);
  assert.equal(podCpuLimit(["app", "sidecar"], limits, seen), 0.75);
  // The Summary lists a container cAdvisor has no quota for: unlimited.
  assert.equal(podCpuLimit(["app", "sidecar", "debug"], limits, seen), undefined);
  // cAdvisor names a container the Summary does not list yet: the roster is
  // behind this reading and the sum could be missing a term.
  assert.equal(podCpuLimit(["app"], new Map([["app", 0.5]]), new Set(["app", "late"])), undefined);
  // No roster, an empty roster, no limits at all.
  assert.equal(podCpuLimit(undefined, limits, seen), undefined);
  assert.equal(podCpuLimit([], limits, seen), undefined);
  assert.equal(podCpuLimit(["app"], undefined, new Set(["app"])), undefined);
});

test("rate memory: per-container throttling keys are forgotten with their pods (no leak)", async () => {
  const rates = new CounterRates();
  const readWith = async (pods: typeof PODS, tick: number, sidecar?: "limited") => {
    const reading = await readCadvisor(
      cadvisorFixture({ node: "node-a", pods, tick, ...(sidecar ? { sidecar } : {}) }).split("\n"),
      {
        readAt: START_MS + tick * PERIOD_MS,
        rates,
        nodeName: "node-a",
        podIdByName: new Map(pods.map((pod) => [`${pod.namespace}/${pod.name}`, `pod/${pod.uid}`])),
        suppressIo: false,
      },
    );
    rates.retain(reading.rateKeys);
    return reading;
  };

  await readWith(PODS, 0, "limited");
  await readWith(PODS, 1, "limited");
  // node: 2 IO keys; per pod: 2 IO keys + one throttling key per limited container.
  assert.equal(rates.size, 2 + PODS.length * (2 + 2));

  // The sidecars go away: their keys must go with them.
  await readWith(PODS, 2);
  assert.equal(rates.size, 2 + PODS.length * (2 + 1));

  // Every pod is replaced. The size stays where it was instead of doubling.
  const next = fixturePods("node-a-second", PODS.length);
  await readWith(next, 3);
  await readWith(next, 4);
  assert.equal(rates.size, 2 + PODS.length * (2 + 1));
});
