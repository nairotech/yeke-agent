/**
 * The ring buffer's three claims: it fills, it drains in order, and it counts
 * what it threw away.
 *
 * The third is the one with a product decision behind it. K5: data loss is
 * never silent. A ring that quietly overwrote its oldest frames would produce a
 * screen that draws a continuous line across a 35-minute outage, and the line
 * would be a lie the product had no way to notice.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_RING_CAPACITY, SampleRing } from "./ring.js";
import { type InternalFrame, packFrame } from "./types.js";

function frame(seq: number): InternalFrame {
  return packFrame({
    seq,
    capturedAt: seq * 30_000,
    entities: [],
    samples: [],
    nodes: [],
  });
}

test("the default ring holds 30 minutes at one frame per 30 seconds", () => {
  assert.equal(DEFAULT_RING_CAPACITY, 60);
  assert.equal((DEFAULT_RING_CAPACITY * 30_000) / 60_000, 30);
});

test("it fills to capacity and then drops the OLDEST", () => {
  const ring = new SampleRing({ capacity: 3 });
  for (let seq = 1; seq <= 3; seq += 1) ring.push(frame(seq));
  assert.equal(ring.size, 3);
  assert.equal(ring.dropped, 0);

  ring.push(frame(4));
  assert.equal(ring.size, 3);
  assert.equal(ring.dropped, 1);
  // The newest data survives: it is what an operator opening the screen after
  // an outage is looking at.
  assert.equal(ring.peek()?.seq, 2);
});

test("it drains in order, oldest first", () => {
  const ring = new SampleRing({ capacity: 10 });
  for (let seq = 1; seq <= 4; seq += 1) ring.push(frame(seq));
  assert.deepEqual([ring.shift()?.seq, ring.shift()?.seq], [1, 2]);
  assert.equal(ring.peek()?.seq, 3);
  assert.equal(ring.size, 2);
});

test("the drop count is read once and then reset", () => {
  const ring = new SampleRing({ capacity: 2 });
  for (let seq = 1; seq <= 5; seq += 1) ring.push(frame(seq));
  assert.equal(ring.dropped, 3);
  assert.equal(ring.takeDropped(), 3);
  // Reading without resetting would repeat the same number on every following
  // frame, and one 35-minute outage would be reported as an unending series of
  // gaps.
  assert.equal(ring.dropped, 0);
  assert.equal(ring.takeDropped(), 0);
});

test("a 35-minute outage loses exactly the five minutes it should", () => {
  // K5's acceptance criterion, in arithmetic: 30 minutes fit, the rest does not.
  const ring = new SampleRing({ capacity: DEFAULT_RING_CAPACITY });
  const framesIn35Minutes = (35 * 60_000) / 30_000;
  for (let seq = 1; seq <= framesIn35Minutes; seq += 1) ring.push(frame(seq));

  assert.equal(ring.size, DEFAULT_RING_CAPACITY);
  assert.equal(ring.dropped, framesIn35Minutes - DEFAULT_RING_CAPACITY);
  assert.equal((ring.dropped * 30_000) / 60_000, 5);
  // And what survived is the LAST 30 minutes.
  assert.equal(ring.peek()?.seq, framesIn35Minutes - DEFAULT_RING_CAPACITY + 1);
});

test("what the ring holds is countable without a garbage collector", () => {
  const ring = new SampleRing({ capacity: 4 });
  const layout = { entities: [], entityIds: ["a"], metrics: ["procs"] as const, signatures: [] };
  for (let seq = 1; seq <= 4; seq += 1) {
    ring.push({
      seq,
      capturedAt: seq * 30_000,
      // The same layout object in every frame: that sharing is what keeps a
      // 30-minute buffer inside the memory target, so it is what the accounting
      // has to be able to see.
      layout,
      values: new Float32Array(1000),
      nodes: [],
      dropped: 0,
    });
  }
  const retained = ring.retained();
  assert.equal(retained.frames, 4);
  assert.equal(retained.valueBytes, 4 * 1000 * 4);
  assert.equal(retained.layouts, 1, "the frames did not share their layout");
});

test("a capacity below one is refused rather than producing a ring that drops everything", () => {
  const ring = new SampleRing({ capacity: 0 });
  assert.equal(ring.capacity, 1);
  ring.push(frame(1));
  assert.equal(ring.size, 1);
});
