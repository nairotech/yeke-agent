/**
 * The 30-minute ring buffer.
 *
 * ─── Why the agent buffers at all ───────────────────────────────────────────
 *
 * K5: when the tunnel is down the agent accumulates for 30 minutes and drains
 * in order once it reconnects. This is MONIPLE's lesson written into the
 * design: its server push had no buffer (`lib/server-push.js`), so every
 * connectivity blip became a permanent hole in the history, and a hole in a
 * history is indistinguishable from a period in which nothing happened.
 *
 * ─── Why a ring and not a queue that grows ──────────────────────────────────
 *
 * An unbounded queue turns a long outage into an OOMKill, in a customer's
 * cluster, in the component that is supposed to be the quiet one. A ring has a
 * ceiling by construction: 60 frames at 30 seconds is 30 minutes, and the roof
 * document's memory target (64 MiB RSS) is a number this buffer has to fit
 * inside, not one it can negotiate with.
 *
 * ─── Why dropping is counted and never silent ───────────────────────────────
 *
 * When the ring is full the OLDEST frame is dropped, not the newest. The newest
 * data is the data an operator opening the screen after an outage is looking
 * at; discarding it to preserve half-hour-old numbers gets the priority exactly
 * backwards.
 *
 * The count of what was dropped rides on the next frame that reaches the wire
 * (K5). The control plane turns it into a gap in the series and a chip on the
 * screen. This is the whole point: after a 35-minute outage the screen must say
 * "five minutes are missing", not draw a line that quietly interpolates over
 * them. A number the product cannot vouch for is not shown as a number.
 */
import type { InternalFrame } from "./types.js";

/** 30 minutes at one frame every 30 seconds (K5). */
export const DEFAULT_RING_CAPACITY = 60;

export class SampleRing {
  readonly #frames: InternalFrame[] = [];
  readonly #capacity: number;
  #dropped = 0;

  constructor(options: { readonly capacity?: number } = {}) {
    this.#capacity = Math.max(1, options.capacity ?? DEFAULT_RING_CAPACITY);
  }

  get size(): number {
    return this.#frames.length;
  }

  get capacity(): number {
    return this.#capacity;
  }

  /** Frames dropped since the last `takeDropped()`. */
  get dropped(): number {
    return this.#dropped;
  }

  push(frame: InternalFrame): void {
    this.#frames.push(frame);
    while (this.#frames.length > this.#capacity) {
      this.#frames.shift();
      this.#dropped += 1;
    }
  }

  /** The oldest frame, without removing it. */
  peek(): InternalFrame | undefined {
    return this.#frames[0];
  }

  /**
   * Removes and returns the oldest frame.
   *
   * One at a time, and in order, because the sink can refuse: a frame that the
   * wire did not accept must still be at the head of the ring on the next tick.
   * A `drain()` that handed over an array would have to put the remainder back,
   * and putting frames back into a ring is how their order gets lost.
   */
  shift(): InternalFrame | undefined {
    return this.#frames.shift();
  }

  /**
   * Exactly what the ring is holding, in bytes of sample data.
   *
   * Structural and exact, which is why it exists at all: the roof document's
   * 64 MiB target is about what a 30-minute buffer HOLDS, and the obvious way
   * to measure that -- force a garbage collection and read the heap -- needs
   * either a command-line flag or a runtime V8 flag change. The second was
   * tried and it destabilised the measurement harness (measured, 09.09.2026:
   * `v8.setFlagsFromString("--expose-gc")` mid-process left runs stalling
   * indefinitely at 50 nodes). Counting the `Float32Array`s is not an estimate
   * of the ring's cost; it IS the ring's cost, minus a per-frame object header.
   *
   * `layouts` is the number of DISTINCT layout objects held. One means every
   * frame in the ring shares a dictionary; a number close to `frames` means the
   * sharing is not working and the memory target is out of reach.
   */
  retained(): { readonly frames: number; readonly valueBytes: number; readonly layouts: number } {
    const layouts = new Set<unknown>();
    let valueBytes = 0;
    for (const frame of this.#frames) {
      valueBytes += frame.values.byteLength;
      layouts.add(frame.layout);
    }
    return { frames: this.#frames.length, valueBytes, layouts: layouts.size };
  }

  /**
   * Reads and RESETS the drop counter.
   *
   * Called by the collector exactly when it is about to stamp a frame that is
   * going to the wire. Reading without resetting would repeat the same count on
   * every subsequent frame, and the control plane would report one 35-minute
   * outage as an unending series of gaps.
   */
  takeDropped(): number {
    const dropped = this.#dropped;
    this.#dropped = 0;
    return dropped;
  }
}
