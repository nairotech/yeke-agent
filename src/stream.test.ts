/**
 * The two pure rules `UpstreamStream.close()` applies before handing a close
 * to `ws` (I12): what reaches the apiserver end to end is measured in
 * `tunnel-client.test.ts`; the boundaries are measured here.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { upstreamCloseCode, upstreamCloseReason } from "./stream.js";

test("upstreamCloseCode: codes a sender may write pass through; reserved and receiver-only codes become 1000", () => {
  for (const code of [1000, 1001, 1002, 1003, 1007, 1008, 1011, 1014, 3000, 4000, 4999]) {
    assert.equal(upstreamCloseCode(code), code, String(code));
  }
  for (const code of [0, 999, 1004, 1005, 1006, 1015, 1016, 2999, 5000, 1000.5, -1]) {
    assert.equal(upstreamCloseCode(code), 1000, String(code));
  }
});

test("upstreamCloseReason: at most 123 bytes, never cut inside a UTF-8 character", () => {
  assert.equal(upstreamCloseReason(undefined), undefined);
  const fits = "x".repeat(123);
  assert.equal(upstreamCloseReason(fits), fits);
  assert.equal(upstreamCloseReason("x".repeat(200)), fits);
  // A 2-, a 3- and a 4-byte character straddling the 123rd byte.
  for (const [char, bytes] of [["é", 2], ["€", 3], ["\u{1f600}", 4]] as const) {
    const reason = `${"x".repeat(122)}${char}tail`;
    const cut = upstreamCloseReason(reason)!;
    assert.equal(cut, "x".repeat(122), `${bytes}-byte character`);
    assert.ok(Buffer.byteLength(cut) <= 123);
  }
  // The character that ends exactly on byte 123 is kept.
  const exact = `${"x".repeat(120)}€`;
  assert.equal(upstreamCloseReason(`${exact}more`), exact);
});
