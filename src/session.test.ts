/**
 * `TunnelSession` and its records, without a network.
 *
 * The end-to-end behaviour (a stale handler that cannot reach the next
 * session, a forgotten id that gets no answer) is measured against real
 * sockets in `tunnel-client.test.ts`. What is measured here is the part those
 * tests cannot reach: rules that a correct control plane never exercises,
 * because it never sends a duplicate id and never reuses an id inside one
 * session — so a regression in them would stay green end to end.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { WebSocket } from "ws";
import { decodeBodyFrame, parseControlMessage, type ControlMessage } from "@nairotech/yeke-tunnel";
import { RequestRecord, StreamRecord, TunnelSession } from "./session.js";
import type { UpstreamStream } from "./stream.js";

interface FakeSocket {
  readyState: number;
  readonly sent: (ControlMessage | { body: number })[];
  send(data: string | Buffer): void;
}

function fakeSocket(): FakeSocket {
  const sent: (ControlMessage | { body: number })[] = [];
  return {
    readyState: WebSocket.OPEN,
    sent,
    send(data) {
      if (typeof data === "string") sent.push(parseControlMessage(data));
      else sent.push({ body: decodeBodyFrame(data)!.requestId });
    },
  };
}

function sessionOn(socket: FakeSocket): TunnelSession {
  return new TunnelSession(socket as unknown as WebSocket);
}

/** An upstream that records what the record asked of it. */
function fakeUpstream(): { readonly closes: [number, string | undefined][]; readonly credits: number[]; upstream: UpstreamStream } {
  const closes: [number, string | undefined][] = [];
  const credits: number[] = [];
  const upstream = {
    close: (code: number, reason?: string) => void closes.push([code, reason]),
    grantCredit: (bytes: number) => void credits.push(bytes),
  } as unknown as UpstreamStream;
  return { closes, credits, upstream };
}

test("claim: a second record for an id is refused, of the same kind or the other one, and the first stays addressable", () => {
  const session = sessionOn(fakeSocket());
  const first = session.claim(1, (s) => new RequestRecord(s, 1, false));
  assert.ok(first);
  assert.equal(session.claim(1, (s) => new RequestRecord(s, 1, true)), undefined, "same kind");
  assert.equal(session.claim(1, (s) => new StreamRecord(s, 1)), undefined, "a stream may not take a request's id");
  assert.equal(session.lookup(1), first);

  const stream = session.claim(2, (s) => new StreamRecord(s, 2));
  assert.ok(stream);
  assert.equal(session.claim(2, (s) => new RequestRecord(s, 2, false)), undefined, "a request may not take a stream's id");
  assert.equal(session.lookup(2), stream);
});

test("release: only the record that holds the id can remove it — a stale record's release leaves the id's new owner alone", () => {
  // Core does not reuse an id inside one session until its counter wraps, so
  // no end-to-end test can build this; the rule is kept because "core does not
  // do that today" is the assumption #12 leaned on.
  const session = sessionOn(fakeSocket());
  const stale = session.claim(1, (s) => new RequestRecord(s, 1, false))!;
  stale.stop();
  const owner = session.claim(1, (s) => new RequestRecord(s, 1, false))!;
  assert.notEqual(owner, stale);

  session.release(1, stale);
  assert.equal(session.lookup(1), owner, "a release by id alone removed the id's new owner");
  stale.finish();
  stale.stop();
  assert.equal(session.lookup(1), owner);
  assert.equal(owner.live, true);
});

test("a stopped record is silent: no message, no body frame, no `err`, and no log line either", () => {
  const socket = fakeSocket();
  const session = sessionOn(socket);
  const record = session.claim(4, (s) => new StreamRecord(s, 4))!;
  const { closes, credits, upstream } = fakeUpstream();
  record.upstream = upstream;

  record.stop(1000, "cancelled");
  assert.deepEqual(closes, [[1000, "cancelled"]], "stop() closes the upstream with the code it was given");
  assert.equal(record.live, false);
  assert.equal(record.signal.aborted, true);
  assert.equal(session.lookup(4), undefined);

  const originalWarn = console.warn;
  const lines: string[] = [];
  console.warn = (...args: unknown[]) => void lines.push(args.join(" "));
  try {
    record.send({ t: "strclose", id: 4, code: 1000 });
    record.sendBody(Buffer.from([1, 2]));
    record.fail({ code: "STREAM_UPSTREAM_ERROR", params: { detail: "late" } });
  } finally {
    console.warn = originalWarn;
  }
  assert.deepEqual(socket.sent, []);
  assert.deepEqual(lines, []);

  // Idempotent, and the first stop wins: a later finish/stop does not close the upstream again.
  record.finish();
  record.stop(1001, "again");
  assert.deepEqual(closes, [[1000, "cancelled"]]);
  record.grantCredit(10);
  assert.deepEqual(credits, [10], "credit is still handed to the upstream object; the lookup by id is what drops late credit");
});

test("finish(): the record's own end releases it without touching what it held", () => {
  const session = sessionOn(fakeSocket());
  const record = session.claim(5, (s) => new StreamRecord(s, 5))!;
  const { closes, upstream } = fakeUpstream();
  record.upstream = upstream;
  record.finish();
  assert.equal(session.lookup(5), undefined);
  assert.equal(record.signal.aborted, true);
  record.stop(1000, "late");
  assert.deepEqual(closes, [], "an upstream that ended on its own is not closed a second time");
});

test("end(): every record is stopped, every body woken, every owned timer cleared, the session's signal aborted — and a second end() changes nothing", async () => {
  const socket = fakeSocket();
  const session = sessionOn(socket);
  const request = session.claim(1, (s) => new RequestRecord(s, 1, true))!;
  const stream = session.claim(2, (s) => new StreamRecord(s, 2))!;
  const opening = session.claim(3, (s) => new StreamRecord(s, 3))!;
  const { closes, upstream } = fakeUpstream();
  stream.upstream = upstream;
  let fired = 0;
  const timer = setInterval(() => {
    fired += 1;
  }, 1);
  session.own(timer);
  const waiting = request.body!.wait();

  session.end();
  await waiting;
  assert.equal(request.body!.state, "aborted");
  assert.deepEqual(closes, [[1001, "tunnel disconnected"]]);
  for (const record of [request, stream, opening]) assert.equal(record.signal.aborted, true);
  assert.equal(session.signal.aborted, true);
  assert.equal(session.ended, true);
  assert.equal(session.live, false);
  assert.deepEqual([...session.records()], []);

  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(fired, 0, "a timer the session owned outlived it");

  session.end();
  assert.deepEqual(closes, [[1001, "tunnel disconnected"]], "a second end() stopped the stream again");
  session.send({ t: "pong", ts: 1 });
  assert.deepEqual(socket.sent, [], "an ended session wrote to its socket");

  // A timer handed to a session that is already over does not get to run at all.
  let late = 0;
  session.own(setInterval(() => {
    late += 1;
  }, 1));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(late, 0);
});

test("a session whose socket is no longer OPEN writes nothing, even before end()", () => {
  const socket = fakeSocket();
  const session = sessionOn(socket);
  const record = session.claim(1, (s) => new RequestRecord(s, 1, false))!;
  socket.readyState = WebSocket.CLOSING;
  assert.equal(session.live, false);
  assert.equal(record.live, false);
  record.send({ t: "end", id: 1 });
  session.sendBody(1, Buffer.from([0]));
  assert.deepEqual(socket.sent, []);
});

test("hasWaitingRequest counts only requests whose response has not started; streams never count", () => {
  const session = sessionOn(fakeSocket());
  session.claim(1, (s) => new StreamRecord(s, 1));
  assert.equal(session.hasWaitingRequest(), false);
  const request = session.claim(2, (s) => new RequestRecord(s, 2, false))!;
  assert.equal(session.hasWaitingRequest(), true);
  request.responding = true;
  assert.equal(session.hasWaitingRequest(), false);
});
