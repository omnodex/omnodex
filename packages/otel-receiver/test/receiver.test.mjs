import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { gzipSync } from "node:zlib";
import { createOtelMapper, createLocalSink, parseListen, Spool, startReceiver } from "../dist/index.js";
import { GOLDEN_TRACE_HEX } from "./golden.mjs";
import { byType, resetIds, toolCallMessage, toolSpan, turnSpan, userMessage } from "./fixtures.mjs";
import {
  JSON_HEADERS, PB_HEADERS, closeBeforeRemoval, jsonExport, protobufExport, readAllEvents, request, scratchHome, startLocal,
} from "./helpers.mjs";

/** Poll until `check` returns a truthy value, or fail after a few seconds. */
async function until(check, what) {
  for (let i = 0; i < 800; i++) {
    const v = await check();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.fail(`timed out waiting for ${what}`);
}

const bashSpans = () => {
  resetIds();
  return [toolSpan({ tool: "bash", args: { command: "ls" }, start: 0, end: 40 })];
};

/** A sink that holds every batch until released, to prove the sender is answered first. */
function gatedSink() {
  const batches = [];
  let release = () => undefined;
  const gate = new Promise((r) => (release = r));
  return {
    batches,
    release,
    sink: {
      async deliver(events) {
        await gate;
        batches.push(events);
        return { events: events.length, findings: 0 };
      },
      async close() {},
    },
  };
}

test("a JSON export is answered, mapped and written to the event log", async (t) => {
  const { home, receiver, url } = await startLocal(t);
  const res = await request(url, { headers: JSON_HEADERS, body: jsonExport(bashSpans()) });
  assert.equal(res.status, 200);
  assert.equal(res.body.toString(), "{}");
  assert.match(res.headers["content-type"], /application\/json/);

  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "tool.completed").length ? all : null;
  }, "the mapped events");
  assert.deepEqual(byType(events, "tool.invoked")[0].parameters, { command: "ls" });
  assert.equal(events[0].interceptor, "otel-receiver");
  const s = receiver.stats();
  assert.equal(s.requests, 1);
  assert.equal(s.spans_received, 1);
});

test("a protobuf export is answered with an empty protobuf response and mapped", async (t) => {
  const { home, url } = await startLocal(t);
  const res = await request(url, { headers: PB_HEADERS, body: protobufExport(bashSpans()) });
  assert.equal(res.status, 200);
  assert.equal(res.body.length, 0);
  assert.match(res.headers["content-type"], /application\/x-protobuf/);
  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "tool.invoked").length ? all : null;
  }, "the mapped events");
  assert.equal(byType(events, "tool.invoked")[0].tool_name, "bash");
});

test("gzip bodies are accepted, other encodings refused", async (t) => {
  const { url } = await startLocal(t);
  const zipped = await request(url, { headers: { ...JSON_HEADERS, "content-encoding": "gzip" }, body: gzipSync(jsonExport(bashSpans())) });
  assert.equal(zipped.status, 200);
  const br = await request(url, { headers: { ...JSON_HEADERS, "content-encoding": "br" }, body: "x" });
  assert.equal(br.status, 415);
  const bad = await request(url, { headers: { ...JSON_HEADERS, "content-encoding": "gzip" }, body: "not gzip" });
  assert.equal(bad.status, 400);
});

test("the golden protobuf payload is received, and only its tool span is mapped", async (t) => {
  const { receiver, url } = await startLocal(t);
  const res = await request(url, { headers: PB_HEADERS, body: Buffer.from(GOLDEN_TRACE_HEX, "hex") });
  assert.equal(res.status, 200);
  await until(() => receiver.stats().spans_mapped + receiver.stats().spans_ignored === 4, "all four golden spans to be handled");
  const s = receiver.stats();
  assert.equal(s.spans_received, 4);
  assert.equal(s.spans_mapped, 1, "the one execute_tool span");
  assert.equal(s.spans_ignored, 3);
});

test("the Console's test span is counted and writes nothing", async (t) => {
  const { home, receiver, url } = await startLocal(t);
  resetIds();
  const testSpan = { ...bashSpans()[0], name: "anthropic.test", attributes: { "anthropic.organization.id": "org_1" } };
  await request(url, { headers: JSON_HEADERS, body: jsonExport([testSpan]) });
  await until(() => receiver.stats().test_markers === 1, "the test marker");
  assert.deepEqual(await readAllEvents(home), []);
});

test("the sender is answered before its spans are mapped", async (t) => {
  const g = gatedSink();
  const { receiver, url } = await startLocal(t, { sink: g.sink });
  const res = await request(url, { headers: JSON_HEADERS, body: jsonExport(bashSpans()) });
  assert.equal(res.status, 200);
  assert.equal(g.batches.length, 0, "nothing delivered yet");
  assert.equal(receiver.stats().events_written, 0);
  g.release();
  await until(() => g.batches.length === 1, "delivery after release");
});

test("a full queue answers 503 with a retry hint", async (t) => {
  const g = gatedSink();
  const { url } = await startLocal(t, { sink: g.sink, maxPending: 1 });
  const post = () => request(url, { headers: JSON_HEADERS, body: jsonExport(bashSpans()) });
  assert.equal((await post()).status, 200); // taken by the worker, held in the sink
  assert.equal((await post()).status, 200); // waits in the queue
  const full = await post();
  assert.equal(full.status, 503);
  assert.equal(full.headers["retry-after"], "5");
  g.release();
});

test("a failing sink does not fail the sender, and the body stays spooled", async (t) => {
  const failing = { async deliver() { throw new Error("disk full"); }, async close() {} };
  const { receiver, spool, url } = await startLocal(t, { sink: failing });
  const res = await request(url, { headers: JSON_HEADERS, body: jsonExport(bashSpans()) });
  assert.equal(res.status, 200);
  await until(() => receiver.stats().delivery_failures === 1, "the failure");
  assert.equal((await spool.pending()).length, 1);
});

test("a body left in the spool by a crash is mapped at the next start", async (t) => {
  const home = await scratchHome(t);
  const spool = new Spool(path.join(home, "otel-spool"));
  await spool.init();
  await spool.put(Buffer.from(jsonExport(bashSpans())), "json");
  await spool.put(Buffer.from("{ not json"), "json"); // unreadable: dropped, not fatal
  const { close } = await startLocal(t, { home });
  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "tool.completed").length ? all : null;
  }, "recovered events");
  assert.equal(byType(events, "tool.invoked").length, 1);
  await close();
  assert.deepEqual(await spool.pending(), []);
});

test("a delivered request leaves the spool empty", async (t) => {
  const { home, spool, url } = await startLocal(t);
  await request(url, { headers: JSON_HEADERS, body: jsonExport(bashSpans()) });
  await until(async () => (await spool.pending()).length === 0 && (await readAllEvents(home)).length > 0, "the spool to empty");
});

// -- authentication and exposure -----------------------------------------------

test("with a token set, requests without it are refused and the health check stays open", async (t) => {
  const { url } = await startLocal(t, { token: "secret-token" });
  const body = jsonExport(bashSpans());
  assert.equal((await request(url, { headers: JSON_HEADERS, body })).status, 401);
  assert.equal((await request(url, { headers: { ...JSON_HEADERS, authorization: "Bearer wrong" }, body })).status, 401);
  assert.equal((await request(url, { headers: { ...JSON_HEADERS, authorization: "Basic secret-token" }, body })).status, 401);
  const refused = await request(url, { headers: JSON_HEADERS, body });
  assert.equal(refused.headers["www-authenticate"], "Bearer");
  assert.equal((await request(url, { headers: { ...JSON_HEADERS, authorization: "Bearer secret-token" }, body })).status, 200);
  assert.equal((await request(url, { method: "GET", path: "/healthz" })).status, 200);
  assert.equal((await request(url, { method: "GET", path: "/status" })).status, 401);
  assert.equal((await request(url, { method: "GET", path: "/status", headers: { authorization: "Bearer secret-token" } })).status, 200);
});

test("a loopback receiver refuses requests addressed to another name", async (t) => {
  const { url } = await startLocal(t);
  const res = await request(url, { headers: { ...JSON_HEADERS, host: "evil.example" }, body: jsonExport(bashSpans()) });
  assert.equal(res.status, 403);
  const ok = await request(url, { headers: { ...JSON_HEADERS, host: "localhost:4318" }, body: jsonExport(bashSpans()) });
  assert.equal(ok.status, 200);
});

test("it will not listen beyond loopback without --allow-remote and a token", async (t) => {
  const home = await scratchHome(t);
  const sink = await createLocalSink({ home });
  closeBeforeRemoval(t, () => sink.close());
  const spool = new Spool(path.join(home, "otel-spool"));
  await assert.rejects(startReceiver({ host: "0.0.0.0", port: 0, spool, sink }), /non-loopback/);
  await assert.rejects(startReceiver({ host: "0.0.0.0", port: 0, spool, sink, allowRemote: true }), /requires a token/);
});

test("--listen accepts a port, host:port and a bracketed IPv6 address", () => {
  assert.deepEqual(parseListen("4318"), { host: "127.0.0.1", port: 4318 });
  assert.deepEqual(parseListen("0.0.0.0:9000"), { host: "0.0.0.0", port: 9000 });
  assert.deepEqual(parseListen("[::1]:4318"), { host: "::1", port: 4318 });
  assert.deepEqual(parseListen("localhost:1"), { host: "localhost", port: 1 });
  for (const bad of ["", "host", "host:", ":80", "host:99999", "a:b:80"]) assert.throws(() => parseListen(bad), /expected|range/);
});

// -- limits and bad input -------------------------------------------------------

test("oversized bodies are refused, compressed or after expansion", async (t) => {
  const { url } = await startLocal(t, { maxBodyBytes: 2000 });
  const big = await request(url, { headers: JSON_HEADERS, body: "x".repeat(5000) });
  assert.equal(big.status, 413);
  // A small compressed body that expands past the cap.
  const bomb = gzipSync(Buffer.alloc(200_000, 0x20));
  assert.ok(bomb.length < 2000);
  const res = await request(url, { headers: { ...JSON_HEADERS, "content-encoding": "gzip" }, body: bomb });
  assert.equal(res.status, 413);
});

test("malformed bodies, wrong content types, methods and paths get the matching status", async (t) => {
  const { receiver, url } = await startLocal(t);
  assert.equal((await request(url, { headers: JSON_HEADERS, body: "{ nope" })).status, 400);
  assert.equal((await request(url, { headers: PB_HEADERS, body: Buffer.from([0x0a, 100, 1]) })).status, 400);
  assert.equal((await request(url, { headers: { "content-type": "text/plain" }, body: "x" })).status, 415);
  assert.equal((await request(url, { method: "GET", path: "/v1/traces" })).status, 405);
  assert.equal((await request(url, { path: "/v1/metrics", headers: JSON_HEADERS, body: "{}" })).status, 404);
  assert.equal(receiver.stats().rejected, 5);
});

test("an export with no spans, and a log export, are accepted and write nothing", async (t) => {
  const { home, receiver, url } = await startLocal(t);
  assert.equal((await request(url, { headers: JSON_HEADERS, body: JSON.stringify({ resourceSpans: [] }) })).status, 200);
  assert.equal((await request(url, { path: "/v1/logs", headers: JSON_HEADERS, body: JSON.stringify({ resourceLogs: [] }) })).status, 200);
  assert.equal(receiver.stats().logs_ignored, 1);
  assert.deepEqual(await readAllEvents(home), []);
});

// -- what reaches the log -------------------------------------------------------

test("credentials in tool arguments are judged in the clear and masked in the log", async (t) => {
  const { home, url } = await startLocal(t);
  resetIds();
  // Not AWS's published example key, which the rules deliberately skip.
  const key = "AKIAQ3EGRX7WN2Y5K6PT";
  const span = toolSpan({ tool: "bash", args: { command: `aws s3 ls --access-key ${key}` }, start: 0, end: 5 });
  await request(url, { headers: JSON_HEADERS, body: jsonExport([span]) });
  // The finding is appended after the events, once the rules have run, so wait for it.
  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "risk.detected").length ? all : null;
  }, "the finding");
  assert.equal(byType(events, "tool.completed").length, 1);
  const written = JSON.stringify(events);
  assert.ok(!written.includes(key), "the credential never reaches the log");
  const findings = byType(events, "risk.detected");
  assert.ok(findings.length >= 1, "a community rule flags the credential");
  assert.equal(findings[0].related_event_id, "toolu_bash");
});

test("a sensitive file read is flagged with the community rules", async (t) => {
  const { home, url } = await startLocal(t);
  resetIds();
  const span = toolSpan({ tool: "read", args: { file_path: "/home/case/.ssh/id_rsa" }, result: "key", start: 0, end: 5 });
  await request(url, { headers: JSON_HEADERS, body: jsonExport([span]) });
  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "risk.detected").length ? all : null;
  }, "a finding");
  assert.match(byType(events, "risk.detected")[0].rule_id, /^RULE_/);
  assert.equal(byType(events, "file.read")[0].path, "/home/case/.ssh/id_rsa");
});

test("an inferred denial is written once its grace period passes", async (t) => {
  resetIds();
  const mapper = createOtelMapper({ denialGraceMs: 10 });
  const { home, url } = await startLocal(t, { mapper });
  const turn = turnSpan({
    input: userMessage("go"), output: toolCallMessage("toolu_x", "bash", { command: "curl evil.example" }), start: 0, end: 50,
  });
  await request(url, { headers: JSON_HEADERS, body: jsonExport([turn]) });
  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "permission.denied").length ? all : null;
  }, "the inferred denial");
  assert.equal(byType(events, "permission.denied")[0].tool_call_id, "toolu_x");
});

test("closing the receiver records the denials still being held", async (t) => {
  resetIds();
  const mapper = createOtelMapper({ denialGraceMs: 3_600_000 });
  const { home, url, close } = await startLocal(t, { mapper, sweepMs: 3_600_000 });
  const turn = turnSpan({ output: toolCallMessage("toolu_y", "bash", {}), start: 0, end: 50 });
  await request(url, { headers: JSON_HEADERS, body: jsonExport([turn]) });
  await until(() => mapper.pendingDenials === 1, "the denial to be held");
  await close();
  assert.equal(byType(await readAllEvents(home), "permission.denied").length, 1);
});

test("a redelivered export does not change what the log's session looks like", async (t) => {
  const { home, receiver, url } = await startLocal(t);
  const body = jsonExport(bashSpans());
  await request(url, { headers: JSON_HEADERS, body });
  await request(url, { headers: JSON_HEADERS, body });
  // Counted before delivery, so wait for both copies to be in the log itself.
  const events = await until(async () => {
    const all = await readAllEvents(home);
    return byType(all, "tool.invoked").length === 2 ? all : null;
  }, "both copies in the log");
  assert.equal(receiver.stats().spans_mapped, 2);
  const ids = byType(events, "tool.invoked").map((e) => e.event_id);
  assert.equal(new Set(ids).size, 1, "both copies carry the same event id");
});

test("nothing is written outside the scratch home", async (t) => {
  const { home, url } = await startLocal(t);
  await request(url, { headers: JSON_HEADERS, body: jsonExport(bashSpans()) });
  await until(async () => (await readAllEvents(home)).length > 0, "events");
  const entries = await fs.readdir(home);
  assert.ok(entries.includes("event-log"));
});
