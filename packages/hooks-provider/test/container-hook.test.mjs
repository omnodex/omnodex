// Tests for the cloud container hook: config validation, the environment
// gate, event shaping, spool and flush, retry and drop behavior. Runs against
// the compiled JS in dist/.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  CLOUD_CONTAINER_MARKERS,
  MAX_BATCH_EVENTS,
  MAX_EVENT_PLAINTEXT_BYTES,
  REDACTED_SENTINEL,
  SPOOL_FLUSH_BYTES,
  STALE_CLAIM_MS,
  batchLines,
  claimPending,
  flushSpool,
  handleHookPayload,
  ingestDir,
  isCloudContainer,
  parseIngestConfig,
  prepareEvent,
  spoolBytes,
  withFallback,
} from "../dist/container-hook.js";
import {
  bytesToBase64,
  generateStreamKeyPair,
  openEvent,
} from "../../sync-encryptor/dist/hpke-event.js";

const TOKEN = "oxi_" + "A".repeat(43);

async function makeKeys() {
  const pair = await generateStreamKeyPair();
  const rawConfig = {
    version: 1,
    ingest_token: TOKEN,
    source_id: "src_0123456789ab",
    public_key: bytesToBase64(pair.publicKey),
    key_id: pair.keyId,
  };
  return { pair, rawConfig, config: await parseIngestConfig(rawConfig) };
}

function tmpHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-container-hook-"));
}

/** A poster that records request bodies and answers with the given statuses in turn. */
function recordingPoster(...statuses) {
  const calls = [];
  const post = async (url, token, body) => {
    calls.push({ url, token, body: JSON.parse(body) });
    const s = statuses.length > 1 ? statuses.shift() : statuses[0];
    return typeof s === "number" ? { status: s } : { error: s };
  };
  return { post, calls };
}

async function openAll(pair, wires) {
  const key = { keyId: pair.keyId, privateKey: pair.privateKey };
  const out = [];
  for (const w of wires) out.push(JSON.parse(new TextDecoder().decode(await openEvent(key, w))));
  return out;
}

const BASE = { session_id: "sess-1", cwd: "/home/case/repo" };

// ---------------------------------------------------------------------------
// Config and gate
// ---------------------------------------------------------------------------

test("parseIngestConfig accepts a valid config and defaults api_base", async () => {
  const { rawConfig, pair } = await makeKeys();
  const c = await parseIngestConfig(rawConfig);
  assert.equal(c.apiBase, "https://api.omnodex.com");
  assert.equal(c.keyId, pair.keyId);
  assert.equal(c.redactParameters, false);
  assert.equal(c.force, false);
});

test("parseIngestConfig rejects a key_id that does not match the public key", async () => {
  const { rawConfig } = await makeKeys();
  assert.equal(await parseIngestConfig({ ...rawConfig, key_id: "00000000" }), null);
});

test("parseIngestConfig rejects bad tokens, versions, source ids and plain-http remote hosts", async () => {
  const { rawConfig } = await makeKeys();
  assert.equal(await parseIngestConfig({ ...rawConfig, ingest_token: "abc" }), null);
  assert.equal(await parseIngestConfig({ ...rawConfig, version: 2 }), null);
  assert.equal(await parseIngestConfig({ ...rawConfig, source_id: "../etc" }), null);
  assert.equal(await parseIngestConfig({ ...rawConfig, api_base: "http://api.example.com" }), null);
  assert.equal(await parseIngestConfig({ ...rawConfig, public_key: "not base64!" }), null);
  assert.equal(await parseIngestConfig(null), null);
  const local = await parseIngestConfig({ ...rawConfig, api_base: "http://127.0.0.1:8787/x" });
  assert.equal(local.apiBase, "http://127.0.0.1:8787");
});

test("isCloudContainer is true only when a marker path exists", () => {
  assert.equal(isCloudContainer(CLOUD_CONTAINER_MARKERS, () => false), false);
  assert.equal(isCloudContainer(CLOUD_CONTAINER_MARKERS, (p) => p === "/root/.ccr"), true);
  assert.equal(isCloudContainer(CLOUD_CONTAINER_MARKERS, () => { throw new Error("EACCES"); }), false);
});

// ---------------------------------------------------------------------------
// Event shaping
// ---------------------------------------------------------------------------

const TOOL_EVENT = {
  schema_version: 1,
  event_id: "e1",
  session_id: "s",
  occurred_at: "2026-09-23T00:00:00.000Z",
  recorded_at: "2026-09-23T00:00:00.000Z",
  interceptor: "claude-code-hook",
  event_type: "tool.invoked",
  tool_call_id: "t1",
  tool_name: "Bash",
  mcp_server: "builtin",
  parameters: { command: "ls /home/case", description: "list" },
};

test("prepareEvent marks the platform and keeps parameters by default", () => {
  const e = prepareEvent(TOOL_EVENT, false);
  assert.equal(e.platform, "cowork");
  assert.deepEqual(e.parameters, TOOL_EVENT.parameters);
});

test("prepareEvent redacts parameter values but keeps their keys", () => {
  const e = prepareEvent(TOOL_EVENT, true);
  assert.deepEqual(e.parameters, { command: REDACTED_SENTINEL, description: REDACTED_SENTINEL });
});

test("prepareEvent replaces oversized parameters with a truncation marker", () => {
  const big = { ...TOOL_EVENT, parameters: { content: "x".repeat(MAX_EVENT_PLAINTEXT_BYTES) } };
  const e = prepareEvent(big, false);
  assert.equal(e.parameters._omnodex_truncated, true);
  assert.ok(e.parameters.original_bytes > MAX_EVENT_PLAINTEXT_BYTES);
  assert.ok(Buffer.byteLength(JSON.stringify(e)) <= MAX_EVENT_PLAINTEXT_BYTES);
});

test("prepareEvent truncates a huge error message", () => {
  const failed = {
    ...TOOL_EVENT,
    event_type: "tool.completed",
    parameters: undefined,
    status: "error",
    error_message: "boom ".repeat(MAX_EVENT_PLAINTEXT_BYTES),
  };
  const e = prepareEvent(failed, false);
  assert.ok(e.error_message.endsWith("[truncated]"));
  assert.ok(Buffer.byteLength(JSON.stringify(e)) <= MAX_EVENT_PLAINTEXT_BYTES);
});

test("batchLines respects the event and byte limits", () => {
  const lines = Array.from({ length: MAX_BATCH_EVENTS * 2 + 5 }, (_, i) => `{"i":${i}}`);
  const batches = batchLines(lines);
  assert.deepEqual(batches.map((b) => b.length), [MAX_BATCH_EVENTS, MAX_BATCH_EVENTS, 5]);
  const fat = Array.from({ length: 5 }, () => `"${"x".repeat(300 * 1024)}"`);
  assert.deepEqual(batchLines(fat).map((b) => b.length), [2, 2, 1]);
});

// ---------------------------------------------------------------------------
// Spool and flush
// ---------------------------------------------------------------------------

test("tool calls are spooled sealed and sent once, on Stop", async () => {
  const { pair, config } = await makeKeys();
  const home = tmpHome();
  const { post, calls } = recordingPoster(202);
  let clock = Date.parse("2026-09-23T12:00:00Z");
  const opts = { home, post, now: () => clock };

  await handleHookPayload({ ...BASE, hook_event_name: "PreToolUse", tool_name: "Read", tool_use_id: "tu_1", tool_input: { file_path: "/home/case/a.txt" } }, config, opts);
  clock += 250;
  await handleHookPayload({ ...BASE, hook_event_name: "PostToolUse", tool_name: "Read", tool_use_id: "tu_1", tool_input: { file_path: "/home/case/a.txt" }, tool_response: { content: "hello" } }, config, opts);
  assert.equal(calls.length, 0, "nothing is sent before the turn ends");
  assert.ok(spoolBytes(home) > 0);

  const spooled = fs.readFileSync(path.join(ingestDir(home), "spool.ndjson"), "utf8");
  assert.ok(!spooled.includes("a.txt"), "the spool holds ciphertext only");

  const result = await handleHookPayload({ ...BASE, hook_event_name: "Stop" }, config, opts);
  assert.equal(result.sent, 3);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://api.omnodex.com/api/v1/ingest/events");
  assert.equal(calls[0].token, TOKEN);

  const events = await openAll(pair, calls[0].body.events);
  assert.deepEqual(events.map((e) => e.event_type), ["tool.invoked", "tool.completed", "file.read"]);
  assert.ok(events.every((e) => e.platform === "cowork" && e.session_id === "sess-1"));
  assert.equal(events[1].duration_ms, 250, "duration comes from the PreToolUse timestamp");
  assert.equal(spoolBytes(home), 0);
  assert.equal(JSON.parse(fs.readFileSync(path.join(ingestDir(home), "status.json"), "utf8")).sent, 3);

  // A second Stop with nothing new sends nothing.
  await handleHookPayload({ ...BASE, hook_event_name: "Stop" }, config, opts);
  assert.equal(calls.length, 1);
});

test("a large spool is flushed without waiting for Stop", async () => {
  const { config } = await makeKeys();
  const home = tmpHome();
  const { post, calls } = recordingPoster(202);
  const input = { content: "y".repeat(200 * 1024) };
  for (let i = 0; calls.length === 0 && i < 10; i++) {
    await handleHookPayload({ ...BASE, hook_event_name: "PreToolUse", tool_name: "Write", tool_use_id: `tu_${i}`, tool_input: input }, config, { home, post });
  }
  assert.equal(calls.length > 0, true);
  assert.ok(spoolBytes(home) < SPOOL_FLUSH_BYTES);
});

test("a transient failure keeps events for the next flush", async () => {
  const { pair, config } = await makeKeys();
  const home = tmpHome();
  const failing = recordingPoster(503);
  await handleHookPayload({ ...BASE, hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu_1", tool_input: { command: "ls" } }, config, { home, post: failing.post });
  const r1 = await handleHookPayload({ ...BASE, hook_event_name: "Stop" }, config, { home, post: failing.post });
  assert.deepEqual([r1.sent, r1.pending, r1.last], [0, 1, 503]);

  const ok = recordingPoster(202);
  await handleHookPayload({ ...BASE, hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu_2", tool_input: { command: "pwd" } }, config, { home, post: ok.post });
  const r2 = await handleHookPayload({ ...BASE, hook_event_name: "Stop" }, config, { home, post: ok.post });
  assert.equal(r2.sent, 2);
  const events = await openAll(pair, ok.calls[0].body.events);
  assert.deepEqual(events.map((e) => e.tool_call_id).sort(), ["tu_1", "tu_2"]);
});

test("a network error keeps events too", async () => {
  const { config } = await makeKeys();
  const home = tmpHome();
  const { post } = recordingPoster("ECONNREFUSED");
  await handleHookPayload({ ...BASE, hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu_1", tool_input: {} }, config, { home, post });
  const r = await handleHookPayload({ ...BASE, hook_event_name: "Stop" }, config, { home, post });
  assert.deepEqual([r.pending, r.last], [1, "ECONNREFUSED"]);
});

test("a revoked token drops the batch instead of retrying it", async () => {
  const { config } = await makeKeys();
  const home = tmpHome();
  const revoked = recordingPoster(401);
  await handleHookPayload({ ...BASE, hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu_1", tool_input: {} }, config, { home, post: revoked.post });
  const r = await handleHookPayload({ ...BASE, hook_event_name: "Stop" }, config, { home, post: revoked.post });
  assert.deepEqual([r.sent, r.dropped, r.pending], [0, 1, 0]);
  const again = await flushSpool(home, config, revoked.post);
  assert.equal(revoked.calls.length, 1, "nothing is left to resend");
  assert.equal(again.sent + again.dropped, 0);
});

test("claims abandoned by a killed flush are retried; fresh claims are left alone", async () => {
  const home = tmpHome();
  const dir = ingestDir(home);
  fs.mkdirSync(dir, { recursive: true });
  const now = Date.now();
  const stale = path.join(dir, "claim-1-1-0.ndjson");
  const fresh = path.join(dir, "claim-2-2-0.ndjson");
  fs.writeFileSync(stale, '{"a":1}\n');
  fs.writeFileSync(fresh, '{"b":2}\n');
  const old = new Date(now - STALE_CLAIM_MS - 1000);
  fs.utimesSync(stale, old, old);

  const claimed = claimPending(home, now);
  assert.equal(claimed.length, 1);
  assert.equal(fs.readFileSync(claimed[0], "utf8"), '{"a":1}\n');
  assert.ok(fs.existsSync(fresh));
  // The taken claim is restamped, so another flush does not take it again.
  assert.equal(claimPending(home, now).length, 0);
});

test("unknown hook events and payloads without a session are ignored", async () => {
  const { config } = await makeKeys();
  const home = tmpHome();
  const { post, calls } = recordingPoster(202);
  assert.equal(await handleHookPayload({ hook_event_name: "Notification" }, config, { home, post }), null);
  assert.equal(await handleHookPayload({ hook_event_name: "PreToolUse", tool_name: "Bash" }, config, { home, post }), null);
  assert.equal(await handleHookPayload({}, config, { home, post }), null);
  assert.equal(calls.length, 0);
  assert.equal(spoolBytes(home), 0);
});

test("withFallback uses the next transport only when there was no response", async () => {
  const seen = [];
  const a = async () => { seen.push("a"); return { error: "ECONNRESET" }; };
  const b = async () => { seen.push("b"); return { status: 202 }; };
  assert.deepEqual(await withFallback(a, b)("u", "t", "{}"), { status: 202 });
  const c = async () => { seen.push("c"); return { status: 500 }; };
  assert.deepEqual(await withFallback(c, b)("u", "t", "{}"), { status: 500 });
  assert.deepEqual(seen, ["a", "b", "c"]);
});
