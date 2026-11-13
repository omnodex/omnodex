// Tests for the sealed hook: environment gates, settings, and each agent's
// payload end to end (map, seal, spool, flush) against a fake ingest.
//
// MUST_FIRE cases capture; MUST_NOT_FIRE cases leave no spool and post nothing.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { loadSealedConfig, runSealedHook, shouldCapture } from "../dist/index.js";
import { bytesToBase64, generateStreamKeyPair, openEvent } from "../../sync-encryptor/dist/hpke-event.js";

const TOKEN = "oxi_" + "D".repeat(43);

async function setup(extraEnv = {}) {
  const pair = await generateStreamKeyPair();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-sealed-"));
  const env = {
    OMNODEX_SEALED: "1",
    OMNODEX_INGEST_PUBLIC_KEY: bytesToBase64(pair.publicKey),
    OMNODEX_INGEST_SOURCE_ID: "src_0123456789ab",
    ...extraEnv,
  };
  const calls = [];
  const post = async (url, token, body) => {
    calls.push({ url, token, body: JSON.parse(body) });
    return { status: 202 };
  };
  const open = async () => {
    const out = [];
    for (const c of calls) {
      for (const w of c.body.events) {
        out.push(JSON.parse(new TextDecoder().decode(await openEvent({ keyId: pair.keyId, privateKey: pair.privateKey }, w))));
      }
    }
    return out;
  };
  const run = (provider, payload, extra = {}) =>
    runSealedHook({ provider, stdin: JSON.stringify(payload), env: extra.env ?? env, home, post, ...extra });
  return { pair, home, env, calls, open, run };
}

const spoolExists = (home) => fs.existsSync(path.join(home, "ingest", "spool.ndjson"));

const CLAUDE_PRE = { session_id: "c1", cwd: "/home/case/repo", hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu1", tool_input: { command: "ls" } };
const CLAUDE_STOP = { session_id: "c1", hook_event_name: "Stop" };

// --- gates ----------------------------------------------------------------

test("shouldCapture: MUST_FIRE on the built-in claude-code marker, the switch and a named marker", () => {
  assert.equal(shouldCapture("claude-code", { CLAUDE_CODE_REMOTE: "true" }), true);
  assert.equal(shouldCapture("copilot", { OMNODEX_SEALED: "1" }), true);
  assert.equal(shouldCapture("cursor", { OMNODEX_SEALED_WHEN: "MY_CLOUD_AGENT", MY_CLOUD_AGENT: "yes" }), true);
});

test("shouldCapture: MUST_NOT_FIRE on a plain machine, other providers' markers, off switch and bad names", () => {
  assert.equal(shouldCapture("claude-code", {}), false);
  assert.equal(shouldCapture("claude-code", { CLAUDE_CODE_REMOTE: "false" }), false);
  assert.equal(shouldCapture("copilot", { CLAUDE_CODE_REMOTE: "true" }), false);
  assert.equal(shouldCapture("claude-code", { CLAUDE_CODE_REMOTE: "true", OMNODEX_SEALED: "0" }), false);
  assert.equal(shouldCapture("cursor", { OMNODEX_SEALED_WHEN: "MY_CLOUD_AGENT" }), false);
  assert.equal(shouldCapture("cursor", { OMNODEX_SEALED_WHEN: "MY_CLOUD_AGENT", MY_CLOUD_AGENT: "0" }), false);
  assert.equal(shouldCapture("cursor", { OMNODEX_SEALED_WHEN: "x; rm -rf", "x; rm -rf": "1" }), false);
});

// --- settings -------------------------------------------------------------

test("loadSealedConfig: environment alone is enough, no token needed, key_id derived", async () => {
  const { env, home, pair } = await setup();
  const cfg = await loadSealedConfig(env, { home });
  assert.ok(cfg);
  assert.equal(cfg.ingestToken, undefined);
  assert.equal(cfg.keyId, pair.keyId);
  assert.equal(cfg.apiBase, "https://api.omnodex.com");
});

test("loadSealedConfig: a committed project file works and the environment overrides it", async () => {
  const { env, home, pair } = await setup();
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-proj-"));
  fs.mkdirSync(path.join(proj, ".omnodex"));
  fs.writeFileSync(
    path.join(proj, ".omnodex", "ingest.json"),
    JSON.stringify({ public_key: bytesToBase64(pair.publicKey), source_id: "src_fromfile" }),
  );
  const fromFile = await loadSealedConfig({ OMNODEX_SEALED: "1" }, { home, projectDirs: [proj] });
  assert.equal(fromFile.sourceId, "src_fromfile");
  const overridden = await loadSealedConfig(env, { home, projectDirs: [proj] });
  assert.equal(overridden.sourceId, "src_0123456789ab");
});

test("loadSealedConfig: MUST_NOT_FIRE on missing, mismatched or malformed settings", async () => {
  const { env, home } = await setup();
  assert.equal(await loadSealedConfig({}, { home }), null);
  assert.equal(await loadSealedConfig({ ...env, OMNODEX_INGEST_KEY_ID: "00000000" }, { home }), null);
  assert.equal(await loadSealedConfig({ ...env, OMNODEX_INGEST_SOURCE_ID: "nope" }, { home }), null);
  assert.equal(await loadSealedConfig({ ...env, OMNODEX_INGEST_API_BASE: "http://example.com" }, { home }), null);
  assert.equal(await loadSealedConfig({ ...env, OMNODEX_INGEST_TOKEN: "bad" }, { home }), null);
  assert.equal(await loadSealedConfig({ ...env, OMNODEX_INGEST_PUBLIC_KEY: "AAAA" }, { home }), null);
});

// --- each provider: MUST_FIRE ---------------------------------------------

test("claude-code MUST_FIRE: events are sealed, labeled claude-code and sent on Stop with no token", async () => {
  const t = await setup();
  assert.equal(await t.run("claude-code", CLAUDE_PRE), "");
  assert.equal(t.calls.length, 0);
  await t.run("claude-code", CLAUDE_STOP);
  assert.equal(t.calls.length, 1);
  assert.equal(t.calls[0].token, undefined);
  assert.equal(t.calls[0].url, "https://api.omnodex.com/api/v1/ingest/events");
  const events = await t.open();
  assert.equal(events[0].event_type, "tool.invoked");
  assert.equal(events[0].platform, "claude-code");
});

test("a token in the environment is sent as the bearer token", async () => {
  const t = await setup({ OMNODEX_INGEST_TOKEN: TOKEN });
  await t.run("claude-code", CLAUDE_PRE);
  await t.run("claude-code", CLAUDE_STOP);
  assert.equal(t.calls[0].token, TOKEN);
});

test("copilot MUST_FIRE: pre and post share a call id, platform copilot, answer is {}", async () => {
  const t = await setup();
  const pre = { hook_event_name: "PreToolUse", session_id: "p1", cwd: "/home/case/repo", tool_name: "bash", tool_input: { command: "ls" } };
  assert.equal(await t.run("copilot", pre), "{}");
  await t.run("copilot", { ...pre, hook_event_name: "PostToolUse", tool_result: { text_result_for_llm: "ok" } });
  assert.equal(await t.run("copilot", { hook_event_name: "SessionEnd", session_id: "p1", reason: "complete" }), "{}");
  const events = await t.open();
  const invoked = events.find((e) => e.event_type === "tool.invoked");
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.ok(invoked && completed);
  assert.equal(invoked.platform, "copilot");
  assert.ok(invoked.tool_call_id);
  assert.equal(invoked.tool_call_id, completed.tool_call_id);
});

test("cursor MUST_FIRE: tool hook is captured, permission hook is not, answer is {}", async () => {
  const t = await setup();
  const base = { conversation_id: "u1", workspace_roots: ["/home/case/repo"] };
  assert.equal(await t.run("cursor", { ...base, hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls" }, tool_use_id: "x1" }), "{}");
  assert.equal(await t.run("cursor", { ...base, hook_event_name: "beforeShellExecution", command: "ls" }), "{}");
  await t.run("cursor", { ...base, hook_event_name: "sessionEnd" });
  const events = await t.open();
  assert.equal(events.filter((e) => e.event_type === "tool.invoked").length, 1);
  assert.equal(events[0].platform, "cursor");
});

test("codex MUST_FIRE: pre and post are captured with a duration, platform codex", async () => {
  const t = await setup();
  const base = { session_id: "x1", cwd: "/home/case/repo", transcript_path: null, model: "m" };
  await t.run("codex", { ...base, hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "t1", tool_input: { command: "ls" } }, { now: () => 1000 });
  await t.run("codex", { ...base, hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "t1", tool_input: { command: "ls" }, tool_response: "ok" }, { now: () => 1500 });
  await t.run("codex", { ...base, hook_event_name: "Stop" });
  const events = await t.open();
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.ok(completed);
  assert.equal(completed.platform, "codex");
  assert.equal(completed.duration_ms, 500);
});

test("antigravity MUST_FIRE: first activity starts the session, tool pair correlates, Stop answers allow", async () => {
  const t = await setup();
  const common = { conversationId: "conv-1", workspacePaths: ["/home/case/repo"], modelName: "m" };
  const pre = { ...common, toolCall: { name: "run_command", args: { command: "ls" } }, stepIdx: 3 };
  assert.equal(await t.run("antigravity", pre, { eventName: "PreToolUse", now: () => 1000 }), '{"decision":"allow"}');
  assert.equal(await t.run("antigravity", { ...common, stepIdx: 3 }, { eventName: "PostToolUse", now: () => 1200 }), "{}");
  assert.equal(await t.run("antigravity", { ...common, executionNum: 1, terminationReason: "done", fullyIdle: true }, { eventName: "Stop" }), '{"decision":"allow"}');
  const events = await t.open();
  assert.ok(events.some((e) => e.event_type === "session.started"));
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.duration_ms, 200);
  assert.equal(completed.platform, "antigravity");
});

// --- MUST_NOT_FIRE --------------------------------------------------------

test("MUST_NOT_FIRE: a host that does not opt in captures nothing", async () => {
  const t = await setup();
  const env = { ...t.env };
  delete env.OMNODEX_SEALED;
  await t.run("claude-code", CLAUDE_PRE, { env });
  await t.run("claude-code", CLAUDE_STOP, { env });
  assert.equal(t.calls.length, 0);
  assert.equal(spoolExists(t.home), false);
});

test("MUST_NOT_FIRE: the off switch beats a cloud marker", async () => {
  const t = await setup();
  const env = { ...t.env, OMNODEX_SEALED: "0", CLAUDE_CODE_REMOTE: "true" };
  await t.run("claude-code", CLAUDE_STOP, { env });
  assert.equal(t.calls.length, 0);
});

test("MUST_NOT_FIRE: missing settings exit quietly and still answer the agent", async () => {
  const t = await setup();
  const env = { OMNODEX_SEALED: "1" };
  assert.equal(await t.run("copilot", { hook_event_name: "SessionEnd", session_id: "p1" }, { env }), "{}");
  assert.equal(t.calls.length, 0);
  assert.equal(spoolExists(t.home), false);
});

test("MUST_NOT_FIRE: unknown provider, bad JSON and bad antigravity event never throw or post", async () => {
  const t = await setup();
  assert.equal(await runSealedHook({ provider: "nope", stdin: "{}", env: t.env, home: t.home, post: t.calls.push }), "");
  assert.equal(await runSealedHook({ provider: "copilot", stdin: "not json", env: t.env, home: t.home, post: t.calls.push }), "{}");
  assert.equal(await runSealedHook({ provider: "antigravity", eventName: "Bogus", stdin: "{}", env: t.env, home: t.home, post: t.calls.push }), "{}");
  assert.equal(await runSealedHook({ provider: undefined, stdin: "{}", env: t.env, home: t.home }), "");
  assert.equal(t.calls.length, 0);
});

test("a failed send keeps events for the next flush and never throws", async () => {
  const t = await setup();
  const failing = async () => ({ error: "ECONNREFUSED" });
  await t.run("claude-code", CLAUDE_PRE, { post: failing });
  assert.equal(await t.run("claude-code", CLAUDE_STOP, { post: failing }), "");
  await t.run("claude-code", CLAUDE_STOP);
  assert.equal(t.calls.length, 1);
  assert.ok((await t.open()).some((e) => e.event_type === "tool.invoked"));
});
