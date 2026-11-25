// Tests for the sealed hook: environment gates, settings, and each agent's
// payload end to end (map, seal, spool, flush) against a fake ingest.
//
// MUST_FIRE cases capture; MUST_NOT_FIRE cases leave no spool and post nothing.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { HOST_MARKER_FILE, lastIngestWarning, loadSealedConfig, providerFromShimName, runSealedHook, sealedHome, shouldCapture } from "../dist/index.js";
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

function projectWith(settings) {
  const proj = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-proj-"));
  fs.mkdirSync(path.join(proj, ".omnodex"));
  fs.writeFileSync(path.join(proj, ".omnodex", "ingest.json"), JSON.stringify(settings));
  return proj;
}

async function otherKeys(extra = {}) {
  const other = await generateStreamKeyPair();
  return { public_key: bytesToBase64(other.publicKey), key_id: other.keyId, source_id: "src_fromfile", ...extra };
}

const HOSTILE = { api_base: "https://collector.example.com", ingest_token: "oxi_" + "R".repeat(43), redact_parameters: true, version: 2 };

test("on a host with no settings, a project file gives only the key and source", async () => {
  const { home } = await setup();
  const keys = await otherKeys();
  const cfg = await loadSealedConfig({}, { home, projectDirs: [projectWith({ ...keys, ...HOSTILE })] });
  assert.equal(cfg.sourceId, "src_fromfile");
  assert.equal(cfg.keyId, keys.key_id);
  assert.equal(cfg.apiBase, "https://api.omnodex.com");
  assert.equal(cfg.ingestToken, undefined);
  assert.equal(cfg.redactParameters, false);
});

test("a host with token, key and source captures with its own, whatever the project file says", async () => {
  const t = await setup({ OMNODEX_INGEST_TOKEN: TOKEN });
  for (const settings of [{ version: 2 }, await otherKeys(HOSTILE)]) {
    const proj = projectWith(settings);
    await t.run("claude-code", { ...CLAUDE_PRE, cwd: proj });
    await t.run("claude-code", { ...CLAUDE_STOP, cwd: proj });
  }
  assert.equal(t.calls.length, 2);
  for (const c of t.calls) {
    assert.equal(c.url, "https://api.omnodex.com/api/v1/ingest/events");
    assert.equal(c.token, TOKEN);
  }
  assert.ok((await t.open()).length > 0); // opens with the host's key
});

test("any one host setting keeps the project file out, so the two never mix", async () => {
  const { env, home, pair } = await setup();
  const proj = projectWith(await otherKeys());
  const load = (e) => loadSealedConfig(e, { home, projectDirs: [proj] });
  // Proxy host with its key and source in the environment.
  const cfg = await load(env);
  assert.equal(cfg.keyId, pair.keyId);
  assert.equal(cfg.sourceId, "src_0123456789ab");
  // A partial host set is not completed from the project.
  assert.equal(await load({ OMNODEX_INGEST_PUBLIC_KEY: env.OMNODEX_INGEST_PUBLIC_KEY }), null);
  assert.equal(await load({ OMNODEX_INGEST_KEY_ID: pair.keyId }), null);
  assert.equal(await load({ OMNODEX_INGEST_SOURCE_ID: "src_0123456789ab" }), null);
  assert.equal(await load({ OMNODEX_INGEST_TOKEN: TOKEN }), null);
  // Nor is an unreadable home file replaced.
  fs.writeFileSync(path.join(home, "ingest.json"), "not json");
  assert.equal(await load({}), null);
});

const warnings = (home) => {
  const log = path.join(home, "ingest", "warnings.log");
  return fs.existsSync(log) ? fs.readFileSync(log, "utf8").trim().split("\n") : [];
};

test("MUST_FIRE: an ignored project file warns once per session, not per event", async () => {
  const t = await setup();
  const cwd = projectWith(await otherKeys());
  for (const payload of [CLAUDE_PRE, CLAUDE_PRE, CLAUDE_STOP]) await t.run("claude-code", { ...payload, cwd });
  assert.equal(warnings(t.home).length, 1);
  assert.equal(
    lastIngestWarning(t.home).message,
    `Omnodex ignored the ingest settings in ${path.join(cwd, ".omnodex", "ingest.json")} because this host has its own. ` +
      `To change them, set OMNODEX_INGEST_PUBLIC_KEY and OMNODEX_INGEST_SOURCE_ID in the environment, or put the settings in ${path.join(t.home, "ingest.json")}.`,
  );
  await t.run("claude-code", { ...CLAUDE_PRE, session_id: "c2", cwd });
  assert.equal(warnings(t.home).length, 2);
});

test("MUST_FIRE: a token on the host with the key only in the project says nothing is recorded", async () => {
  const t = await setup();
  const cwd = projectWith(await otherKeys());
  const env = { OMNODEX_SEALED: "1", OMNODEX_INGEST_TOKEN: TOKEN };
  assert.equal(await t.run("claude-code", { ...CLAUDE_PRE, cwd }, { env }), "");
  await t.run("claude-code", { ...CLAUDE_STOP, cwd }, { env });
  assert.equal(t.calls.length, 0);
  assert.equal(warnings(t.home).length, 1);
  assert.match(lastIngestWarning(t.home).message, /^Omnodex is not recording: it ignored the ingest settings in /);
});

test("MUST_NOT_FIRE: no warning without an ignored project file or on a host that does not capture", async () => {
  const t = await setup();
  const plain = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-proj-"));
  await t.run("claude-code", { ...CLAUDE_PRE, cwd: plain });
  const cwd = projectWith(await otherKeys());
  // The project file is the one in use.
  await t.run("claude-code", { ...CLAUDE_PRE, cwd }, { env: { OMNODEX_SEALED: "1" } });
  // A machine that does not capture.
  await t.run("claude-code", { ...CLAUDE_PRE, cwd }, { env: { ...t.env, OMNODEX_SEALED: "0" } });
  // Run from the directory that holds the host's own file.
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-user-"));
  const home = path.join(base, ".omnodex");
  fs.mkdirSync(home);
  fs.writeFileSync(path.join(home, "ingest.json"), JSON.stringify(await otherKeys()));
  await runSealedHook({ provider: "claude-code", stdin: JSON.stringify({ ...CLAUDE_PRE, cwd: base }), env: { OMNODEX_SEALED: "1" }, home, post: async () => ({ status: 202 }) });
  assert.deepEqual(warnings(t.home), []);
  assert.deepEqual(warnings(home), []);
});

test("relative OMNODEX_INGEST_CONFIG and OMNODEX_HOME are ignored", async () => {
  const { env, home } = await setup();
  const proj = projectWith({ api_base: "https://collector.example.com" });
  const prev = process.cwd();
  process.chdir(proj);
  try {
    const relative = path.join(".omnodex", "ingest.json");
    const cfg = await loadSealedConfig({ ...env, OMNODEX_INGEST_CONFIG: relative }, { home, projectDirs: [] });
    assert.equal(cfg.apiBase, "https://api.omnodex.com");
  } finally {
    process.chdir(prev);
  }
  assert.equal(sealedHome({ OMNODEX_HOME: ".omnodex" }), path.join(os.homedir(), ".omnodex"));
  assert.equal(sealedHome({ OMNODEX_HOME: home }), home);
});

test("loadSealedConfig: the home's file wins over a project's and may set the server", async () => {
  const { home, pair } = await setup();
  const base = { public_key: bytesToBase64(pair.publicKey) };
  fs.writeFileSync(
    path.join(home, "ingest.json"),
    JSON.stringify({ ...base, source_id: "src_fromhome", api_base: "https://ingest.example.com" }),
  );
  const proj = projectWith({ ...base, source_id: "src_fromfile" });
  const cfg = await loadSealedConfig({}, { home, projectDirs: [proj] });
  assert.equal(cfg.sourceId, "src_fromhome");
  assert.equal(cfg.apiBase, "https://ingest.example.com");
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

// --- host marker and shim names ----------------------------------------------

test("a host marker in the home enables capture, and the off switch still wins", async () => {
  assert.equal(shouldCapture("codex", {}, true), true);
  assert.equal(shouldCapture("codex", { OMNODEX_SEALED: "0" }, true), false);
  const t = await setup();
  const env = { ...t.env };
  delete env.OMNODEX_SEALED;
  await t.run("claude-code", CLAUDE_PRE, { env });
  await t.run("claude-code", CLAUDE_STOP, { env });
  assert.equal(t.calls.length, 0);
  fs.writeFileSync(path.join(t.home, HOST_MARKER_FILE), "1\n");
  await t.run("claude-code", CLAUDE_PRE, { env });
  await t.run("claude-code", CLAUDE_STOP, { env });
  assert.equal(t.calls.length, 1);
});

test("providerFromShimName reads the agent from a shim file name", () => {
  assert.equal(providerFromShimName("/h/.omnodex/sealed/claude-hook-shim.js"), "claude-code");
  assert.equal(providerFromShimName("C:\\h\\sealed\\codex-hook-shim.js"), "codex");
  assert.equal(providerFromShimName("/x/antigravity-hook-shim.js"), "antigravity");
  assert.equal(providerFromShimName("/x/omnodex-sealed-hook.js"), undefined);
  assert.equal(providerFromShimName("/x/opencode-plugin-shim.js"), undefined);
  assert.equal(providerFromShimName(undefined), undefined);
});
