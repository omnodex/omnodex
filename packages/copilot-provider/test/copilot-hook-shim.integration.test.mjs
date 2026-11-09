// Validation: the Copilot hook shim records a session end to end, keeps the
// contract (exit 0, one valid JSON document) on any input, and denies a call
// only through the guardrails module.
//
// Run: node --test packages/copilot-provider/test/copilot-hook-shim.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loggedEvents, runShim, scratch } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/copilot-hook-shim.js");
const base = (id) => ({ session_id: id, cwd: "/tmp/repo", timestamp: new Date().toISOString() });

test("a session: start, prompt, a paired tool call, end", async (t) => {
  const s = await scratch(t);
  const id = "s-copilot-flow";
  const input = { command: "echo hi" };
  for (const payload of [
    { ...base(id), hook_event_name: "SessionStart", source: "startup" },
    { ...base(id), hook_event_name: "UserPromptSubmit", prompt: "say hi" },
    { ...base(id), hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: input },
    { ...base(id), hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: input, tool_result: { result_type: "success", text_result_for_llm: "hi" } },
    { ...base(id), hook_event_name: "Stop", stop_reason: "end_turn" },
    { ...base(id), hook_event_name: "SessionEnd", reason: "complete" },
  ]) {
    const r = await runShim(SHIM, s, payload);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, "{}", payload.hook_event_name);
  }
  const events = await loggedEvents(s.home);
  assert.deepEqual(
    events.filter((e) => e.event_type !== "risk.detected").map((e) => e.event_type),
    ["session.started", "prompt.submitted", "tool.invoked", "tool.completed", "session.ended"],
  );
  assert.ok(events.every((e) => e.interceptor === "copilot-hook" || e.interceptor === "analyzer"));
  const invoked = events.find((e) => e.event_type === "tool.invoked");
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.ok(invoked.tool_call_id, "the pre-hook made a call id");
  assert.equal(completed.tool_call_id, invoked.tool_call_id, "the post-hook pairs with it");
  assert.equal(events.find((e) => e.event_type === "session.started").platform, "copilot");
});

test("two identical calls in flight keep their own ids, in order", async (t) => {
  const s = await scratch(t);
  const id = "s-copilot-twins";
  const call = { ...base(id), tool_name: "Bash", tool_input: { command: "sleep 1" } };
  await runShim(SHIM, s, { ...call, hook_event_name: "PreToolUse" });
  await runShim(SHIM, s, { ...call, hook_event_name: "PreToolUse" });
  await runShim(SHIM, s, { ...call, hook_event_name: "PostToolUse", tool_result: "ok" });
  await runShim(SHIM, s, { ...call, hook_event_name: "PostToolUse", tool_result: "ok" });
  const events = await loggedEvents(s.home);
  const invoked = events.filter((e) => e.event_type === "tool.invoked").map((e) => e.tool_call_id);
  const completed = events.filter((e) => e.event_type === "tool.completed").map((e) => e.tool_call_id);
  assert.equal(new Set(invoked).size, 2);
  assert.deepEqual(completed, invoked);
});

test("a failed call is recorded as an error", async (t) => {
  const s = await scratch(t);
  const id = "s-copilot-fail";
  const call = { ...base(id), tool_name: "Bash", tool_input: { command: "false" } };
  await runShim(SHIM, s, { ...call, hook_event_name: "PreToolUse" });
  await runShim(SHIM, s, { ...call, hook_event_name: "PostToolUseFailure", error: "exit 1" });
  const done = (await loggedEvents(s.home)).find((e) => e.event_type === "tool.completed");
  assert.equal(done.status, "error");
});

test("the contract holds on garbage: exit 0 and one valid JSON document, nothing recorded", async (t) => {
  const s = await scratch(t);
  for (const raw of ["", "not json", "[]", "null", '{"hook_event_name":"PreToolUse"}', '{"session_id":"x","hook_event_name":"Nope"}', "\u0000\u0001"]) {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [SHIM], {
        env: { ...process.env, HOME: s.userHome, USERPROFILE: s.userHome, OMNODEX_HOME: s.home, OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0" },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout }));
      child.stdin.end(raw);
    });
    assert.equal(result.code, 0, JSON.stringify(raw));
    assert.doesNotThrow(() => JSON.parse(result.stdout), JSON.stringify(raw));
    assert.equal(result.stdout, "{}", JSON.stringify(raw));
  }
  assert.deepEqual(await loggedEvents(s.home), []);
});

test("a home the shim cannot use does not fail the hook: no decision, exit 0", async (t) => {
  const s = await scratch(t);
  // A path beneath a regular file cannot be created.
  const r = await runShim(SHIM, { ...s, home: path.join(fileURLToPath(import.meta.url), "not-a-dir") }, { ...base("s-copilot-ro"), hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } });
  assert.equal(r.code, 0);
  assert.equal(r.stdout, "{}");
});
