// Validation: in guardrails mode the Claude Code shim hands PreToolUse to
// the guardrails module, writes its answer on stdout before anything slow,
// stamps findings with whether they held the call, defers its cloud push,
// and lets the call run when it cannot judge it or has no module.
//
// Run: node --test packages/hooks-provider/test/guardrails.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { findingsIn, guardrailsCases, loggedEvents, runShim, scratch } from "../../analyzer/test/helpers/shim-harness.mjs";
import { installModule } from "../../analyzer/test/helpers/make-module.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/claude-hook-shim.js");

const preToolUse = (sessionId, filePath = "/etc/shadow") => ({
  session_id: sessionId,
  cwd: "/tmp/repo",
  hook_event_name: "PreToolUse",
  tool_name: "Read",
  tool_use_id: `tu-${sessionId}`,
  tool_input: { file_path: filePath },
});

guardrailsCases(test, assert, {
  shim: SHIM,
  host: "claude-code",
  sensitiveRead: (id) => ({ payload: preToolUse(id) }),
});

async function setup(t, enforcement) {
  const s = await scratch(t);
  await mkdir(s.home, { recursive: true });
  await writeFile(path.join(s.home, "omnodex-config.json"), JSON.stringify({ enforcement }));
  return { s, env: installModule(s.home).env };
}

test("a harmless call writes nothing on stdout", async (t) => {
  const { s, env } = await setup(t, { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
  const result = await runShim(SHIM, s, preToolUse("s-g-clean", "/tmp/repo/README.md"), { env });
  assert.equal(result.stdout, "");
});

test("rules that run out of time with on_error block: the module's answer is written", async (t) => {
  const { s, env } = await setup(t, { mode: "guardrails", on_error: "block" });
  const result = await runShim(SHIM, s, preToolUse("s-g-block"), {
    env: { ...env, OMNODEX_TEST_CAPTURE: "hang", OMNODEX_CAPTURE_DETECT_TIMEOUT_MS: "150" },
  });
  assert.equal(JSON.parse(result.stdout).could_not_check, true);
  const error = (await loggedEvents(s.home)).find((e) => e.event_type === "risk.enforcement_error");
  assert.equal(error.outcome, "blocked");
  assert.equal(error.reason, "timeout");
  assert.equal(error.related_event_id, "tu-s-g-block");
});

test("a recording pause does not switch guardrails off", async (t) => {
  const { s, env } = await setup(t, { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
  const { startPause } = await import("../../event-log/dist/index.js");
  await startPause(s.home, "record", { untilMs: null, by: "cli" });
  const result = await runShim(SHIM, s, preToolUse("s-g-paused"), { env });
  assert.equal(JSON.parse(result.stdout).test_decision, "deny");
  assert.equal(findingsIn(await loggedEvents(s.home)).length, 0, "nothing is recorded while recording is paused");
});

test("other hook events never write a decision", async (t) => {
  const { s, env } = await setup(t, { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
  const result = await runShim(SHIM, s, {
    session_id: "s-g-post", cwd: "/tmp/repo", hook_event_name: "PostToolUse", tool_name: "Read",
    tool_use_id: "tu-x", tool_input: { file_path: "/etc/shadow" }, tool_response: {},
  }, { env });
  assert.equal(result.stdout, "");
});
