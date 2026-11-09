// Validation: Copilot runs the hooks in a project's .claude/settings.json, so
// the Claude Code shim sees Copilot's calls. Where Omnodex records Copilot
// itself, the Claude Code shim steps aside so a call is not recorded twice,
// once of them mislabeled; everywhere else it records as before.
//
// Run: node --test packages/hooks-provider/test/copilot-run.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { loggedEvents, runShim, scratch } from "../../analyzer/test/helpers/shim-harness.mjs";
import { copilotCaptureInstalled, looksLikeCopilotRun } from "../dist/copilot-run.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/claude-hook-shim.js");

// What Copilot sends under a PascalCase name: no transcript_path, no tool_use_id.
const copilotCall = (id) => ({ session_id: id, cwd: "/tmp/repo", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } });
// What Claude Code sends: transcript_path, permission_mode and tool_use_id.
const claudeCall = (id) => ({ ...copilotCall(id), transcript_path: "/tmp/t.jsonl", permission_mode: "default", tool_use_id: "tu-1" });

async function installRegistry(home, installations) {
  await mkdir(home, { recursive: true });
  await writeFile(path.join(home, "installations.json"), JSON.stringify({ version: 2, installations }));
}

test("a payload is told apart by the fields only Claude Code sends", () => {
  assert.equal(looksLikeCopilotRun(copilotCall("s")), true);
  assert.equal(looksLikeCopilotRun({ ...copilotCall("s"), hook_event_name: "PostToolUse" }), true);
  assert.equal(looksLikeCopilotRun({ session_id: "s", hook_event_name: "SessionStart" }), true);
  assert.equal(looksLikeCopilotRun(claudeCall("s")), false);
  assert.equal(looksLikeCopilotRun({ ...copilotCall("s"), tool_use_id: "tu" }), false, "a call id means Claude Code");
  assert.equal(looksLikeCopilotRun({ session_id: "s", hook_event_name: "SessionStart", transcript_path: "/t" }), false);
  assert.equal(looksLikeCopilotRun({ session_id: "s", hook_event_name: "SessionStart", permission_mode: "plan" }), false);
  for (const odd of [null, undefined, "x", 1, [], {}, { hook_event_name: "SubagentStop" }]) assert.equal(looksLikeCopilotRun(odd), false);
});

test("Copilot capture counts as installed from the registry or the every-project list", async (t) => {
  const s = await scratch(t);
  assert.equal(await copilotCaptureInstalled(s.home), false, "no files");
  await installRegistry(s.home, [{ target: "claude-code", component: "hooks" }]);
  assert.equal(await copilotCaptureInstalled(s.home), false);
  await installRegistry(s.home, [{ target: "copilot", component: "hooks" }]);
  assert.equal(await copilotCaptureInstalled(s.home), true);
  const e = await scratch(t);
  await mkdir(e.home, { recursive: true });
  await writeFile(path.join(e.home, "hook-scope.json"), JSON.stringify({ version: 1, everywhere: ["copilot"], excluded: {} }));
  assert.equal(await copilotCaptureInstalled(e.home), true);
  await writeFile(path.join(e.home, "hook-scope.json"), "{broken");
  assert.equal(await copilotCaptureInstalled(e.home), false, "damaged files do not throw");
});

test("a Copilot run reaching the Claude Code shim is not recorded when Copilot is recorded directly", async (t) => {
  const s = await scratch(t);
  await installRegistry(s.home, [{ target: "claude-code", component: "hooks" }, { target: "copilot", component: "hooks" }]);
  const r = await runShim(SHIM, s, copilotCall("s-dc-skip"));
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(await loggedEvents(s.home), []);
});

test("it is recorded as before when Copilot is not installed, and a real Claude Code call is always recorded", async (t) => {
  const s = await scratch(t);
  await installRegistry(s.home, [{ target: "claude-code", component: "hooks" }]);
  assert.equal((await runShim(SHIM, s, copilotCall("s-dc-none"))).code, 0);
  assert.ok((await loggedEvents(s.home)).some((e) => e.session_id === "s-dc-none" && e.event_type === "tool.invoked"));

  const both = await scratch(t);
  await installRegistry(both.home, [{ target: "claude-code", component: "hooks" }, { target: "copilot", component: "hooks" }]);
  assert.equal((await runShim(SHIM, both, claudeCall("s-dc-claude"))).code, 0);
  const events = await loggedEvents(both.home);
  assert.ok(events.some((e) => e.session_id === "s-dc-claude" && e.event_type === "tool.invoked" && e.interceptor === "claude-code-hook"));
});
