import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_SELF_PROTECTION_BASH, RULE_SELF_PROTECTION_HOOK_REMOVED } from "../../dist/rules/index.js";

let n = 0;
const event = (tool_name, parameters) => ({ schema_version: 1, event_id: `evt-case-${++n}`, session_id: "case", occurred_at: "2026-11-18T12:00:00Z", recorded_at: "2026-11-18T12:00:00Z", interceptor: "mock", event_type: "tool.invoked", tool_call_id: `call-case-${n}`, tool_name, parameters });
const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
const run = (command) => engine.evaluate(event("Bash", { command }));

for (const file of [".claude/settings.local.json", ".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", ".github/hooks/omnodex.json", ".config/opencode/plugins/omnodex.js"]) {
  for (const prefix of ["git rm --cached", "git rm -r --cached", "git -C /home/case/repo rm --cached"]) {
    const command = `${prefix} ${file}`;
    test(`MUST_NOT_FIRE: untracking keeps the hook file: ${command}`, () => assert.deepEqual(run(command), []));
  }
  for (const prefix of ["git rm", "git rm -r", "rm"]) {
    const command = `${prefix} ${file}`;
    test(`MUST_FIRE: deleting the hook file: ${command}`, () => assert.equal(run(command)[0]?.severity, "HIGH"));
  }
}

for (const command of [
  'git rm --cached -- ".claude/settings.local.json"',
  "git rm .claude/settings.local.json --cached",
  "git rm -r --cached .claude/settings.local.json && git status",
  "rm README.md && git rm --cached .claude/settings.local.json",
  "git rm .claude/settings.local.json --cached; git status",
]) test(`MUST_NOT_FIRE: index-only removal: ${command}`, () => assert.deepEqual(run(command), []));

for (const command of [
  "git rm --cached .claude/settings.local.json && rm .claude/settings.local.json",
  "git rm --cached README.md; git rm .claude/settings.local.json",
  "git rm .claude/settings.local.json; git rm --cached README.md",
  "git rm .claude/settings.local.json && echo --cached",
  "git rm .claude/settings.local.json\necho --cached",
  "git\nrm --cached .claude/settings.local.json",
  "git rm -- .claude/settings.local.json --cached",
  "mv clean.json .claude/settings.local.json",
  "mv .claude/settings.local.json /tmp/case-settings.json",
  "git rm --cached .claude/settings.local.json && mv .claude/settings.local.json /tmp/case-settings.json",
  "git -C /home/case/repo rm .claude/settings.local.json",
]) test(`MUST_FIRE: untracking does not hide a destructive action: ${command}`, () => assert.equal(run(command)[0]?.severity, "HIGH"));

test("MUST_FIRE: an edit that removes hooks is still detected", () => {
  const removed = new RuleEngine([RULE_SELF_PROTECTION_HOOK_REMOVED]);
  assert.equal(removed.evaluate(event("Edit", { file_path: "/home/case/repo/.claude/settings.local.json", old_string: '"command": "node claude-hook-launcher.js"', new_string: "" }))[0]?.severity, "HIGH");
});

test("MUST_NOT_FIRE: an unrelated edit keeps the hook entry", () => {
  const removed = new RuleEngine([RULE_SELF_PROTECTION_HOOK_REMOVED]);
  assert.deepEqual(removed.evaluate(event("Edit", { file_path: "/home/case/repo/.claude/settings.local.json", old_string: '"timeout": 10', new_string: '"timeout": 20' })), []);
});
