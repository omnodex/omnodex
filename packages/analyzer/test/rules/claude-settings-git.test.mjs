/**
 * RULE_CREDENTIAL_SETTINGS_LOCAL_GIT: git commands that name Claude Code's
 * local settings file.
 */

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CREDENTIAL_SETTINGS_LOCAL_GIT } from "../../dist/rules/index.js";

let n = 0;
function bash(command) {
  n++;
  return {
    schema_version: 1,
    event_id: `evt-cs-${n}`,
    session_id: "sess-cs",
    occurred_at: "2026-11-13T00:00:00.000Z",
    recorded_at: "2026-11-13T00:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-cs-${n}`,
    tool_name: "Bash",
    mcp_server: "builtin",
    parameters: { command },
  };
}
const engine = new RuleEngine([RULE_CREDENTIAL_SETTINGS_LOCAL_GIT]);
const run = (command) => engine.evaluate(bash(command));

const MUST_FIRE = [
  ["git add the file", "git add .claude/settings.local.json"],
  ["git add -f the file", "git add -f .claude/settings.local.json"],
  ["git add with other paths", "git add src/index.ts .claude/settings.local.json"],
  ["git -C dir add", "git -C app add .claude/settings.local.json"],
  ["git add from inside .claude", "git add settings.local.json"],
  ["git add a glob of local settings", "git add .claude/*.local.json"],
  ["git commit naming the file", "git commit .claude/settings.local.json -m wip"],
  ["git add after another command", "cd app && git add .claude/settings.local.json"],
  ["git stash push of the file", "git stash push -- .claude/settings.local.json"],
  ["Windows path", "git add .claude\\settings.local.json"],
];

const MUST_NOT_FIRE = [
  ["git add the shared settings file", "git add .claude/settings.json"],
  ["git add source", "git add src/rules.ts"],
  ["git add everything", "git add -A"],
  ["git commit -am", 'git commit -am "update rules"'],
  ["git status", "git status"],
  ["git check-ignore on the file", "git check-ignore -v .claude/settings.local.json"],
  ["cat the file", "cat .claude/settings.local.json"],
  ["git log", "git log --oneline"],
  ["ls then git add elsewhere", "ls .claude/settings.local.json; git add README.md"],
  ["git diff of the file", "git diff .claude/settings.local.json"],
];

describe("settings file in git: MUST_FIRE", () => {
  for (const [name, command] of MUST_FIRE) {
    test(name, () => {
      const findings = run(command);
      assert.equal(findings.length, 1, `no finding for: ${command}`);
      assert.equal(findings[0].severity, "HIGH");
      assert.equal(findings[0].rule_id, "RULE_CREDENTIAL_SETTINGS_LOCAL_GIT");
    });
  }
});

describe("settings file in git: MUST_NOT_FIRE", () => {
  for (const [name, command] of MUST_NOT_FIRE) {
    test(name, () => {
      assert.deepEqual(run(command), [], `unexpected finding for: ${command}`);
    });
  }
});
