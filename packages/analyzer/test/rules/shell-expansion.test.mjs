/**
 * RULE_THREAT_SHELL_EXPANSION_IN_TEXT: backticks and $( ) inside a
 * double-quoted text argument of git, gh or glab.
 */

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_THREAT_SHELL_EXPANSION_IN_TEXT } from "../../dist/rules/index.js";

let n = 0;
function bash(command) {
  n++;
  return {
    schema_version: 1,
    event_id: `evt-se-${n}`,
    session_id: "sess-se",
    occurred_at: "2026-11-13T00:00:00.000Z",
    recorded_at: "2026-11-13T00:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-se-${n}`,
    tool_name: "Bash",
    mcp_server: "builtin",
    parameters: { command },
  };
}
const engine = new RuleEngine([RULE_THREAT_SHELL_EXPANSION_IN_TEXT]);
const run = (command) => engine.evaluate(bash(command));

const MUST_FIRE = [
  ["gh pr create --body with a code span", 'gh pr create --title "Fix" --body "Run `docker volume prune` to reset"', "backtick-expansion"],
  ["gh issue comment --body", 'gh issue comment 12 --body "see `rm -rf build` output"', "backtick-expansion"],
  ["git commit -m with backticks", 'git commit -m "fix `parse()` crash"', "backtick-expansion"],
  ["git commit --message=", 'git commit --message="handle `null` input"', "backtick-expansion"],
  ["git commit -am", 'git commit -am "tidy `utils`"', "backtick-expansion"],
  ["gh release create --notes", 'gh release create v1 --notes "adds `--force` flag"', "backtick-expansion"],
  ["glab mr create --description", 'glab mr create --description "uses `make clean`"', "backtick-expansion"],
  ["backticks late in a long body", 'gh pr create --body "Summary line one.\n\n- item with `code` here"', "backtick-expansion"],
  ["$( ) in a body", 'gh pr create --body "Built at $(date)"', "command-substitution"],
  ["$( ) in a commit message", 'git commit -m "bump to $(cat VERSION)"', "command-substitution"],
  ["unquoted heredoc delimiter still expands", 'git commit -m "$(cat <<EOF\nfix `x`\nEOF\n)"', "command-substitution"],
  ["after an escaped quote", 'git commit -m "say \\"hi\\" then `whoami`"', "backtick-expansion"],
];

const MUST_NOT_FIRE = [
  ["single-quoted body with backticks", "gh pr create --body 'Run `docker volume prune` to reset'"],
  ["single-quoted commit message", "git commit -m 'fix `parse()` crash'"],
  ["double quotes, no expansion", 'git commit -m "fix parse crash"'],
  ["escaped backticks", 'gh pr create --body "Run \\`docker volume prune\\` to reset"'],
  ["escaped dollar paren", 'git commit -m "literal \\$(date)"'],
  ["quoted heredoc (single quote delimiter)", "git commit -m \"$(cat <<'EOF'\nfix `parse()` crash\nEOF\n)\""],
  ["quoted heredoc (double quote delimiter)", 'git commit -m "$(cat <<"EOF"\nfix `parse()` crash\nEOF\n)"'],
  ["backslash-escaped heredoc delimiter", 'git commit -m "$(cat <<\\EOF\nplain text\nEOF\n)"'],
  ["arithmetic, not a command", 'git commit -m "total $((1+2))"'],
  ["body from a file", "gh pr create --body-file body.md"],
  ["backticks outside any text flag", 'git log --grep "`x`"'],
  ["backticks in a non-git command", 'echo "run `ls`"'],
  ["dollar variable", 'git commit -m "release $VERSION"'],
  ["single-quoted text holding double quotes and backticks", "git commit -m 'say \"hi\" then `whoami`'"],
  ["plain git status", "git status --short"],
];

describe("shell expansion in text: MUST_FIRE", () => {
  for (const [name, command, type] of MUST_FIRE) {
    test(name, () => {
      const findings = run(command);
      assert.equal(findings.length, 1, `no finding for: ${command}`);
      assert.equal(findings[0].severity, "MEDIUM");
      assert.ok(findings[0].description.includes(type), findings[0].description);
    });
  }
});

describe("shell expansion in text: MUST_NOT_FIRE", () => {
  for (const [name, command] of MUST_NOT_FIRE) {
    test(name, () => {
      assert.deepEqual(run(command), [], `unexpected finding for: ${command}`);
    });
  }
});
