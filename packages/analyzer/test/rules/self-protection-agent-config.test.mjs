/**
 * Self-protection rules for the agent's own configuration: removing the
 * Omnodex hook, MCP or plugin entry, switching hooks off, rewriting or
 * resetting hook files, and removing the plugin through the agent's CLI.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  COMMUNITY_RULES,
  RULE_SELF_PROTECTION_BASH,
  RULE_SELF_PROTECTION_HOOK_REMOVED,
  RULE_SELF_PROTECTION_HOOKS_DISABLED,
  RULE_SELF_PROTECTION_HOOK_FILE_REWRITE,
  RULE_SANDBOX_DISABLE_SETTINGS_WRITE,
} from "../../dist/rules/index.js";

function makeEvent(tool_name, parameters) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-10-21T00:00:00.000Z",
    recorded_at: "2026-10-21T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name,
    mcp_server: "builtin",
    parameters,
  };
}

function run(rule, tool, params) {
  return new RuleEngine([rule]).evaluate(makeEvent(tool, params));
}

const CLAUDE_HOOK = `{ "type": "command", "command": "node /home/case/.omnodex/bin/claude-hook-launcher.js", "async": true, "omnodex-managed": true }`;
const CODEX_HOOK = `{ "type": "command", "command": "node /home/case/.omnodex/bin/codex-hook-launcher.js", "omnodex-managed": true }`;
const OTHER_HOOK = `{ "type": "command", "command": "npx prettier --write" }`;

// ---- Registry ----

test("new rules are in the community set", () => {
  for (const rule of [RULE_SELF_PROTECTION_HOOK_REMOVED, RULE_SELF_PROTECTION_HOOKS_DISABLED, RULE_SELF_PROTECTION_HOOK_FILE_REWRITE]) {
    assert.ok(COMMUNITY_RULES.includes(rule), rule.rule_id);
  }
});

// ---- Hook, MCP or plugin entry removed by an edit ----

test("fires when an Edit removes the Omnodex hook entry from Claude Code settings", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/.claude/settings.json",
    old_string: `"PreToolUse": [{ "matcher": "*", "hooks": [${CLAUDE_HOOK}] }]`,
    new_string: `"PreToolUse": []`,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "self_protection");
  assert.match(findings[0].description, /Omnodex hook entry/);
  assert.match(findings[0].description, /\.claude\/settings\.json/);
});

test("fires for a settings file moved with CLAUDE_CONFIG_DIR", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/agent-config/settings.json",
    old_string: `"hooks": [${CLAUDE_HOOK}, ${OTHER_HOOK}]`,
    new_string: `"hooks": [${OTHER_HOOK}]`,
  });
  assert.equal(findings.length, 1);
});

test("fires when one edit of a MultiEdit removes the entry", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "MultiEdit", {
    file_path: "/home/case/project/.claude/settings.local.json",
    edits: [
      { old_string: `"allow": []`, new_string: `"allow": ["Bash(npm test)"]` },
      { old_string: `"hooks": [${CLAUDE_HOOK}]`, new_string: `"hooks": []` },
    ],
  });
  assert.equal(findings.length, 1);
});

test("fires when an apply_patch removes the entry from Codex hooks.json", () => {
  const patch = [
    "*** Begin Patch",
    "*** Update File: /home/case/.codex/hooks.json",
    "@@",
    `-      ${CODEX_HOOK},`,
    `       ${OTHER_HOOK}`,
    "*** End Patch",
  ].join("\n");
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "apply_patch", { command: patch });
  assert.equal(findings.length, 1);
  assert.match(findings[0].description, /hooks\.json/);
});

test("fires when the Omnodex MCP server is removed from .claude.json", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/.claude.json",
    old_string: `"mcpServers": { "omnodex": { "command": "node" }, "github": {} }`,
    new_string: `"mcpServers": { "github": {} }`,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].description, /MCP server entry/);
});

test("fires when the Omnodex MCP server is removed from Codex config.toml", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/.codex/config.toml",
    old_string: `[mcp_servers.omnodex]\ncommand = "node"\n\n[mcp_servers.github]`,
    new_string: `[mcp_servers.github]`,
  });
  assert.equal(findings.length, 1);
});

test("fires when the Omnodex plugin is switched off in Claude Code settings", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/.claude/settings.json",
    old_string: `"omnodex-cowork@omnodex-local": true`,
    new_string: `"omnodex-cowork@omnodex-local": false`,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].description, /Omnodex plugin/);
});

test("no finding for an edit to other keys in the same settings file", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/.claude/settings.json",
    old_string: `"allow": ["Bash(ls)"]`,
    new_string: `"allow": ["Bash(ls)", "Bash(npm test)"]`,
  });
  assert.equal(findings.length, 0);
});

test("no finding when an edit keeps the entry (changing its timeout)", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/.claude/settings.json",
    old_string: CLAUDE_HOOK,
    new_string: CLAUDE_HOOK.replace(`"async": true`, `"async": true, "timeout": 30`),
  });
  assert.equal(findings.length, 0);
});

test("no finding when a document mentioning the launcher is edited", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Edit", {
    file_path: "/home/case/project/docs/setup.md",
    old_string: "The hook runs claude-hook-launcher.js.",
    new_string: "The hook runs a launcher.",
  });
  assert.equal(findings.length, 0);
});

test("pairs removed text with its own file in a multi-file patch", () => {
  const patch = [
    "*** Begin Patch",
    "*** Update File: /home/case/project/README.md",
    "@@",
    "-Hooks call codex-hook-launcher.js",
    "+Hooks call a launcher",
    "*** Update File: /home/case/.codex/hooks.json",
    "@@",
    `-      ${OTHER_HOOK}`,
    `+      ${OTHER_HOOK.replace("prettier", "eslint")}`,
    "*** End Patch",
  ].join("\n");
  assert.equal(run(RULE_SELF_PROTECTION_HOOK_REMOVED, "apply_patch", { command: patch }).length, 0);
});

test("no finding for reading the settings file", () => {
  assert.equal(run(RULE_SELF_PROTECTION_HOOK_REMOVED, "Read", { file_path: "/home/case/.claude/settings.json" }).length, 0);
});

// ---- All hooks switched off ----

test("fires when an edit sets disableAllHooks", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "Edit", {
    file_path: "/home/case/.claude/settings.json",
    old_string: `{\n  "model": "opus"`,
    new_string: `{\n  "disableAllHooks": true,\n  "model": "opus"`,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.match(findings[0].description, /disableAllHooks/);
});

test("fires when a whole settings file is written with disableAllHooks", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "Write", {
    file_path: "/home/case/project/.claude/settings.local.json",
    content: `{ "disableAllHooks": true }`,
  });
  assert.equal(findings.length, 1);
});

test("no finding when disableAllHooks is set to false", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "Edit", {
    file_path: "/home/case/.claude/settings.json",
    old_string: `"disableAllHooks": true`,
    new_string: `"disableAllHooks": false`,
  });
  assert.equal(findings.length, 0);
});

// ---- Hook file rewritten or deleted without the entry ----

test("fires (MEDIUM) when Codex hooks.json is rewritten without the entry", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_FILE_REWRITE, "Write", {
    file_path: "/home/case/.codex/hooks.json",
    content: `{ "hooks": { "PreToolUse": [${OTHER_HOOK}] } }`,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
});

test("fires when a patch deletes the Antigravity hooks file", () => {
  const patch = "*** Begin Patch\n*** Delete File: /home/case/.gemini/config/hooks.json\n*** End Patch";
  assert.equal(run(RULE_SELF_PROTECTION_HOOK_FILE_REWRITE, "apply_patch", { command: patch }).length, 1);
});

test("no finding for a settings file written with no hooks section", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_FILE_REWRITE, "Write", {
    file_path: "/home/case/project/.claude/settings.json",
    content: `{ "permissions": { "allow": ["Bash(npm test)"] } }`,
  });
  assert.equal(findings.length, 0);
});

test("no finding when the rewritten hook file keeps the entry", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_FILE_REWRITE, "Write", {
    file_path: "/home/case/.codex/hooks.json",
    content: `{ "hooks": { "PreToolUse": [${CODEX_HOOK}, ${OTHER_HOOK}] } }`,
  });
  assert.equal(findings.length, 0);
});

// ---- Shell: the agent's CLI, hook files, disableAllHooks ----

const shellFires = [
  "claude plugin uninstall omnodex-cowork@omnodex-local",
  "claude plugin disable omnodex-cowork",
  "claude mcp remove omnodex",
  "codex mcp remove omnodex",
  "codex plugin remove omnodex-codex",
  "rm -rf ~/.codex/plugins/omnodex-codex",
  "rm ~/.codex/hooks.json",
  "truncate -s 0 ~/.claude/settings.json",
  "git checkout -- .claude/settings.json",
  "git restore .claude/settings.local.json",
  "echo '{}' > ~/.claude/settings.json",
  "cp /tmp/clean.json ~/.gemini/config/hooks.json",
  'mv new.json "$CODEX_HOME/hooks.json"',
  `python3 -c "import json; json.dump({}, open('/home/case/.claude/settings.json', 'w'))"`,
  "jq '.disableAllHooks = true' settings.json > tmp.json",
];

for (const command of shellFires) {
  test(`shell fires: ${command}`, () => {
    const findings = run(RULE_SELF_PROTECTION_BASH, "Bash", { command });
    assert.equal(findings.length, 1, command);
    assert.equal(findings[0].severity, "HIGH");
  });
}

const shellQuiet = [
  "claude plugin install omnodex-cowork@omnodex-local --scope user",
  "claude mcp remove github",
  "codex mcp list",
  "cat ~/.claude/settings.json",
  "cp ~/.claude/settings.json /tmp/settings-backup.json",
  "jq .hooks ~/.codex/hooks.json",
  `python3 -c "print(open('/home/case/.claude/settings.json').read())"`,
  "git diff .claude/settings.json",
];

for (const command of shellQuiet) {
  test(`shell quiet: ${command}`, () => {
    assert.equal(run(RULE_SELF_PROTECTION_BASH, "Bash", { command }).length, 0, command);
  });
}

test("a hook-file reset staged in a script is reported one severity lower", () => {
  const findings = run(RULE_SELF_PROTECTION_BASH, "Write", {
    file_path: "/home/case/project/scripts/cleanup.sh",
    content: "#!/bin/sh\nrm ~/.codex/hooks.json\n",
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
});

test("a hook-file command in a document is not reported", () => {
  const findings = run(RULE_SELF_PROTECTION_BASH, "Write", {
    file_path: "/home/case/project/docs/uninstall.md",
    content: "To remove it by hand: `rm ~/.codex/hooks.json`",
  });
  assert.equal(findings.length, 0);
});

// ---- Sandbox-disable paths ----

test("sandbox: fires on Codex config.toml with danger-full-access", () => {
  const findings = run(RULE_SANDBOX_DISABLE_SETTINGS_WRITE, "Edit", {
    file_path: "/home/case/.codex/config.toml",
    old_string: `sandbox_mode = "workspace-write"`,
    new_string: `sandbox_mode = "danger-full-access"`,
  });
  assert.equal(findings.length, 1);
});

test("sandbox: fires on Antigravity settings under .gemini/config", () => {
  const findings = run(RULE_SANDBOX_DISABLE_SETTINGS_WRITE, "Write", {
    file_path: "/home/case/.gemini/config/settings.json",
    content: `{ "sandbox_mode": "none" }`,
  });
  assert.equal(findings.length, 1);
});

test("sandbox: quiet on Codex config.toml with workspace-write", () => {
  const findings = run(RULE_SANDBOX_DISABLE_SETTINGS_WRITE, "Write", {
    file_path: "/home/case/.codex/config.toml",
    content: `sandbox_mode = "workspace-write"\nmodel = "gpt-6"`,
  });
  assert.equal(findings.length, 0);
});

// ---- Codex and Antigravity disable controls and tool shapes ----

test("fires when Codex config.toml turns hooks off", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "Edit", {
    file_path: "/home/case/.codex/config.toml",
    old_string: `[features]\nweb_search = true`,
    new_string: `[features]\nweb_search = true\nhooks = false`,
  });
  assert.equal(findings.length, 1);
  assert.match(findings[0].description, /hooks = false/);
});

test("fires on the older codex_hooks key in an apply_patch", () => {
  const patch = "*** Begin Patch\n*** Update File: /home/case/.codex/config.toml\n@@\n-codex_hooks = true\n+codex_hooks = false\n*** End Patch";
  assert.equal(run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "apply_patch", { command: patch }).length, 1);
});

test("no finding for allow_managed_hooks_only in Codex config", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "Edit", {
    file_path: "/home/case/.codex/config.toml",
    old_string: `[features]`,
    new_string: `[features]\nallow_managed_hooks_only = false`,
  });
  assert.equal(findings.length, 0);
});

test("fires when the Omnodex hook group is disabled in Antigravity hooks.json", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "replace_file_content", {
    TargetFile: "/home/case/.gemini/config/hooks.json",
    TargetContent: `"omnodex": { "enabled": true, "command": "node /home/case/.omnodex/bin/antigravity-hook-launcher.js" }`,
    ReplacementContent: `"omnodex": { "enabled": false, "command": "node /home/case/.omnodex/bin/antigravity-hook-launcher.js" }`,
  });
  assert.equal(findings.length, 1);
});

test("no finding when another Antigravity hook group is disabled", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOKS_DISABLED, "replace_file_content", {
    TargetFile: "/home/case/.gemini/config/hooks.json",
    TargetContent: `"lint": { "enabled": true, "command": "npx eslint" }`,
    ReplacementContent: `"lint": { "enabled": false, "command": "npx eslint" }`,
  });
  assert.equal(findings.length, 0);
});

test("fires when Antigravity's multi_replace_file_content removes the entry", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_REMOVED, "multi_replace_file_content", {
    TargetFile: "/home/case/.gemini/config/hooks.json",
    ReplacementChunks: [
      { TargetContent: `"command": "node /home/case/.omnodex/bin/antigravity-hook-launcher.js"`, ReplacementContent: `"command": "true"` },
    ],
  });
  assert.equal(findings.length, 1);
});

test("fires (MEDIUM) when Antigravity's write_to_file rewrites hooks.json without the entry", () => {
  const findings = run(RULE_SELF_PROTECTION_HOOK_FILE_REWRITE, "write_to_file", {
    TargetFile: "/home/case/.gemini/config/hooks.json",
    CodeContent: `{ "hooks": {} }`,
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
});

for (const command of [
  "agy plugin disable omnodex-antigravity",
  "agy mcp remove omnodex",
  "agy mcp disable omnodex",
  "codex --disable hooks exec 'refactor'",
  "codex -c features.hooks=false exec 'refactor'",
  "claude --bare -p 'summarize'",
  `claude --settings '{"disableAllHooks":true}' -p 'summarize'`,
]) {
  test(`shell fires: ${command}`, () => {
    assert.equal(run(RULE_SELF_PROTECTION_BASH, "Bash", { command }).length, 1, command);
  });
}

for (const command of ["agy mcp list", "codex --disable web_search exec 'x'", "claude -p 'summarize'"]) {
  test(`shell quiet: ${command}`, () => {
    assert.equal(run(RULE_SELF_PROTECTION_BASH, "Bash", { command }).length, 0, command);
  });
}
