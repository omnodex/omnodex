/**
 * Sandbox disable detection rule unit tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_SANDBOX_DISABLE_SETTINGS_WRITE,
  RULE_SANDBOX_DISABLE_BASH,
} from "../../dist/rules/index.js";

function makeEvent(overrides = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-06-02T00:00:00.000Z",
    recorded_at: "2026-06-02T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: "Write",
    mcp_server: "builtin",
    parameters: {},
    ...overrides,
  };
}

// ---- SETTINGS WRITE ----

test("fires on Claude settings with sandbox: false", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_SETTINGS_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.claude/settings.json",
      content: '{"sandbox": false, "theme": "dark"}',
    },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "sandbox_disable");
});

test("fires on Claude settings.local.json with toolSandboxing: false", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_SETTINGS_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.claude/settings.local.json",
      content: '{"toolSandboxing": false}',
    },
  }));
  assert.equal(findings.length, 1);
});

test("fires on Codex config with skip-sandbox", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_SETTINGS_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.codex/config.json",
      content: '{"dangerously-skip-permissions": true}',
    },
  }));
  assert.equal(findings.length, 1);
});

test("fires on Gemini config with sandbox_mode: none", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_SETTINGS_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.gemini/config.json",
      content: '{"sandbox_mode": "none"}',
    },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on Claude settings without sandbox content", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_SETTINGS_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.claude/settings.json",
      content: '{"theme": "dark", "model": "opus"}',
    },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on unrelated settings file", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_SETTINGS_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.vscode/settings.json",
      content: '{"sandbox": false}',
    },
  }));
  assert.equal(findings.length, 0);
});

// ---- BASH ----

test("fires on --dangerously-skip-permissions flag", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "claude --dangerously-skip-permissions" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("fires on GEMINI_SANDBOX=none", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "export GEMINI_SANDBOX=none && gemini-cli run" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on sed targeting claude settings", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "sed -i 's/true/false/' ~/.claude/settings.json" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on normal claude command", () => {
  const engine = new RuleEngine([RULE_SANDBOX_DISABLE_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "claude --help" },
  }));
  assert.equal(findings.length, 0);
});
