/**
 * Cross-agent authentication access rule unit tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CROSS_AGENT_AUTH_ACCESS } from "../../dist/rules/index.js";

const engine = new RuleEngine([RULE_CROSS_AGENT_AUTH_ACCESS]);

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
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: {},
    ...overrides,
  };
}

test("fires on reading Cursor auth token", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.cursor/auth-token.json" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "cross_agent");
  assert.ok(findings[0].description.includes("Cursor auth file"));
});

test("fires on reading Windsurf auth", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.windsurf/auth-session.json" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on reading Gemini CLI credential", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.gemini/auth-credentials.json" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on reading Codex auth token", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.codex/auth-token" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on reading Copilot hosts.json", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.config/github-copilot/hosts.json" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on reading own Claude config", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.claude/settings.json" },
  }));
  // Claude settings are not in the cross-agent list (that's our own config)
  assert.equal(findings.length, 0);
});

test("no finding on reading normal project file", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/project/package.json" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on reading .cursor directory without auth files", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/.cursor/settings.json" },
  }));
  // settings.json doesn't match the auth/token/credential pattern
  assert.equal(findings.length, 0);
});
