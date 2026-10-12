/**
 * Self-protection rule unit tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_SELF_PROTECTION_CONFIG_WRITE,
  RULE_SELF_PROTECTION_BASH,
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

// ---- CONFIG WRITE ----

test("fires on write to .omnodex/ directory", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_CONFIG_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.omnodex/config.json",
      content: '{"enforcement": false}',
    },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "self_protection");
});

test("fires on write to event log file", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_CONFIG_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/project/omnodex-events.jsonl",
      content: "",
    },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on write to normal project file", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_CONFIG_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/project/src/index.ts",
      content: "console.log('hello')",
    },
  }));
  assert.equal(findings.length, 0);
});

// ---- BASH ----

test("fires on omnodex uninstall", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "omnodex uninstall claude-code --confirm" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("fires on rm of omnodex event log", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "rm -f ~/project/omnodex-events.jsonl" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on rm of .omnodex directory", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "rm -rf ~/.omnodex" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on kill omnodex process", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "pkill -f omnodex" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on omnodex status command", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "omnodex status" },
  }));
  assert.equal(findings.length, 0);
});

// ---- CAPTURE PAUSE ----

for (const command of [
  "omnodex record pause",
  "omnodex sync pause 1h",
  "omnodex   enforce pause",
  "cd /tmp && omnodex record pause 30m",
  "npx omnodex sync pause",
]) {
  test(`fires on capture pause: ${command}`, () => {
    const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
    const findings = engine.evaluate(makeEvent({ tool_name: "Bash", parameters: { command } }));
    assert.equal(findings.length, 1);
    assert.match(findings[0].description, /omnodex-capture-pause/);
  });
}

for (const command of [
  "omnodex record resume",
  "omnodex sync resume",
  "omnodex sync status",
  "omnodex sync",
  "omnodex sync --sessions a,b",
  "echo pause",
]) {
  test(`no finding on: ${command}`, () => {
    const engine = new RuleEngine([RULE_SELF_PROTECTION_BASH]);
    const findings = engine.evaluate(makeEvent({ tool_name: "Bash", parameters: { command } }));
    assert.equal(findings.length, 0);
  });
}

test("fires on a write to the pause state file", () => {
  const engine = new RuleEngine([RULE_SELF_PROTECTION_CONFIG_WRITE]);
  const findings = engine.evaluate(makeEvent({
    parameters: {
      file_path: "/home/case/.omnodex/pause-state.json",
      content: '{"record":{"pause_id":"x","paused_at":"2026-06-02T00:00:00.000Z","until":null,"by":"cli"}}',
    },
  }));
  assert.equal(findings.length, 1);
});
