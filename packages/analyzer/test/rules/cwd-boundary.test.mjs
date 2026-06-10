/**
 * Working-directory boundary detection rule unit tests.
 *
 * Tests the cwd_boundary condition type and the RULE_CWD_BOUNDARY_WRITE rule.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CWD_BOUNDARY_WRITE } from "../../dist/rules/index.js";

const engine = new RuleEngine([RULE_CWD_BOUNDARY_WRITE]);

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
    cwd: "/home/case/projects/myapp",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Cases that MUST fire (file outside cwd)
// ---------------------------------------------------------------------------

test("fires on write to path outside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/other-project/config.json", content: "{}" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
  assert.equal(findings[0].category, "cwd_boundary");
  assert.ok(findings[0].description.includes("/home/case/other-project/config.json"));
});

test("fires on write to parent directory", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/evil.sh", content: "#!/bin/sh" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on write to /tmp", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/tmp/staging/payload.bin", content: "data" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on write to home-relative path with ~ when cwd is absolute", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "~/.bashrc", content: "export PATH=evil" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on read of file outside cwd via Bash cat", () => {
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "cat /etc/shadow" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on bash cp from outside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "cp /home/case/.ssh/id_rsa ./stolen.key" },
  }));
  assert.equal(findings.length, 1);
});

// ---------------------------------------------------------------------------
// Cases that MUST NOT fire (file inside cwd or no cwd)
// ---------------------------------------------------------------------------

test("no finding on write inside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp/src/index.ts", content: "export {}" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on write to nested subdirectory of cwd", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp/src/deep/nested/file.ts", content: "x" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding when cwd is not populated (backwards compat)", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: undefined,
    parameters: { file_path: "/etc/passwd" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on relative path (assumed relative to cwd)", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "src/components/Button.tsx", content: "export default Button" },
  }));
  assert.equal(findings.length, 0);
});

test("no finding on write to cwd root itself", () => {
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp/package.json", content: "{}" },
  }));
  assert.equal(findings.length, 0);
});

test("does not false-positive on similar prefix (myapp vs myapp-other)", () => {
  // /home/case/projects/myapp-other is NOT inside /home/case/projects/myapp
  const findings = engine.evaluate(makeEvent({
    parameters: { file_path: "/home/case/projects/myapp-other/file.ts", content: "x" },
  }));
  assert.equal(findings.length, 1); // This IS outside cwd, should fire
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

test("handles Windows-style paths with backslashes", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: "C:\\Users\\case\\projects\\myapp",
    parameters: { file_path: "C:\\Users\\case\\Desktop\\evil.bat", content: "del /s" },
  }));
  assert.equal(findings.length, 1);
});

test("handles Windows path inside cwd", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: "C:\\Users\\case\\projects\\myapp",
    parameters: { file_path: "C:\\Users\\case\\projects\\myapp\\src\\main.ts", content: "x" },
  }));
  assert.equal(findings.length, 0);
});

test("handles trailing slash on cwd", () => {
  const findings = engine.evaluate(makeEvent({
    cwd: "/home/case/projects/myapp/",
    parameters: { file_path: "/home/case/projects/myapp/file.ts", content: "x" },
  }));
  assert.equal(findings.length, 0);
});
