// Codex command operands must reach the same path rules as other shell hosts.
// These are synthetic events; no command or sensitive-file read is executed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { extractPaths, evaluatePathMatch } from "../dist/conditions/path-match.js";
import { normalizeAction } from "../dist/action.js";
import { RuleEngine } from "../dist/engine.js";
import { RULE_SENSITIVE_PATH_READ } from "../dist/rules/index.js";

const engine = new RuleEngine([RULE_SENSITIVE_PATH_READ]);
function event(parameters, tool_name = "exec_command") {
  return {
    schema_version: 1, event_id: "case-event", session_id: "case-session",
    occurred_at: "2026-10-01T12:00:00Z", recorded_at: "2026-10-01T12:00:00Z",
    interceptor: "codex-hook", event_type: "tool.invoked", tool_call_id: "case-call",
    tool_name, mcp_server: "builtin", parameters, cwd: "/home/case/repo",
  };
}

for (const command of [
  "cat /etc/shadow", "less /etc/passwd", "head -n1 /etc/shadow",
  "tail -n1 /etc/passwd", "cp /etc/shadow /tmp/case-copy",
  "scp /etc/shadow case@localhost:/tmp/case-copy",
  "cat C:\\Users\\case\\.codex\\auth.json",
]) {
  test(`MUST_FIRE: cmd exposes sensitive operands: ${command}`, () => {
    const call = event({ cmd: command });
    assert.deepEqual(extractPaths(call), extractPaths(event({ command })));
    assert.deepEqual(extractPaths(call), extractPaths(event({ CommandLine: command })));
    const findings = engine.evaluate(call);
    assert.ok(findings.length > 0);
    assert.equal(findings.length, engine.evaluate(event({ command })).length);
    assert.ok(findings.every((f) => f.rule_id === "RULE_SENSITIVE_PATH_READ" && f.severity === "HIGH"));
  });
}

test("cmd keeps source reads separate from destination writes", () => {
  const condition = { type: "path_match", patterns: [{ regex: "^/etc/shadow$", label: "shadow" }] };
  const read = event({ cmd: "cat /etc/shadow" });
  const write = event({ cmd: "cp /tmp/case-input /etc/shadow" });
  const matched = (call, access) => evaluatePathMatch({ ...condition, access }, call).length;
  assert.equal(matched(read, "read"), 1);
  assert.equal(matched(read, "write"), 0);
  assert.equal(matched(write, "read"), 0);
  assert.equal(matched(write, "write"), 1);
  assert.ok(normalizeAction(read).kinds.has("read"));
  assert.ok(!normalizeAction(read).kinds.has("write"));
});

for (const cmd of ["cat /home/case/repo/README.md", "head /tmp/case.log", "echo /etc/shadow", "echo done"]) {
  test(`MUST_NOT_FIRE: harmless cmd: ${cmd}`, () => {
    assert.deepEqual(engine.evaluate(event({ cmd })), []);
  });
}

for (const tool of ["Write", "apply_patch", "mcp__tickets__create_issue"]) {
  test(`MUST_NOT_FIRE: cmd metadata on ${tool} is not a shell read`, () => {
    const call = event({ cmd: "cat /etc/shadow", content: "cat /etc/shadow" }, tool);
    assert.deepEqual(extractPaths(call), []);
    assert.deepEqual(engine.evaluate(call), []);
  });
}

test("MUST_NOT_FIRE: malformed cmd values are not commands", () => {
  for (const cmd of [null, 42, {}, ["cat", "/etc/shadow"]]) {
    assert.deepEqual(extractPaths(event({ cmd })), []);
  }
});
