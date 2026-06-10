/**
 * RULE_SENSITIVE_PATH_READ unit tests.
 *
 * Verifies the rule fires for each sensitive path category and does not
 * fire for benign paths.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_SENSITIVE_PATH_READ } from "../../dist/rules/index.js";

const engine = new RuleEngine([RULE_SENSITIVE_PATH_READ]);

function makeEvent(params = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-05-01T00:00:00.000Z",
    recorded_at: "2026-05-01T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: params,
  };
}

// Sensitive paths that must trigger a HIGH finding.
const MUST_FIRE = [
  ["/etc/passwd",                "/etc/passwd"],
  ["/etc/shadow",                "/etc/shadow"],
  ["/etc/sudoers",               "/etc/sudoers"],
  ["/etc/sudoers.d/admin",       "/etc/sudoers"],
  ["/etc/ssh/sshd_config",       "/etc/ssh/ config"],
  ["/root/.bashrc",              "/root/ directory"],
  ["/home/user/.ssh/id_rsa",     "SSH private key"],
  ["/home/user/.ssh/config",     ".ssh directory"],
  ["/home/user/.env",            ".env file"],
  ["/home/user/.env.production", ".env file"],
  ["/home/user/.aws/credentials","AWS credentials"],
  ["/home/user/.gcloud/config",  "GCloud config"],
  ["/home/user/.kube/config",    "Kubernetes config"],
  ["/home/user/server.pem",      "PEM private key"],
  ["/home/user/.ssh/id_ed25519", "SSH private key"],
];

for (const [filePath, expectedLabel] of MUST_FIRE) {
  test(`fires HIGH for path: ${filePath}`, () => {
    const findings = engine.evaluate(makeEvent({ file_path: filePath }));
    assert.equal(findings.length, 1, `expected 1 finding for ${filePath}`);
    assert.equal(findings[0].severity, "HIGH");
    assert.equal(findings[0].category, "sensitive_path_read");
    assert.equal(findings[0].rule_id, "RULE_SENSITIVE_PATH_READ");
    assert.ok(
      findings[0].description.includes(expectedLabel),
      `description "${findings[0].description}" should include label "${expectedLabel}"`,
    );
    assert.ok(findings[0].description.includes(filePath));
  });
}

// Benign paths that must NOT trigger a finding.
const MUST_NOT_FIRE = [
  "/home/user/project/src/main.ts",
  "/tmp/output.txt",
  "/var/log/app.log",
  "/home/user/documents/report.pdf",
  "/usr/local/bin/node",
];

for (const filePath of MUST_NOT_FIRE) {
  test(`does not fire for benign path: ${filePath}`, () => {
    const findings = engine.evaluate(makeEvent({ file_path: filePath }));
    assert.equal(findings.length, 0);
  });
}

// Multiple paths in one event -- one finding per sensitive path.
test("emits one finding per sensitive path when multiple paths present", () => {
  const findings = engine.evaluate(
    makeEvent({ file_path: "/etc/passwd", filename: "/home/user/.ssh/id_rsa" }),
  );
  assert.equal(findings.length, 2);
});
