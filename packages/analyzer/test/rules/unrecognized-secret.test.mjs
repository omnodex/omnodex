/**
 * RULE_UNRECOGNIZED_SECRET unit tests.
 *
 * The rule reports a machine-made value used as a credential that the
 * credential rule does not already report: named for a secret, key or
 * auth, passed as a credential flag, or sent in a non-Bearer Authorization
 * header. Hashes, UUIDs, integrity strings, paths, placeholders, public
 * keys and values the credential rule reports must not fire it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_UNRECOGNIZED_SECRET, RULE_CREDENTIAL_IN_PARAMS } from "../../dist/rules/index.js";
import { FAKE } from "../fixtures/credentials.mjs";

const engine = new RuleEngine([RULE_UNRECOGNIZED_SECRET]);
const both = new RuleEngine([RULE_CREDENTIAL_IN_PARAMS, RULE_UNRECOGNIZED_SECRET]);

// Machine-made values with no vendor format.
const GENERATED = "kR7vQ2mX9pL4tN8wZ3bY6cH1jF5dS0gA";
const GENERATED_B64 = "c2VydmljZTpkN2Y0YjkyYzFlOGE2MzA1";

function makeEvent(toolName, parameters) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-10-21T00:00:00.000Z",
    recorded_at: "2026-10-21T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: toolName,
    mcp_server: toolName === "Bash" || toolName === "Write" ? "builtin" : "http",
    parameters,
  };
}

const bash = (command) => makeEvent("Bash", { command });

const MUST_FIRE = [
  ["a secret variable in a command", bash(`CLIENT_SECRET=${GENERATED} ./deploy.sh`)],
  ["a JSON field named for a signing key", makeEvent("mcp__http__post", { body: { signingKey: GENERATED } })],
  ["a header named for a key", makeEvent("mcp__http__post", { url: "https://api.vendor.example.com/v2", headers: { "X-Vendor-Key": GENERATED } })],
  ["a credential flag", bash(`vendorctl login --client-secret ${GENERATED}`)],
  ["a credential flag with =", bash(`vendorctl login --auth-key=${GENERATED}`)],
  ["an Authorization token header", bash(`curl -H "Authorization: token ${GENERATED}" https://git.example.org/api/v1/user`)],
  ["an Authorization Basic header", bash(`curl -H "Authorization: Basic ${GENERATED_B64}" https://registry.example.org/v2/`)],
  ["a secret in file content being written",
    makeEvent("Write", { file_path: "/home/case/repo/config/prod.yaml", content: `webhook:\n  secret: ${GENERATED}\n` })],
];

for (const [desc, event] of MUST_FIRE) {
  test(`MUST_FIRE: ${desc}`, () => {
    const findings = engine.evaluate(event);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule_id, "RULE_UNRECOGNIZED_SECRET");
    assert.equal(findings[0].severity, "LOW");
    assert.equal(findings[0].category, "credential_exposure");
  });
}

const MUST_NOT_FIRE = [
  ["a git commit SHA as a cache key", makeEvent("mcp__http__post", { body: { cacheKey: "9fceb02d0ae598e95dc970b74767f19372d61af8" } })],
  ["a sha256 digest as a key", bash("export ARTIFACT_KEY=3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b")],
  ["a UUID as an idempotency key", makeEvent("mcp__http__post", { body: { idempotencyKey: "123e4567-e89b-42d3-a456-426614174000" } })],
  ["a lockfile integrity string", makeEvent("Write", { file_path: "/home/case/repo/package-lock.json",
    content: '"integrity": "sha512-Zk3vQ8pL2mX7tN4wR9bY6cH1jF5dS0gAkR7vQ2mX9pL4tN8wZ3bY6cH1jF5dS0gA=="' })],
  ["base64 file content with no credential name", makeEvent("mcp__http__post", { content: GENERATED_B64 + GENERATED_B64 })],
  ["a key file path passed to a flag", bash("curl --key /home/case/certs/client2.key --cert /home/case/certs/client2.crt https://mtls.example.org/")],
  ["a public key", makeEvent("mcp__http__post", { body: { publicKey: GENERATED } })],
  ["a placeholder", bash("CLIENT_SECRET=your_client_secret_here_123 ./deploy.sh")],
  ["an environment reference", bash("vendorctl login --client-secret \"$CLIENT_SECRET\"")],
  ["an ordinary word in a key field", makeEvent("mcp__http__post", { body: { sortKey: "createdAtDescending" } })],
  ["a short value", bash("API_AUTH=abc123")],
];

for (const [desc, event] of MUST_NOT_FIRE) {
  test(`MUST_NOT_FIRE: ${desc}`, () => {
    assert.equal(engine.evaluate(event).length, 0);
  });
}

// Values the credential rule reports are left to it.
const CLAIMED = [
  ["a Bearer token", bash(`curl -H "Authorization: Bearer ${GENERATED}" https://api.example.org/`)],
  ["a token= assignment", bash(`MY_SERVICE_TOKEN=${GENERATED} ./run.sh`)],
  ["an api_key assignment", makeEvent("mcp__http__post", { body: { api_key: GENERATED } })],
  ["a vendor-format key in a secret field", makeEvent("mcp__http__post", { body: { secret: FAKE.huggingface } })],
];

for (const [desc, event] of CLAIMED) {
  test(`MUST_NOT_FIRE: ${desc} is reported only by the credential rule`, () => {
    const ids = both.evaluate(event).map((f) => f.rule_id);
    assert.deepEqual(ids, ["RULE_CREDENTIAL_IN_PARAMS"]);
  });
}
