/**
 * RULE_CREDENTIAL_IN_PARAMS unit tests.
 *
 * Verifies the rule detects each credential type and produces a single
 * MEDIUM finding with the detected types listed. Also verifies it does
 * not fire on safe parameter values.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CREDENTIAL_IN_PARAMS } from "../../dist/rules/index.js";

const engine = new RuleEngine([RULE_CREDENTIAL_IN_PARAMS]);

function makeEvent(parameters = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-05-01T00:00:00.000Z",
    recorded_at: "2026-05-01T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: "mcp__http__post",
    mcp_server: "http",
    parameters,
  };
}

// Each entry is [description, parameters, expected credential type label].
const MUST_FIRE = [
  ["AWS access key",       { key: "AKIAIOSFODNN7EXAMPLE" },         "aws-key"     ],
  ["GitHub PAT",           { token: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890" }, "github-pat"],
  ["Slack bot token",      { auth: "xoxb-abc-def-ghi" },            "slack-bot"   ],
  ["Stripe live key",      { secret: "sk_live_abc123def456" },      "stripe-live" ],
  ["Stripe test key",      { secret: "sk_test_abc123def456" },      "stripe-test" ],
  ["Bearer token",         { header: "Bearer eyJsometoken123456" }, "bearer"      ],
  ["api_key assignment",   { body: "api_key=abcdefghijklmnop" },    "api-key"     ],
  ["token= assignment",    { body: "token=abcdefghijklmnop" },      "token"       ],
  ["password= assignment", { body: "password=hunter2abc" },         "password"    ],
];

for (const [desc, params, expectedType] of MUST_FIRE) {
  test(`detects ${desc}`, () => {
    const findings = engine.evaluate(makeEvent(params));
    assert.equal(findings.length, 1, `expected 1 finding for ${desc}`);
    assert.equal(findings[0].severity, "MEDIUM");
    assert.equal(findings[0].category, "credential_exposure");
    assert.ok(
      findings[0].description.includes(expectedType),
      `description "${findings[0].description}" should include "${expectedType}"`,
    );
    assert.ok(findings[0].description.includes("mcp__http__post"));
  });
}

// Multiple credential types in one event -- all types appear in one finding.
test("lists multiple credential types in a single finding", () => {
  const findings = engine.evaluate(makeEvent({
    key: "AKIAIOSFODNN7EXAMPLE",
    token: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
  }));
  assert.equal(findings.length, 1);
  assert.ok(findings[0].description.includes("aws-key"));
  assert.ok(findings[0].description.includes("github-pat"));
});

// Safe parameters that must NOT trigger a finding.
const MUST_NOT_FIRE = [
  { query: "SELECT * FROM users WHERE id = 1" },
  { message: "hello world" },
  { config: JSON.stringify({ debug: true, port: 3000 }) },
  { short: "abc" }, // too short to match any pattern
];

for (const params of MUST_NOT_FIRE) {
  test(`does not fire for safe params: ${JSON.stringify(params)}`, () => {
    assert.equal(engine.evaluate(makeEvent(params)).length, 0);
  });
}
