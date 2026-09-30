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
import { FAKE, DOCUMENTATION } from "../fixtures/credentials.mjs";

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
  ["AWS access key",       { key: FAKE.aws },                     "aws-key"     ],
  ["GitHub PAT",           { token: FAKE.github },               "github-pat"],
  ["Slack bot token",      { auth: FAKE.slack },                  "slack-bot"   ],
  ["Stripe live key",      { secret: FAKE.stripeLive },           "stripe-live" ],
  ["Stripe test key",      { secret: FAKE.stripeTest },           "stripe-test" ],
  ["Bearer token",         { header: `Bearer ${FAKE.jwt}` },      "bearer"      ],
  ["api_key assignment",   { body: `api_key=${FAKE.apiKey}` },    "api-key"     ],
  ["token= assignment",    { body: `token=${FAKE.token}` },        "token"       ],
  ["password= assignment", { body: "password=hunter2abc" },         "password"    ],
  // Quoted in code, which reaches the scanner JSON-escaped.
  ["quoted password in code", { content: 'const db = connect({ password: "Tr0ub4dor&3" });' }, "password"],
  ["quoted token in code",    { content: `client.auth({ token: "${FAKE.token}" })` },            "token"   ],
  ["quoted api key in code",  { content: `const API_KEY = "${FAKE.apiKey}"; // api_key: "${FAKE.apiKey}"` }, "api-key"],
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
    key: FAKE.aws,
    token: FAKE.github,
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
  // Text about credentials, not credentials.
  { content: "Bearer tokens are sent in the Authorization header." },
  { command: "curl -H \"Authorization: Bearer ${API_TOKEN}\" https://api.example.org" },
  { content: "headers: { Authorization: `Bearer ${token}` }" },
  { body: "api_key=your_api_key_here_123" },
  { body: "token=notarealtoken12345" },
  { body: "token=aaaaaaaaaaaaaaaaaaaa1" },
  { body: "token=abcdefghijklmnopqrst" },
  { body: "password=${DB_PASSWORD}" },
  { body: "password=<your-password>" },
  // Identifiers and fixture runs.
  { body: "OMNODEX_API_TOKEN=local_dev_token_123" },
  { content: "const key = await argon2id({ password: passphrase, salt });" },
  { content: "password = masterPassphrase" },
  { token: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890" },
  // Vendor documentation keys.
  { key: DOCUMENTATION.aws },
  { secret: DOCUMENTATION.stripe },
  { token: DOCUMENTATION.github },
];

for (const params of MUST_NOT_FIRE) {
  test(`does not fire for safe params: ${JSON.stringify(params)}`, () => {
    assert.equal(engine.evaluate(makeEvent(params)).length, 0);
  });
}
