/**
 * Masking of credentials at capture: no full copy in the written event, a
 * stable fingerprint, and the credential rule still reading a masked call as
 * a credential of the same type.
 */

import "../../../scripts/test-home.mjs";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { RuleEngine } from "../dist/engine.js";
import { RULE_CREDENTIAL_IN_PARAMS } from "../dist/rules/index.js";
import { maskEventSecrets, maskSecretsInText } from "../dist/mask-secrets.js";
import { findSecretMarkers, parseSecretMarker, displayHint } from "../dist/secret-marker.js";
import { maskCaptured } from "../dist/capture.js";
import { credentialFingerprinter } from "../dist/known-secrets.js";
import { FAKE } from "./fixtures/credentials.mjs";

const fp = (v) => credentialFingerprinter(HOME)(v);
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-mask-"));

function makeEvent(parameters, type = "tool.invoked") {
  return {
    schema_version: 1, event_id: "evt-1", session_id: "sess-test",
    occurred_at: "2026-05-01T00:00:00.000Z", recorded_at: "2026-05-01T00:00:00.000Z",
    interceptor: "mock", event_type: type, tool_call_id: "tc-1", tool_name: "mcp__http__post",
    mcp_server: "http", parameters,
  };
}

// [description, parameters, value that must not survive, expected type]
const MUST_MASK = [
  ["GitHub PAT", { token: FAKE.github }, FAKE.github, "github-pat"],
  ["AWS key", { key: FAKE.aws }, FAKE.aws, "aws-key"],
  ["Bearer header", { headers: { Authorization: `Bearer ${FAKE.jwt}` } }, FAKE.jwt, "bearer"],
  ["api_key in a body", { body: `api_key=${FAKE.apiKey}` }, FAKE.apiKey, "api-key"],
  ["password in code", { content: 'connect({ password: "Tr0ub4dor&3" });' }, "Tr0ub4dor&3", "password"],
  ["Anthropic key", { env: { K: FAKE.anthropic } }, FAKE.anthropic, "anthropic"],
];

for (const [name, params, secret, type] of MUST_MASK) {
  test(`masks ${name}: no full copy, type kept`, () => {
    const out = maskEventSecrets(makeEvent(params), fp);
    const json = JSON.stringify(out);
    assert.ok(!json.includes(secret), "the value is gone");
    const markers = findSecretMarkers(json);
    assert.equal(markers.length, 1);
    assert.equal(markers[0].type, type);
    assert.match(markers[0].fingerprint, /^[0-9a-f]{16}$/);
  });
}

test("the same credential gets the same fingerprint, a different one a different fingerprint", () => {
  const a = findSecretMarkers(JSON.stringify(maskEventSecrets(makeEvent({ x: FAKE.github }), fp)))[0];
  const b = findSecretMarkers(JSON.stringify(maskEventSecrets(makeEvent({ y: { z: `Bearer ${FAKE.github}` } }), fp)))[0];
  const c = findSecretMarkers(JSON.stringify(maskEventSecrets(makeEvent({ x: FAKE.aws }), fp)))[0];
  assert.equal(a.fingerprint, b.fingerprint);
  assert.notEqual(a.fingerprint, c.fingerprint);
});

test("the hint keeps at most 4 characters from each end, none of a short value", () => {
  const long = findSecretMarkers(maskSecretsInText(FAKE.github, fp))[0];
  assert.equal(displayHint(long.hint), "ghp_...2Ue4");
  const short = findSecretMarkers(maskSecretsInText("password=hunter2abc", fp))[0];
  assert.equal(short.hint, "");
});

test("masking is idempotent and leaves other events and clean calls alone", () => {
  const once = maskEventSecrets(makeEvent({ token: FAKE.github }), fp);
  assert.deepEqual(maskEventSecrets(once, fp), once);
  const clean = makeEvent({ path: "/home/case/a.txt", note: "Bearer tokens are sent in headers" });
  assert.equal(maskEventSecrets(clean, fp), clean);
  const other = makeEvent({ token: FAKE.github }, "tool.completed");
  assert.equal(maskEventSecrets(other, fp), other);
});

test("maskCaptured masks under the machine key and the original event is untouched", async () => {
  const event = makeEvent({ token: FAKE.github });
  const [out] = await maskCaptured([event], HOME);
  assert.ok(!JSON.stringify(out).includes(FAKE.github));
  assert.equal(event.parameters.token, FAKE.github);
  assert.equal(parseSecretMarker(out.parameters.token).fingerprint, fp(FAKE.github).slice(0, 16));
});

const engine = new RuleEngine([RULE_CREDENTIAL_IN_PARAMS]);

for (const [name, params, , type] of MUST_MASK) {
  test(`MUST_FIRE: the credential rule reads masked ${name} as ${type}`, () => {
    const findings = engine.evaluate(maskEventSecrets(makeEvent(params), fp));
    assert.equal(findings.length, 1);
    assert.match(JSON.stringify(findings[0]), new RegExp(type));
  });
}

test("MUST_NOT_FIRE: a call that only mentions secrets, or holds a marker-like word, is not a credential", () => {
  assert.equal(engine.evaluate(makeEvent({ text: "keep the secret marker [omnodex:secret] out of logs" })).length, 0);
  assert.equal(engine.evaluate(makeEvent({ text: "Bearer tokens are sent in headers" })).length, 0);
});

test("a masked password is reported once, as its own type, not again as a password", () => {
  const masked = maskEventSecrets(makeEvent({ token: FAKE.github, password: "Tr0ub4dor&3" }), fp);
  const finding = engine.evaluate(masked);
  assert.equal(finding.length, 1);
  assert.match(JSON.stringify(finding[0]), /github-pat/);
  assert.match(JSON.stringify(finding[0]), /password/);
});
