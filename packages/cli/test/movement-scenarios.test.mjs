import { test } from "node:test";
import assert from "node:assert/strict";
import { MOVEMENT_SCENARIOS, buildMovementScenarios, COMMUNITY_SCENARIOS } from "../../hooks-provider/dist/index.js";
import { normalizeAction, classifyHost } from "../../analyzer/dist/action.js";
import { detectRisks } from "../../analyzer/dist/index.js";
import { parseSpikeOptions } from "../dist/spike-options.js";

// Names that can never resolve to a real host: RFC 2606 example domains and
// reserved TLDs, plus the RFC 5737 documentation ranges.
const RESERVED_NAME = /(^|\.)(example\.(com|org|net)|example|invalid|test|localhost)$/;
const DOC_RANGE = /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/;
const inert = (host) => classifyHost(host) === "loopback" || RESERVED_NAME.test(host) || DOC_RANGE.test(host);

// Community findings each chain raises through the real batch analyzer.
const COMMUNITY_FINDINGS = {
  "credential-body": ["RULE_SENSITIVE_PATH_READ"],
  "provider-auth": ["RULE_SENSITIVE_PATH_READ"],
  "credential-staged": ["RULE_SENSITIVE_PATH_READ", "RULE_THREAT_CREDENTIAL_ARCHIVE"],
  "release-staged": ["RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"],
  "sensitive-new-destination": ["RULE_OUTBOUND_UNKNOWN_IP", "RULE_SENSITIVE_PATH_READ"],
  "tests-usual-api": ["RULE_SENSITIVE_PATH_READ"],
  "credential-outside-write": ["RULE_CWD_BOUNDARY_TEMP_WRITE", "RULE_SENSITIVE_PATH_READ"],
  "login-config-write": ["RULE_CWD_BOUNDARY_WRITE", "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"],
  "staged-path-mismatch": ["RULE_SENSITIVE_PATH_READ", "RULE_THREAT_CREDENTIAL_ARCHIVE"],
  "windows-credential-copy": ["RULE_CWD_BOUNDARY_WRITE", "RULE_SENSITIVE_PATH_READ"],
};

for (const seed of [0, 1, 42, -1, 12345]) {
  test(`movement set is deterministic, inert and preserves every chain: ${seed}`, () => {
    const events = buildMovementScenarios({ seed });
    assert.deepEqual(events, buildMovementScenarios({ seed }));
    const ids = [...new Set(events.map(e => e.session_id))];
    assert.equal(ids.length, COMMUNITY_SCENARIOS.length + MOVEMENT_SCENARIOS.length + 4);
    for (const [index, fixture] of MOVEMENT_SCENARIOS.entries()) {
      const source = events.filter(e => e.session_id === ids[COMMUNITY_SCENARIOS.length + index]);
      const calls = source.filter(e => e.event_type === "tool.invoked");
      assert.equal(calls.length, fixture.calls.length, fixture.id);
      assert.deepEqual(calls.map(e => e.parameters), fixture.calls.map(c => c.parameters));
      for (const call of calls) {
        for (const destination of normalizeAction(call).destinations) assert.ok(inert(destination.host), `${fixture.id}: ${destination.host}`);
        assert.ok(!JSON.stringify(call.parameters).includes("sk_live_"));
        assert.ok(!JSON.stringify(call.parameters).includes("ghp_"));
      }
      let n = 0;
      const rules = [...new Set(detectRisks(source, () => `risk_${n++}`).newEvents.map(e => e.rule_id))].sort();
      assert.deepEqual(rules, COMMUNITY_FINDINGS[fixture.id], fixture.id);
    }
  });
}
test("send chains leave loopback and routine counterparts stay on known destinations", () => {
  const external = (id) => MOVEMENT_SCENARIOS.find(f => f.id === id).calls
    .flatMap(c => normalizeAction({ event_type: "tool.invoked", tool_name: c.tool, parameters: c.parameters }).destinations)
    .filter(d => classifyHost(d.host) !== "loopback").map(d => d.host);
  for (const id of ["credential-body", "credential-staged", "sensitive-new-destination", "staged-path-mismatch"]) assert.ok(external(id).length > 0, id);
  assert.deepEqual(external("provider-auth"), []);
  for (const id of ["release-staged", "tests-usual-api"]) assert.equal(new Set(external(id)).size, 1, id);
});
test("CLI opts into movement fixtures and enforces the larger minimum", () => {
  assert.equal(parseSpikeOptions(["--scenario-set", "movement"]).additionalScenarios, MOVEMENT_SCENARIOS);
  assert.throws(() => parseSpikeOptions(["--scenario-set", "unknown"]));
  assert.throws(() => parseSpikeOptions(["--scenario-set", "movement", "--sessions", "12"]));
});
