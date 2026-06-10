/**
 * RuleRegistry unit tests.
 *
 * Verifies that community rules are always active, tier filtering works,
 * and the advanced rules stub throws the expected error.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleRegistry } from "../dist/registry.js";
import { COMMUNITY_RULES } from "../dist/rules/index.js";

test("default registry contains all community rules", () => {
  const registry = new RuleRegistry();
  const rules = registry.getRules();
  assert.ok(rules.length >= 3, "expected at least 3 community rules");
  for (const rule of COMMUNITY_RULES) {
    assert.ok(
      rules.some((r) => r.rule_id === rule.rule_id),
      `rule ${rule.rule_id} should be in the registry`,
    );
  }
});

test("getCommunityRules returns only community-tier rules", () => {
  const registry = new RuleRegistry();
  const rules = registry.getCommunityRules();
  assert.ok(rules.length > 0);
  assert.ok(rules.every((r) => r.tier === "community"));
});

test("getAdvancedRules returns empty array before loading", () => {
  const registry = new RuleRegistry();
  assert.equal(registry.getAdvancedRules().length, 0);
});

test("getRules returns a copy -- mutations do not affect the registry", () => {
  const registry = new RuleRegistry();
  const rules = registry.getRules();
  rules.push({ rule_id: "INJECTED" });
  assert.ok(
    registry.getRules().every((r) => r.rule_id !== "INJECTED"),
    "mutating getRules() result should not affect the registry",
  );
});

test("custom initialRules are respected", () => {
  const customRule = {
    rule_id: "CUSTOM_RULE",
    version: "0.0.1",
    tier: "community",
    event_types: ["tool.invoked"],
    conditions: [],
    severity: "LOW",
    category: "custom",
    description_template: "custom",
  };
  const registry = new RuleRegistry([customRule]);
  const rules = registry.getRules();
  assert.equal(rules.length, 1);
  assert.equal(rules[0].rule_id, "CUSTOM_RULE");
});

test("loadAdvancedRules throws with a clear message (stub behavior)", async () => {
  const registry = new RuleRegistry();
  await assert.rejects(
    () => registry.loadAdvancedRules("fake-token"),
    (err) => {
      assert.ok(err instanceof Error);
      assert.ok(
        err.message.includes("Pro or Enterprise"),
        `expected message to mention tier, got: "${err.message}"`,
      );
      return true;
    },
  );
});
