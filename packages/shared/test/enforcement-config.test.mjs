/**
 * Enforcement configuration parsing.
 *
 * The parser is lenient entry by entry: one malformed override is dropped
 * and the rest still apply. The repository parser keeps only what can
 * tighten protection.
 *
 * Run: node --test packages/shared/test/enforcement-config.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseEnforcementConfig, parseRepoEnforcementConfig } from "../dist/index.js";

describe("parseEnforcementConfig", () => {
  it("returns an empty config for anything that is not an object", () => {
    for (const raw of [undefined, null, 3, "guardrails", []]) {
      assert.deepEqual(parseEnforcementConfig(raw), {});
    }
  });

  it("keeps valid fields", () => {
    const cfg = parseEnforcementConfig({
      mode: "shadow",
      on_error: "block",
      severity_defaults: { CRITICAL: "deny", HIGH: "confirm" },
      rules: { RULE_A: "alert_only" },
      exceptions: [{ rule_id: "RULE_B", kind: "allow", target: { path: "/home/case/repo/tmp" }, note: "scratch" }],
    });
    assert.deepEqual(cfg, {
      mode: "shadow",
      on_error: "block",
      severity_defaults: { CRITICAL: "deny", HIGH: "confirm" },
      rules: { RULE_A: "alert_only" },
      exceptions: [{ rule_id: "RULE_B", kind: "allow", target: { path: "/home/case/repo/tmp" }, note: "scratch" }],
    });
  });

  it("drops malformed entries one by one", () => {
    const cfg = parseEnforcementConfig({
      mode: "enforce-only",
      on_error: "maybe",
      severity_defaults: { CRITICAL: "deny", URGENT: "deny", LOW: "block" },
      rules: { RULE_A: "deny", RULE_B: "stop", "": "deny" },
      exceptions: [
        { rule_id: "RULE_C", kind: "mute" },
        { rule_id: "RULE_D", kind: "ignore" },
        { kind: "allow" },
        { rule_id: "RULE_E", kind: "allow", target: { path: "/a", destination: "b.example" } },
        { rule_id: "RULE_F", kind: "allow", target: {} },
        { rule_id: "RULE_G", kind: "allow", target: "everything" },
      ],
    });
    assert.deepEqual(cfg, {
      severity_defaults: { CRITICAL: "deny" },
      rules: { RULE_A: "deny" },
      exceptions: [{ rule_id: "RULE_C", kind: "mute" }],
    });
  });

  it("reads per-project sections, without a mode or nested projects", () => {
    const cfg = parseEnforcementConfig({
      projects: {
        "/home/case/repo": {
          mode: "guardrails",
          rules: { RULE_A: "alert_only" },
          projects: { "/home/case/repo/sub": { rules: { RULE_B: "deny" } } },
        },
        "/home/case/empty": { mode: "guardrails" },
      },
    });
    assert.deepEqual(cfg, { projects: { "/home/case/repo": { rules: { RULE_A: "alert_only" } } } });
  });
});

describe("parseRepoEnforcementConfig", () => {
  it("keeps only per-rule and severity verdicts", () => {
    const cfg = parseRepoEnforcementConfig({
      mode: "monitor",
      on_error: "allow",
      severity_defaults: { HIGH: "confirm" },
      rules: { RULE_A: "deny" },
      exceptions: [{ rule_id: "RULE_A", kind: "allow" }],
      projects: { "/home/case/repo": { exceptions: [{ rule_id: "RULE_A", kind: "allow" }] } },
    });
    assert.deepEqual(cfg, { severity_defaults: { HIGH: "confirm" }, rules: { RULE_A: "deny" } });
  });
});
