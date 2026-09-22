/**
 * createEvaluator() tests.
 *
 * The evaluator is the one place risk.detected events are made. Covers rule
 * classification (pinned for every community rule), host filtering,
 * sequence rules, deduplication seeded from the log, warming from history,
 * stats, and equivalence with the plain engine.
 *
 * Run: node --test packages/analyzer/test/evaluator.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createEvaluator,
  classifyRule,
  loadRegistry,
  HOST_CLASSES,
} from "../dist/evaluator.js";
import { RuleEngine } from "../dist/engine.js";
import { RuleRegistry } from "../dist/registry.js";
import { COMMUNITY_RULES } from "../dist/rules/index.js";
import { findCredentialTypes } from "../dist/conditions/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let counter = 0;
const newEventId = () => `evt-${++counter}`;

let seq = 0;
function tool(overrides = {}) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-tool-${seq}`,
    session_id: "sess-case",
    occurred_at: new Date(Date.parse("2026-09-21T12:00:00Z") + seq * 1000).toISOString(),
    recorded_at: new Date().toISOString(),
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-${seq}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: {},
    ...overrides,
  };
}

const sshRead = (o = {}) => tool({ parameters: { file_path: "/home/case/.ssh/config" }, ...o });
const harmless = (o = {}) => tool({ parameters: { file_path: "/home/case/repo/README.md" }, ...o });
const curl = (o = {}) =>
  tool({ tool_name: "Bash", parameters: { command: "curl -s https://example.org/upload" }, ...o });
const mcpCall = (server, o = {}) =>
  tool({ tool_name: `mcp__${server}__list`, mcp_server: server, parameters: {}, ...o });

/** Outbound call after an .ssh read, within 3 events. */
const SEQUENCE_RULE = {
  rule_id: "RULE_CASE_SSH_THEN_OUTBOUND",
  version: "1.0.0",
  tier: "advanced",
  event_types: ["tool.invoked"],
  conditions: [
    { type: "outbound_call" },
    {
      type: "sequence",
      within_events: 3,
      prior: [{ type: "path_match", patterns: [{ regex: "\\.ssh/", label: "ssh" }] }],
    },
  ],
  severity: "HIGH",
  category: "case_sequence",
  description_template: "Outbound call via {{tool_name}} after an SSH file read.",
};

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

describe("classifyRule", () => {
  // Pinned so that a rule gaining state cannot silently reach the hook host.
  const STATEFUL = {
    RULE_SUPPLY_CHAIN_NEW_MCP_SERVER: "machine",
    RULE_UNBOUNDED_CONSUMPTION_BURST: "session",
    RULE_UNBOUNDED_CONSUMPTION_SUSTAINED: "session",
  };

  it("classifies every community rule: 34 event, 2 session, 1 machine", () => {
    assert.equal(COMMUNITY_RULES.length, 37);
    for (const rule of COMMUNITY_RULES) {
      assert.equal(classifyRule(rule), STATEFUL[rule.rule_id] ?? "event", rule.rule_id);
    }
  });

  it("classifies a sequence rule as session", () => {
    assert.equal(classifyRule(SEQUENCE_RULE), "session");
  });

  it("rejects a sequence whose prior step is itself stateful", () => {
    const bad = {
      ...SEQUENCE_RULE,
      conditions: [{ type: "sequence", prior: [{ type: "rate_threshold", window_seconds: 5, threshold: 2 }] }],
    };
    assert.throws(() => classifyRule(bad), /must be stateless/);
  });
});

describe("hosts", () => {
  it("runs event-class rules only in the hook host", () => {
    const hook = createEvaluator({ host: "hook", newEventId });
    const ids = hook.rules.map((r) => r.rule_id);
    assert.equal(ids.length, 34);
    assert.ok(!ids.includes("RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"));
    assert.ok(!ids.includes("RULE_UNBOUNDED_CONSUMPTION_BURST"));
    assert.deepEqual(HOST_CLASSES.hook, ["event"]);
  });

  it("runs every rule in the proxy and batch hosts", () => {
    for (const host of ["proxy", "batch"]) {
      assert.equal(createEvaluator({ host, newEventId }).rules.length, 37, host);
    }
  });

  it("loads the community rules from loadRegistry", () => {
    assert.equal(loadRegistry("/home/case/.omnodex").getRules().length, 37);
  });
});

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

describe("evaluate", () => {
  it("emits a complete risk.detected with the rule tier", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const call = tool({ parameters: { file_path: "/etc/passwd" } });
    const [risk] = ev.evaluate(call).filter((r) => r.rule_id === "RULE_SENSITIVE_PATH_READ");
    assert.equal(risk.event_type, "risk.detected");
    assert.equal(risk.interceptor, "analyzer");
    assert.equal(risk.session_id, "sess-case");
    assert.equal(risk.related_event_id, call.tool_call_id);
    assert.equal(risk.rule_tier, "community");
    assert.equal(risk.related_event_ids, undefined);
  });

  it("does not repeat a finding for the same rule and call", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const call = tool({ parameters: { file_path: "/etc/passwd" } });
    const first = ev.evaluate(call);
    assert.ok(first.length >= 1);
    assert.deepEqual(ev.evaluate(call), []);
    assert.equal(ev.stats().skipped, first.length);
  });

  it("does not write a finding another host already recorded", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const call = tool({ parameters: { file_path: "/etc/passwd" } });
    ev.evaluate({
      ...call,
      event_id: "evt-other-host",
      event_type: "risk.detected",
      severity: "HIGH",
      category: "sensitive_path_read",
      description: "recorded elsewhere",
      related_event_id: call.tool_call_id,
      rule_id: "RULE_SENSITIVE_PATH_READ",
    });
    const out = ev.evaluate(call);
    assert.ok(!out.some((r) => r.rule_id === "RULE_SENSITIVE_PATH_READ"));
  });

  it("orders findings as a single engine over the whole registry would", () => {
    const rules = loadRegistry().getRules();
    const engine = new RuleEngine(rules);
    const ev = createEvaluator({ host: "batch", newEventId });
    const calls = [
      tool({ parameters: { file_path: "/etc/passwd" } }),
      curl(),
      mcpCall("plane"),
      tool({ tool_name: "Bash", parameters: { command: "rm -rf / && cat ~/.aws/credentials" } }),
    ];
    for (const call of calls) {
      const expected = [...new Set(engine.evaluate(call).map((f) => f.rule_id))];
      const actual = ev.evaluate(call).map((r) => r.rule_id);
      assert.deepEqual(actual, expected, call.tool_call_id);
    }
  });

  it("counts evaluations and findings by rule and by tier", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    ev.evaluate(harmless());
    ev.evaluate(tool({ parameters: { file_path: "/etc/passwd" } }));
    const stats = ev.stats();
    assert.equal(stats.evaluated, 2);
    assert.ok(stats.findings >= 1);
    assert.equal(stats.byRule.RULE_SENSITIVE_PATH_READ, 1);
    assert.equal(stats.byTier.community, stats.findings);
  });

  it("ignores event types it does not judge", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    assert.deepEqual(ev.evaluate({ ...harmless(), event_type: "tool.completed" }), []);
    assert.equal(ev.stats().evaluated, 0);
  });
});

// ---------------------------------------------------------------------------
// History and session state
// ---------------------------------------------------------------------------

describe("observe and endSession", () => {
  it("warms first-seen state from history without emitting", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    ev.observe(mcpCall("plane"));
    assert.equal(ev.stats().findings, 0);
    const out = ev.evaluate(mcpCall("plane"));
    assert.ok(!out.some((r) => r.rule_id === "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"));
  });

  it("seeds deduplication from history", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const call = tool({ parameters: { file_path: "/etc/passwd" } });
    ev.observe({
      ...call,
      event_id: "evt-hist-risk",
      event_type: "risk.detected",
      severity: "HIGH",
      category: "sensitive_path_read",
      description: "earlier",
      related_event_id: call.tool_call_id,
      rule_id: "RULE_SENSITIVE_PATH_READ",
    });
    assert.ok(!ev.evaluate(call).some((r) => r.rule_id === "RULE_SENSITIVE_PATH_READ"));
  });

  it("releases a session's state when the session ends", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const first = ev.evaluate(mcpCall("plane"));
    assert.ok(first.some((r) => r.rule_id === "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"));
    ev.evaluate({ ...harmless(), event_type: "session.ended", duration_ms: 1, status: "completed" });
    const again = ev.evaluate(mcpCall("plane"));
    assert.ok(again.some((r) => r.rule_id === "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"));
  });
});

// ---------------------------------------------------------------------------
// Sequence rules
// ---------------------------------------------------------------------------

describe("sequence rules", () => {
  const registry = () => new RuleRegistry([SEQUENCE_RULE]);

  for (const host of ["proxy", "batch"]) {
    it(`fires on the two-event pattern and cites both events (${host} host)`, () => {
      const ev = createEvaluator({ host, registry: registry(), newEventId });
      const read = sshRead();
      const call = curl();
      assert.deepEqual(ev.evaluate(read), []);
      const out = ev.evaluate(call);
      assert.equal(out.length, 1);
      assert.equal(out[0].rule_id, "RULE_CASE_SSH_THEN_OUTBOUND");
      assert.equal(out[0].rule_tier, "advanced");
      assert.equal(out[0].related_event_id, call.tool_call_id);
      assert.deepEqual(out[0].related_event_ids, [read.tool_call_id, call.tool_call_id]);
    });
  }

  it("does not fire on either event alone", () => {
    const ev = createEvaluator({ host: "batch", registry: registry(), newEventId });
    assert.deepEqual(ev.evaluate(curl()), []);
    assert.deepEqual(ev.evaluate(sshRead()), []);
  });

  it("does not fire when the order is reversed", () => {
    const ev = createEvaluator({ host: "batch", registry: registry(), newEventId });
    ev.evaluate(curl());
    assert.deepEqual(ev.evaluate(sshRead()), []);
  });

  it("respects within_events", () => {
    const ev = createEvaluator({ host: "batch", registry: registry(), newEventId });
    ev.evaluate(sshRead());
    for (let i = 0; i < 3; i++) ev.evaluate(harmless());
    assert.deepEqual(ev.evaluate(curl()), []);
  });

  it("respects within_seconds", () => {
    const timed = {
      ...SEQUENCE_RULE,
      conditions: [
        { type: "outbound_call" },
        { ...SEQUENCE_RULE.conditions[1], within_events: undefined, within_seconds: 10 },
      ],
    };
    const ev = createEvaluator({ host: "batch", registry: new RuleRegistry([timed]), newEventId });
    const t0 = Date.parse("2026-09-21T13:00:00Z");
    ev.evaluate(sshRead({ occurred_at: new Date(t0).toISOString() }));
    assert.deepEqual(ev.evaluate(curl({ occurred_at: new Date(t0 + 30_000).toISOString() })), []);
    ev.evaluate(sshRead({ occurred_at: new Date(t0 + 40_000).toISOString() }));
    assert.equal(ev.evaluate(curl({ occurred_at: new Date(t0 + 45_000).toISOString() })).length, 1);
  });

  it("keeps sessions apart", () => {
    const ev = createEvaluator({ host: "batch", registry: registry(), newEventId });
    ev.evaluate(sshRead({ session_id: "sess-case-a" }));
    assert.deepEqual(ev.evaluate(curl({ session_id: "sess-case-b" })), []);
  });

  it("is never run by the hook host", () => {
    const ev = createEvaluator({ host: "hook", registry: registry(), newEventId });
    assert.equal(ev.rules.length, 0);
    ev.evaluate(sshRead());
    assert.deepEqual(ev.evaluate(curl()), []);
  });
});

// ---------------------------------------------------------------------------
// Compiled patterns
// ---------------------------------------------------------------------------

describe("compiled patterns", () => {
  it("give the same answer on repeated use of a global pattern", () => {
    const patterns = [{ regex: "ghp_[A-Za-z0-9]{8,}", type: "github-pat" }];
    const text = "token ghp_abcdefghijkl and again ghp_mnopqrstuvwx";
    for (let i = 0; i < 3; i++) {
      assert.deepEqual(findCredentialTypes(text, patterns), ["github-pat"]);
    }
  });
});
