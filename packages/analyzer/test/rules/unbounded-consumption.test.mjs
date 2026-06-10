/**
 * Unbounded consumption detection rule unit tests.
 *
 * Covers:
 *   RULE_UNBOUNDED_CONSUMPTION_BURST -- 50 calls in 60s (MEDIUM)
 *   RULE_UNBOUNDED_CONSUMPTION_SUSTAINED -- 200 calls in 5min (HIGH)
 *   rate_threshold condition evaluator behavior
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_UNBOUNDED_CONSUMPTION_BURST,
  RULE_UNBOUNDED_CONSUMPTION_SUSTAINED,
} from "../../dist/rules/index.js";

function makeEvent(sessionId, occurredAt) {
  return {
    schema_version: 1,
    event_id: `evt-${Math.random().toString(36).slice(2)}`,
    session_id: sessionId,
    occurred_at: occurredAt,
    recorded_at: occurredAt,
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: `tc-${Math.random().toString(36).slice(2)}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: "/tmp/test.txt" },
  };
}

/** Generate N events starting at base time, spaced by intervalMs. */
function generateBurst(sessionId, count, baseTime, intervalMs) {
  const events = [];
  for (let i = 0; i < count; i++) {
    const t = new Date(baseTime.getTime() + i * intervalMs).toISOString();
    events.push(makeEvent(sessionId, t));
  }
  return events;
}

// ---------------------------------------------------------------------------
// BURST RULE (50 calls / 60s)
// ---------------------------------------------------------------------------

const burstEngine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);

test("BURST: does not fire for 49 calls in 60s (just below threshold)", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);
  const base = new Date("2026-05-31T10:00:00.000Z");
  const events = generateBurst("sess-burst-49", 49, base, 1000); // 49 calls, 1s apart
  let totalFindings = 0;
  for (const event of events) {
    totalFindings += engine.evaluate(event).length;
  }
  assert.equal(totalFindings, 0, "49 calls in 49s should not fire");
});

test("BURST: fires on the 50th call within 60s window", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);
  const base = new Date("2026-05-31T10:00:00.000Z");
  const events = generateBurst("sess-burst-50", 55, base, 1000); // 55 calls, 1s apart
  let fired = false;
  let fireCount = 0;
  for (const event of events) {
    const findings = engine.evaluate(event);
    if (findings.length > 0) {
      fired = true;
      fireCount++;
      assert.equal(findings[0].severity, "MEDIUM");
      assert.equal(findings[0].category, "unbounded_consumption");
      assert.ok(findings[0].description.includes("50"));
    }
  }
  assert.ok(fired, "Should fire once threshold is reached");
  assert.equal(fireCount, 1, "Should only fire once (suppresses duplicates)");
});

test("BURST: fires again after rate drops and spikes back up", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);
  const base = new Date("2026-05-31T10:00:00.000Z");

  // First burst: 55 calls in 55s
  const burst1 = generateBurst("sess-burst-twice", 55, base, 1000);
  let fireCount = 0;
  for (const event of burst1) {
    fireCount += engine.evaluate(event).length;
  }
  assert.equal(fireCount, 1, "First burst should fire once");

  // Gap: wait 2 minutes (all old timestamps expire from 60s window)
  const gapTime = new Date(base.getTime() + 120000);
  const gapEvent = makeEvent("sess-burst-twice", gapTime.toISOString());
  engine.evaluate(gapEvent); // This should reset fired flag (count drops to 1)

  // Second burst: 55 more calls starting after gap
  const burst2Start = new Date(gapTime.getTime() + 1000);
  const burst2 = generateBurst("sess-burst-twice", 55, burst2Start, 1000);
  let secondFireCount = 0;
  for (const event of burst2) {
    secondFireCount += engine.evaluate(event).length;
  }
  assert.equal(secondFireCount, 1, "Second burst should fire again");
});

test("BURST: separate sessions have independent state", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);
  const base = new Date("2026-05-31T10:00:00.000Z");

  // Session A: 30 calls
  const eventsA = generateBurst("sess-A", 30, base, 1000);
  // Session B: 30 calls
  const eventsB = generateBurst("sess-B", 30, base, 1000);

  let totalFindings = 0;
  for (let i = 0; i < 30; i++) {
    totalFindings += engine.evaluate(eventsA[i]).length;
    totalFindings += engine.evaluate(eventsB[i]).length;
  }
  assert.equal(totalFindings, 0, "Neither session alone should reach threshold");
});

test("BURST: window slides - old events expire", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);
  const base = new Date("2026-05-31T10:00:00.000Z");

  // 25 calls at t=0-24s
  const early = generateBurst("sess-slide", 25, base, 1000);
  for (const e of early) engine.evaluate(e);

  // 25 calls at t=62-86s (first 25 should have expired from 60s window)
  const late = generateBurst(
    "sess-slide", 25,
    new Date(base.getTime() + 62000), 1000
  );
  let findings = 0;
  for (const e of late) findings += engine.evaluate(e).length;
  assert.equal(findings, 0, "With sliding window, old events expire");
});

// ---------------------------------------------------------------------------
// SUSTAINED RULE (200 calls / 300s)
// ---------------------------------------------------------------------------

test("SUSTAINED: fires at 200 calls within 5 minutes", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_SUSTAINED]);
  const base = new Date("2026-05-31T10:00:00.000Z");
  // 210 calls over 210s (1/s) - all within 5min window
  const events = generateBurst("sess-sustained", 210, base, 1000);
  let fired = false;
  let fireCount = 0;
  for (const event of events) {
    const findings = engine.evaluate(event);
    if (findings.length > 0) {
      fired = true;
      fireCount++;
      assert.equal(findings[0].severity, "HIGH");
      assert.equal(findings[0].category, "unbounded_consumption");
    }
  }
  assert.ok(fired, "Should fire at 200 calls");
  assert.equal(fireCount, 1, "Should only fire once");
});

test("SUSTAINED: does not fire for 199 calls in 5 minutes", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_SUSTAINED]);
  const base = new Date("2026-05-31T10:00:00.000Z");
  const events = generateBurst("sess-sustained-199", 199, base, 1000);
  let totalFindings = 0;
  for (const event of events) {
    totalFindings += engine.evaluate(event).length;
  }
  assert.equal(totalFindings, 0);
});

// ---------------------------------------------------------------------------
// BOTH RULES TOGETHER
// ---------------------------------------------------------------------------

test("Both rules can fire independently on the same session", () => {
  const engine = new RuleEngine([
    RULE_UNBOUNDED_CONSUMPTION_BURST,
    RULE_UNBOUNDED_CONSUMPTION_SUSTAINED,
  ]);
  const base = new Date("2026-05-31T10:00:00.000Z");
  // 210 calls at 1/s - burst fires at 50, sustained fires at 200
  const events = generateBurst("sess-both", 210, base, 1000);
  let burstFired = false;
  let sustainedFired = false;
  for (const event of events) {
    const findings = engine.evaluate(event);
    for (const f of findings) {
      if (f.rule_id === "RULE_UNBOUNDED_CONSUMPTION_BURST") burstFired = true;
      if (f.rule_id === "RULE_UNBOUNDED_CONSUMPTION_SUSTAINED") sustainedFired = true;
    }
  }
  assert.ok(burstFired, "Burst rule should fire");
  assert.ok(sustainedFired, "Sustained rule should fire");
});

// ---------------------------------------------------------------------------
// DESCRIPTION TEMPLATE
// ---------------------------------------------------------------------------

test("BURST: description includes rate_count and rate_window", () => {
  const engine = new RuleEngine([RULE_UNBOUNDED_CONSUMPTION_BURST]);
  const base = new Date("2026-05-31T10:00:00.000Z");
  const events = generateBurst("sess-desc", 55, base, 1000);
  let description = "";
  for (const event of events) {
    const findings = engine.evaluate(event);
    if (findings.length > 0) {
      description = findings[0].description;
      break;
    }
  }
  assert.ok(description.includes("50"), `Should contain count, got: ${description}`);
  assert.ok(description.includes("60"), `Should contain window, got: ${description}`);
});
