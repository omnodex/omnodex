/**
 * Tests for collapsing correlated hook and proxy observations for readers.
 *
 * A routed MCP call is recorded by the agent's hook, in the agent's session,
 * and by the proxy, in its own session; the correlation pass gives both rows
 * a shared correlation_id. These tests confirm a reader sees one call and
 * one finding:
 *   1. The pair becomes one call in the agent's session, carrying both
 *      sources, the agent's name for it and the proxy's timing and outcome.
 *   2. The proxy's session gives the call up, and its tool_call_count drops.
 *   3. The same rule raised by both hosts is one finding; a finding only the
 *      proxy raised moves to the agent's session, repointed at the kept call.
 *   4. Risk scores are recomputed for the sessions that changed.
 *   5. A snapshot with nothing correlated comes back as it went in.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { collapseCorrelated, InMemoryReadModelStore, readSnapshot } from "../dist/index.js";

const AT = "2026-09-29T12:00:00.000Z";
const CORR = "corr-1";

function session(id, interceptor, overrides = {}) {
  return {
    session_id: id,
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
    interceptor,
    started_at: AT,
    ended_at: null,
    duration_ms: null,
    status: "completed",
    tool_call_count: 1,
    file_read_count: 0,
    file_write_count: 0,
    risk_score: 0,
    last_event_at: AT,
    source_root: null,
    ...overrides,
  };
}

function call(id, sessionId, interceptor, overrides = {}) {
  return {
    tool_call_id: id,
    session_id: sessionId,
    tool_name: interceptor === "mcp-proxy" ? "read_file" : "mcp__filesystem__read_file",
    mcp_server: "filesystem",
    interceptor,
    correlation_id: CORR,
    parameters_json: "{\"path\":\"/home/case/repo/README.md\"}",
    started_at: AT,
    ended_at: null,
    duration_ms: null,
    status: "in_progress",
    response_bytes: null,
    error_message: null,
    ...overrides,
  };
}

function finding(sessionId, relatedId, ruleId, overrides = {}) {
  return {
    event_id: `f-${sessionId}-${ruleId}`,
    session_id: sessionId,
    related_event_id: relatedId,
    severity: "HIGH",
    category: "sensitive_path_read",
    description: "read a sensitive path",
    rule_id: ruleId,
    detected_at: AT,
    correlation_id: CORR,
    ...overrides,
  };
}

/** Agent session "hook" and proxy session "proxy", one routed call between them. */
function pairSnapshot() {
  return {
    sessions: [
      session("hook", "claude-code-hook", { risk_score: 0.7 }),
      session("proxy", "mcp-proxy", { risk_score: 1.4 }),
    ],
    tool_calls: {
      hook: [call("tc-hook", "hook", "claude-code-hook")],
      proxy: [call("tc-proxy", "proxy", "mcp-proxy", {
        ended_at: "2026-09-29T12:00:01.000Z",
        duration_ms: 250,
        response_bytes: 512,
        status: "success",
      })],
    },
    file_events: { hook: [], proxy: [] },
    risk_events: {
      hook: [finding("hook", "tc-hook", "rule_sensitive_path")],
      proxy: [
        finding("proxy", "tc-proxy", "rule_sensitive_path"),
        finding("proxy", "tc-proxy", "rule_proxy_only"),
      ],
    },
  };
}

test("a correlated pair becomes one call in the agent's session", () => {
  const out = collapseCorrelated(pairSnapshot());
  assert.equal(out.tool_calls.hook.length, 1);
  assert.equal(out.tool_calls.proxy.length, 0);

  const kept = out.tool_calls.hook[0];
  assert.equal(kept.tool_call_id, "tc-hook");
  assert.equal(kept.tool_name, "mcp__filesystem__read_file");
  assert.deepEqual(kept.sources, ["claude-code-hook", "mcp-proxy"]);
  assert.equal(kept.duration_ms, 250);
  assert.equal(kept.response_bytes, 512);
  assert.equal(kept.status, "success");

  const byId = Object.fromEntries(out.sessions.map((s) => [s.session_id, s]));
  assert.equal(byId.hook.tool_call_count, 1);
  assert.equal(byId.proxy.tool_call_count, 0);
});

test("an error on the proxy's side is an error on the merged call", () => {
  const snap = pairSnapshot();
  snap.tool_calls.proxy[0].status = "error";
  snap.tool_calls.proxy[0].error_message = "upstream refused";
  const kept = collapseCorrelated(snap).tool_calls.hook[0];
  assert.equal(kept.status, "error");
  assert.equal(kept.error_message, "upstream refused");
});

test("one rule raised by both hosts is one finding, kept in the agent's session", () => {
  const out = collapseCorrelated(pairSnapshot());
  const hookRules = out.risk_events.hook.map((r) => r.rule_id).sort();
  assert.deepEqual(hookRules, ["rule_proxy_only", "rule_sensitive_path"]);
  assert.equal(out.risk_events.proxy.length, 0);

  const moved = out.risk_events.hook.find((r) => r.rule_id === "rule_proxy_only");
  assert.equal(moved.session_id, "hook");
  assert.equal(moved.related_event_id, "tc-hook", "repointed at the call that was kept");
});

test("risk scores are recomputed for the sessions that changed", () => {
  const byId = Object.fromEntries(collapseCorrelated(pairSnapshot()).sessions.map((s) => [s.session_id, s]));
  assert.equal(byId.hook.risk_score, 1.4, "two HIGH findings");
  assert.equal(byId.proxy.risk_score, 0);
});

test("a sequence finding's pattern names the calls that were kept", () => {
  const snap = pairSnapshot();
  // A sequence the proxy saw: an earlier plain call, then the routed one.
  snap.tool_calls.proxy.unshift(call("tc-earlier", "proxy", "mcp-proxy", { correlation_id: null }));
  snap.risk_events.proxy.push(finding("proxy", "tc-proxy", "rule_sequence", {
    rule_tier: "advanced",
    related_event_ids: ["tc-earlier", "tc-proxy"],
  }));
  const out = collapseCorrelated(snap);
  const seq = out.risk_events.hook.find((r) => r.rule_id === "rule_sequence");
  assert.equal(seq.related_event_id, "tc-hook");
  assert.deepEqual(seq.related_event_ids, ["tc-earlier", "tc-hook"], "the proxy's id for the routed call is repointed");
  assert.equal(seq.rule_tier, "advanced");
});

test("a snapshot with nothing correlated comes back unchanged", async () => {
  const snap = pairSnapshot();
  for (const rows of Object.values(snap.tool_calls)) for (const r of rows) r.correlation_id = null;
  for (const rows of Object.values(snap.risk_events)) for (const r of rows) delete r.correlation_id;
  assert.equal(collapseCorrelated(snap), snap);

  // And an empty store reads as an empty snapshot.
  const empty = await readSnapshot(new InMemoryReadModelStore());
  assert.deepEqual(collapseCorrelated(empty), { sessions: [], tool_calls: {}, file_events: {}, risk_events: {} });
});
