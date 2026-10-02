/**
 * The local dashboard's view logic: filters, the connection tree, the
 * grouped credential ledger, call sorting and parameter display.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  NO_FILTERS,
  connectionTree,
  filterOptions,
  filterSessions,
  groupedLedger,
  narrowView,
  parseParameters,
  selectView,
  sortCalls,
  timelineEntries,
  promptPreview,
  subagentLabel,
  ALL_SESSIONS,
} from "../dist/dashboard-model/index.js";

const NOW = Date.parse("2026-09-30T12:00:00Z");
const hoursAgo = (h) => new Date(NOW - h * 3_600_000).toISOString();

function session(id, over = {}) {
  return {
    session_id: id, user: "case", project_path: `/home/case/${id}`, mcp_servers: [], interceptor: "claude-code-hook",
    started_at: hoursAgo(2), ended_at: null, duration_ms: null, status: "completed", tool_call_count: 1,
    file_read_count: 0, file_write_count: 0, risk_score: 0, last_event_at: hoursAgo(1), source_root: "/home/case/.omnodex",
    ...over,
  };
}

function call(id, sessionId, over = {}) {
  return {
    tool_call_id: id, session_id: sessionId, tool_name: "Bash", mcp_server: "builtin", parameters_json: "{}",
    started_at: hoursAgo(1), ended_at: null, duration_ms: 10, status: "success", response_bytes: 5, error_message: null,
    ...over,
  };
}

const snapshot = {
  sessions: [
    session("a"),
    session("b", { interceptor: "codex-hook", status: "in_progress", risk_score: 0.8, last_event_at: hoursAgo(30) }),
    session("c", { interceptor: "mcp-proxy", platform: "cowork", source_root: "/mnt/c/Users/case/.omnodex", mcp_servers: ["filesystem", "github"] }),
  ],
  tool_calls: {
    a: [call("a1", "a", { started_at: hoursAgo(0.5) }), call("a2", "a", { started_at: hoursAgo(26), tool_name: "Read" })],
    b: [call("b1", "b", { started_at: hoursAgo(30) })],
    c: [call("c1", "c", { mcp_server: "filesystem", tool_name: "read_file" }), call("c2", "c", { mcp_server: "filesystem", tool_name: "read_file" }), call("c3", "c", { mcp_server: "filesystem", tool_name: "list_directory" })],
  },
  file_events: { a: [{ event_id: "f1", session_id: "a", direction: "read", path: "/x", bytes: 3, at: hoursAgo(0.5) }] },
  risk_events: {
    a: [{ event_id: "r1", session_id: "a", related_event_id: "a1", severity: "HIGH", category: "c", description: "d", rule_id: "R", detected_at: hoursAgo(0.5) }],
  },
};

test("session filters narrow by runtime, status, risk, root, time and the hidden list", () => {
  const ids = (f) => filterSessions(snapshot.sessions, { ...NO_FILTERS, ...f }, NOW).map((s) => s.session_id);
  assert.deepEqual(ids({}), ["a", "b", "c"]);
  assert.deepEqual(ids({ runtimes: ["Codex"] }), ["b"]);
  assert.deepEqual(ids({ runtimes: ["Cowork via MCP Proxy"] }), ["c"]);
  assert.deepEqual(ids({ statuses: ["in_progress"] }), ["b"]);
  assert.deepEqual(ids({ risk: "MEDIUM" }), ["b"]);
  assert.deepEqual(ids({ risk: "CRITICAL" }), []);
  assert.deepEqual(ids({ roots: ["/mnt/c/Users/case/.omnodex"] }), ["c"]);
  assert.deepEqual(ids({ time: "24h" }), ["a", "c"]);
  assert.deepEqual(ids({ hidden: ["a"] }), ["b", "c"]);
  assert.deepEqual(ids({ hidden: ["a"], showHidden: true }), ["a", "b", "c"]);
});

test("filter menus offer the values the sessions hold", () => {
  const o = filterOptions(snapshot.sessions);
  assert.deepEqual(o.runtimes, ["Claude Code", "Codex", "Cowork via MCP Proxy"]);
  assert.deepEqual(o.statuses, ["completed", "in_progress"]);
  assert.equal(o.roots.length, 2);
});

test("the time range and a graph selection narrow rows, and findings follow their calls", () => {
  const view = selectView(snapshot, ALL_SESSIONS);
  const day = narrowView(view, { ...NO_FILTERS, time: "24h" }, NOW);
  assert.deepEqual(day.toolCalls.map((t) => t.tool_call_id).sort(), ["a1", "c1", "c2", "c3"]);
  assert.equal(day.riskEvents.length, 1);
  assert.equal(day.fileEvents.length, 1);

  const fs = narrowView(view, { ...NO_FILTERS, graph: { runtime: "Cowork via MCP Proxy", server: "filesystem" } }, NOW);
  assert.deepEqual(fs.toolCalls.map((t) => t.tool_call_id).sort(), ["c1", "c2", "c3"]);
  assert.equal(fs.riskEvents.length, 0, "the finding was on a call outside the selection");
  assert.equal(fs.fileEvents.length, 0, "an MCP server selection has no file events");

  const builtin = narrowView(view, { ...NO_FILTERS, graph: { runtime: "Claude Code", server: "builtin" } }, NOW);
  assert.equal(builtin.fileEvents.length, 1, "built-in tools keep the runtime's file events");
  const tool = narrowView(view, { ...NO_FILTERS, graph: { runtime: "Cowork via MCP Proxy", server: "filesystem", tool: "list_directory" } }, NOW);
  assert.deepEqual(tool.toolCalls.map((t) => t.tool_call_id), ["c3"]);
});

test("the connection tree groups runtime, server and tools, busiest first, with idle servers", () => {
  const view = selectView(snapshot, ALL_SESSIONS);
  const tree = connectionTree(view.sessions, view.toolCalls);
  assert.deepEqual(tree.map((n) => [n.label, n.calls]), [["Cowork via MCP Proxy", 3], ["Claude Code", 2], ["Codex", 1]]);
  const cowork = tree[0];
  assert.deepEqual(cowork.children.map((c) => [c.kind, c.label]), [["server", "filesystem"], ["idle", "1 idle server"]]);
  assert.deepEqual(cowork.children[0].tools, [{ name: "read_file", calls: 2 }, { name: "list_directory", calls: 1 }]);
  assert.deepEqual(cowork.children[1].tools, [{ name: "github", calls: 0 }]);
  assert.equal(tree[1].children[0].label, "Built-in tools");
  assert.deepEqual(cowork.children[0].path, { runtime: "Cowork via MCP Proxy", server: "filesystem" });
});

test("the credential ledger groups uses of one credential, newest first", () => {
  const token = ["Hj5Wq2Ez9Rb4Yc7N", "Lm3Xp8Kd2Tr6Vb1Q"].join("");
  const calls = [
    call("x1", "a", { started_at: hoursAgo(3), parameters_json: JSON.stringify({ headers: { Authorization: `Bearer ${token}` } }) }),
    call("x2", "a", { started_at: hoursAgo(1), mcp_server: "http", tool_name: "fetch", parameters_json: JSON.stringify({ auth: `Bearer ${token}` }) }),
    call("x3", "a", { started_at: hoursAgo(2), parameters_json: JSON.stringify({ text: "Bearer tokens are sent in headers" }) }),
  ];
  const ledger = groupedLedger(calls);
  assert.equal(ledger.length, 1, "prose about bearer tokens is not a credential");
  assert.equal(ledger[0].type, "bearer");
  assert.deepEqual(ledger[0].uses.map((u) => u.toolCallId), ["x2", "x1"]);
  assert.equal(ledger[0].firstSeen, hoursAgo(3));
  assert.equal(ledger[0].lastSeen, hoursAgo(1));
  assert.ok(!JSON.stringify(ledger).includes(token), "the full value never leaves the ledger");
});

test("tool calls sort by any column, ties newest first", () => {
  const calls = [call("1", "a", { tool_name: "b", duration_ms: 5, started_at: hoursAgo(3) }), call("2", "a", { tool_name: "a", duration_ms: 50, started_at: hoursAgo(1) }), call("3", "a", { tool_name: "a", duration_ms: null, started_at: hoursAgo(2) })];
  assert.deepEqual(sortCalls(calls, "time", "desc").map((c) => c.tool_call_id), ["2", "3", "1"]);
  assert.deepEqual(sortCalls(calls, "tool", "asc").map((c) => c.tool_call_id), ["2", "3", "1"]);
  assert.deepEqual(sortCalls(calls, "duration", "desc").map((c) => c.tool_call_id), ["2", "1", "3"]);
});

test("parameters show long and multi-line strings as text blocks", () => {
  const node = parseParameters(JSON.stringify({ file_path: "/a.ts", content: "line one\nline two", n: 3, nested: { ok: true } }));
  assert.equal(node.kind, "object");
  const byKey = Object.fromEntries(node.entries.map((e) => [e.key, e.value]));
  assert.deepEqual(byKey.file_path, { kind: "scalar", value: '"/a.ts"' });
  assert.deepEqual(byKey.content, { kind: "text", value: "line one\nline two" });
  assert.deepEqual(byKey.n, { kind: "scalar", value: "3" });
  assert.equal(byKey.nested.kind, "object");
  assert.deepEqual(parseParameters("not json"), { kind: "text", value: "not json" });
});

// --- Prompts and subagents in the timeline ---

function agentSnapshot() {
  const t = (m) => `2026-09-30T11:${String(m).padStart(2, "0")}:00.000Z`;
  return {
    sessions: [session("s1", { last_event_at: t(9) })],
    tool_calls: {
      s1: [
        call("main-call", "s1", { started_at: t(1) }),
        call("sub-call", "s1", { started_at: t(3), agent_id: "agent-1", tool_name: "Read" }),
        call("same-instant", "s1", { started_at: t(5) }),
      ],
    },
    file_events: { s1: [] },
    risk_events: { s1: [] },
    prompts: { s1: [{ event_id: "p1", session_id: "s1", prompt: "Find the call sites", at: t(0) }] },
    subagents: { s1: [{ session_id: "s1", agent_id: "agent-1", agent_type: "Explore", started_at: t(2), ended_at: t(5), duration_ms: 180000, status: "completed", response_bytes: 40 }] },
  };
}

test("one session's timeline interleaves prompts, subagent markers and calls, oldest first", () => {
  const entries = timelineEntries(selectView(agentSnapshot(), "s1"), false);
  assert.deepEqual(entries.map((e) => e.kind === "call" ? e.call.tool_call_id : e.kind), [
    "prompt", "main-call", "subagent-start", "sub-call", "same-instant", "subagent-stop",
  ]);
  const sub = entries.find((e) => e.kind === "call" && e.call.tool_call_id === "sub-call");
  assert.equal(subagentLabel(sub.subagent), "Explore");
  assert.equal(entries.find((e) => e.kind === "call" && e.call.tool_call_id === "main-call").subagent, undefined);
});

test("the all-sessions timeline is the same entries newest first", () => {
  const view = selectView(agentSnapshot(), ALL_SESSIONS);
  const oldest = timelineEntries(view, false).map((e) => e.kind + (e.call?.tool_call_id ?? ""));
  assert.deepEqual(timelineEntries(view, true).map((e) => e.kind + (e.call?.tool_call_id ?? "")), [...oldest].reverse());
});

test("a running subagent has a start marker and no finish", () => {
  const snap = agentSnapshot();
  snap.subagents.s1[0] = { ...snap.subagents.s1[0], ended_at: null, duration_ms: null, status: "in_progress" };
  const kinds = timelineEntries(selectView(snap, "s1"), false).map((e) => e.kind);
  assert.equal(kinds.includes("subagent-start"), true);
  assert.equal(kinds.includes("subagent-stop"), false);
});

test("a session without prompts or subagents reads as before", () => {
  const snap = agentSnapshot();
  delete snap.prompts;
  delete snap.subagents;
  const view = selectView(snap, "s1");
  assert.deepEqual(view.prompts, []);
  assert.deepEqual(view.subagents, []);
  assert.deepEqual(timelineEntries(view, false).map((e) => e.kind), ["call", "call", "call"]);
});

test("a server or tool selection hides prompts and subagents; the time range applies to them", () => {
  const view = selectView(agentSnapshot(), "s1");
  const byServer = narrowView(view, { ...NO_FILTERS, graph: { server: "builtin" } }, Date.parse("2026-09-30T12:00:00Z"));
  assert.deepEqual([byServer.prompts.length, byServer.subagents.length], [0, 0]);
  const lastHour = narrowView(view, { ...NO_FILTERS, time: "1h" }, Date.parse("2026-09-30T12:00:00Z"));
  assert.deepEqual([lastHour.prompts.length, lastHour.subagents.length], [1, 1]);
  const later = narrowView(view, { ...NO_FILTERS, time: "1h" }, Date.parse("2026-09-30T13:30:00Z"));
  assert.deepEqual([later.prompts.length, later.subagents.length], [0, 0]);
});

test("promptPreview keeps one line and shortens long prompts", () => {
  assert.equal(promptPreview("Fix\n  the  build"), "Fix the build");
  const long = promptPreview("x".repeat(500));
  assert.equal(long.length, 140);
  assert.ok(long.endsWith("…"));
});
