/**
 * Tests for what the local dashboard shows.
 *
 * These tests confirm:
 *   1. Sessions tailed concurrently from several roots keep their own root,
 *      whatever the root's path format (Windows, WSL, macOS, Linux). One
 *      projector serves every tail, and they interleave.
 *   2. /api/snapshot serves correlated hook and proxy observations as one
 *      call and one finding, with session totals to match.
 *   3. The page labels each session by its agent runtime, not a fixed name.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog, newEventId } from "../../event-log/dist/index.js";
import { InMemoryReadModelStore, Projector } from "../../projection/dist/index.js";
import { createEvaluator } from "../../analyzer/dist/index.js";
import { tailSession } from "../dist/streaming.js";
import { DashboardServer } from "../dist/dashboard-server.js";
import { runtimeLabel } from "../dist/dashboard-model/index.js";

const AT = "2026-09-29T12:00:00.000Z";

function base(sessionId, n, overrides = {}) {
  return {
    schema_version: 1,
    event_id: `${sessionId}-e${n}`,
    session_id: sessionId,
    occurred_at: new Date(Date.parse(AT) + n * 1000).toISOString(),
    recorded_at: AT,
    interceptor: "claude-code-hook",
    ...overrides,
  };
}

function sessionEvents(sessionId, count) {
  const events = [
    base(sessionId, 0, { event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] }),
  ];
  for (let i = 1; i <= count; i++) {
    events.push(base(sessionId, i, {
      event_type: "tool.invoked",
      tool_call_id: `${sessionId}-tc${i}`,
      tool_name: "Read",
      mcp_server: "builtin",
      parameters: { path: "/home/case/repo/README.md" },
    }));
  }
  return events;
}

// ---------------------------------------------------------------------------
// Source root under concurrent tails
// ---------------------------------------------------------------------------

test("concurrently tailed sessions keep their own root in every path format", async (t) => {
  const roots = [
    "C:\\Users\\case\\.omnodex",
    "/mnt/c/Users/case/.omnodex",
    "/Users/case/.omnodex",
    "/home/case/.omnodex",
  ];
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-roots-"));
  t.after(() => fs.rm(tmp, { recursive: true, force: true }));

  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const server = { broadcast() {} };
  const evaluator = createEvaluator({ host: "batch", newEventId });
  const ctrl = new AbortController();

  const logs = await Promise.all(roots.map(async (_, i) => {
    const log = new EventLog({ root: path.join(tmp, `log${i}`) });
    await log.init();
    return log;
  }));

  // Every tail starts before any of its session's events exist, one after
  // another, so each later tail starts after the earlier ones are waiting.
  // The events then arrive live and interleaved: each session is created
  // by an apply that runs while all four tails share the projector.
  const running = [];
  for (let i = 0; i < roots.length; i++) {
    running.push(tailSession(`sess${i}`, logs[i], store, projector, server, evaluator, ctrl.signal, false, roots[i]));
    await new Promise((r) => setTimeout(r, 30));
  }
  const events = roots.map((_, i) => sessionEvents(`sess${i}`, 3));
  for (let n = 0; n < events[0].length; n++) {
    for (let i = 0; i < roots.length; i++) await logs[i].append(events[i][n]);
  }

  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const counts = await Promise.all(roots.map(async (_, i) => (await store.getSession(`sess${i}`))?.tool_call_count ?? 0));
    if (counts.every((c) => c === 3)) break;
    await new Promise((r) => setTimeout(r, 20));
  }
  ctrl.abort();
  await Promise.all(running);
  for (const log of logs) await log.close();

  for (let i = 0; i < roots.length; i++) {
    const session = await store.getSession(`sess${i}`);
    assert.ok(session, `sess${i} was never projected`);
    assert.equal(session.source_root, roots[i], `sess${i} was stamped with another root`);
    assert.equal(session.tool_call_count, 3);
  }
});

// ---------------------------------------------------------------------------
// /api/snapshot
// ---------------------------------------------------------------------------

function getJson(port, pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: pathname, headers: { host: `localhost:${port}` } }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(body) }));
    }).on("error", reject);
  });
}

test("/api/snapshot serves a correlated pair as one call and one finding", async (t) => {
  const store = new InMemoryReadModelStore();
  const session = (id, interceptor) => ({
    session_id: id, user: "case", project_path: "/home/case/repo", mcp_servers: [], interceptor,
    started_at: AT, ended_at: null, duration_ms: null, status: "completed",
    tool_call_count: 1, file_read_count: 0, file_write_count: 0, risk_score: 0.7,
    last_event_at: AT, source_root: null,
  });
  const call = (id, sid, interceptor) => ({
    tool_call_id: id, session_id: sid, tool_name: "read_file", mcp_server: "filesystem", interceptor,
    correlation_id: "corr-1", parameters_json: "{}", started_at: AT, ended_at: null, duration_ms: null,
    status: "success", response_bytes: null, error_message: null,
  });
  const finding = (sid, rel) => ({
    event_id: `f-${sid}`, session_id: sid, related_event_id: rel, severity: "HIGH", category: "x",
    description: "d", rule_id: "rule_1", detected_at: AT, correlation_id: "corr-1",
  });
  await store.upsertSession(session("hook", "claude-code-hook"));
  await store.upsertSession(session("proxy", "mcp-proxy"));
  await store.insertToolCall(call("tc-hook", "hook", "claude-code-hook"));
  await store.insertToolCall(call("tc-proxy", "proxy", "mcp-proxy"));
  await store.insertRiskEvent(finding("hook", "tc-hook"));
  await store.insertRiskEvent(finding("proxy", "tc-proxy"));

  const assetsDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-snap-"));
  const server = new DashboardServer({ store, port: 0, assetsDir });
  t.after(async () => {
    await server.close();
    await fs.rm(assetsDir, { recursive: true, force: true });
  });
  await server.ready;

  const { status, body } = await getJson(server.port, "/api/snapshot");
  assert.equal(status, 200);
  const calls = Object.values(body.tool_calls).flat();
  const findings = Object.values(body.risk_events).flat();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].sources, ["claude-code-hook", "mcp-proxy"]);
  assert.equal(findings.length, 1);
  const total = body.sessions.reduce((n, s) => n + s.tool_call_count, 0);
  assert.equal(total, 1, "session totals count the pair once");
  const risk = body.sessions.reduce((n, s) => n + s.risk_score, 0);
  assert.equal(Math.round(risk * 100) / 100, 0.7, "the finding is scored once");
});

// ---------------------------------------------------------------------------
// Runtime labels on the page
// ---------------------------------------------------------------------------

test("the page labels each session by its agent runtime", () => {
  const cases = [
    [{ interceptor: "claude-code-hook", platform: "claude-code" }, "Claude Code"],
    [{ interceptor: "claude-code-hook" }, "Claude Code"],
    [{ interceptor: "claude-code-hook", platform: "cowork" }, "Cowork Cloud"],
    [{ interceptor: "cowork-desktop" }, "Cowork"],
    [{ interceptor: "codex-hook", platform: "codex" }, "Codex"],
    [{ interceptor: "codex-hook" }, "Codex"],
    [{ interceptor: "antigravity-hook", platform: "antigravity" }, "Antigravity"],
    [{ interceptor: "mcp-proxy" }, "MCP Proxy"],
    [{ interceptor: "mcp-proxy", platform: "codex" }, "Codex via MCP Proxy"],
    [{ interceptor: "mcp-proxy", platform: "cowork", mcp_client_name: "claude-ai" }, "Cowork via MCP Proxy"],
    [{ interceptor: "mcp-proxy", mcp_client_name: "Some Client" }, "Some Client via MCP Proxy"],
  ];
  for (const [session, expected] of cases) {
    assert.equal(runtimeLabel(session), expected, JSON.stringify(session));
  }
});
