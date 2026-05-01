import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  InMemoryReadModelStore,
  Projector,
  SqliteReadModelStore,
} from "../dist/index.js";
import { MockInterceptor } from "../../hooks-provider/dist/index.js";

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-proj-"));
}

test("projector applies mock session to in-memory store", async () => {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  const interceptor = new MockInterceptor({ sessionId: "sess_imem" });
  const events = interceptor.buildSessionEvents();

  await projector.replay((async function* () {
    for (const e of events) yield e;
  })());

  const sessions = await store.listSessions();
  assert.equal(sessions.length, 1);
  const session = sessions[0];
  assert.equal(session.session_id, "sess_imem");
  assert.equal(session.status, "completed");
  assert.equal(session.tool_call_count, 9);
  assert.equal(session.file_read_count, 2);
  assert.equal(session.file_write_count, 1);
  assert.equal(session.risk_score, 90);
  // mcp_servers should reflect the MCP servers seen in tool.invoked events.
  // The mock has postgres, http-api, and filesystem calls.
  assert.deepEqual(
    [...session.mcp_servers].sort(),
    ["filesystem", "http-api", "postgres"],
  );

  const tools = await store.listToolCalls("sess_imem");
  assert.equal(tools.length, 9);
  for (const t of tools) {
    assert.equal(t.status, "success");
    assert.ok(t.duration_ms !== null);
  }

  const risks = await store.listRiskEvents("sess_imem");
  assert.equal(risks.length, 2);
  assert.equal(risks[0].severity, "HIGH");
  assert.equal(risks[0].category, "sensitive_path_read");
  assert.equal(risks[1].severity, "CRITICAL");
  assert.equal(risks[1].category, "credential_exfiltration");
});

test("projector applies mock session to sqlite store and replay is idempotent", async () => {
  const root = await mkTmp();
  const dbPath = path.join(root, "traces.db");
  const store = new SqliteReadModelStore({ dbPath });
  await store.init();

  const projector = new Projector(store);
  const interceptor = new MockInterceptor({ sessionId: "sess_sqlite" });
  const events = interceptor.buildSessionEvents();
  const iterate = async function* () {
    for (const e of events) yield e;
  };

  await projector.replay(iterate());
  const firstSessions = await store.listSessions();
  assert.equal(firstSessions.length, 1);
  assert.equal(firstSessions[0].tool_call_count, 9);

  // A second replay should produce the same state, not double-count.
  await projector.replay(iterate());
  const secondSessions = await store.listSessions();
  assert.equal(secondSessions.length, 1);
  assert.equal(secondSessions[0].tool_call_count, 9);
  assert.equal(secondSessions[0].file_read_count, 2);
  assert.equal(secondSessions[0].file_write_count, 1);
  assert.equal(secondSessions[0].risk_score, 90);

  await store.close();
});

test("projector derives mcp_servers from tool.invoked events when SessionStart payload is empty", async () => {
  // Simulates the real Claude Code case where SessionStart provides
  // mcp_servers: [] but tool.invoked events carry the actual server names.
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);

  const now = "2026-04-17T00:00:00.000Z";
  const base = {
    schema_version: 1,
    session_id: "sess_mcp_derive",
    occurred_at: now,
    recorded_at: now,
    interceptor: "claude-code-hook",
  };

  await projector.replay((async function* () {
    // SessionStart with empty mcp_servers (as Claude Code sends in practice).
    yield {
      ...base,
      event_id: "e1",
      event_type: "session.started",
      user: "unknown",
      project_path: "/home/brian/project",
      mcp_servers: [],
    };
    // A builtin tool call — should NOT appear in mcp_servers.
    yield {
      ...base,
      event_id: "e2",
      event_type: "tool.invoked",
      tool_call_id: "tc1",
      tool_name: "Grep",
      mcp_server: "builtin",
      parameters: { pattern: "foo" },
    };
    // An MCP tool call — should appear in mcp_servers.
    yield {
      ...base,
      event_id: "e3",
      event_type: "tool.invoked",
      tool_call_id: "tc2",
      tool_name: "mcp__filesystem__read",
      mcp_server: "filesystem",
      parameters: { path: "/tmp/test.txt" },
    };
    // A second call to the same MCP server — should not duplicate.
    yield {
      ...base,
      event_id: "e4",
      event_type: "tool.invoked",
      tool_call_id: "tc3",
      tool_name: "mcp__filesystem__write",
      mcp_server: "filesystem",
      parameters: { path: "/tmp/out.txt", content: "hi" },
    };
    // A different MCP server — should also appear.
    yield {
      ...base,
      event_id: "e5",
      event_type: "tool.invoked",
      tool_call_id: "tc4",
      tool_name: "mcp__postgres__query",
      mcp_server: "postgres",
      parameters: { sql: "SELECT 1" },
    };
  })());

  const session = await store.getSession("sess_mcp_derive");
  assert.ok(session, "session should exist");
  assert.deepEqual(
    [...session.mcp_servers].sort(),
    ["filesystem", "postgres"],
    "mcp_servers should contain only non-builtin servers, without duplicates",
  );
  assert.equal(session.tool_call_count, 4);
});
