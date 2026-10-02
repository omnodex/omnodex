// Prompt, subagent and permission events in the event log and read model.
// Prompts and subagents are projected into their own rows, and tool calls
// made inside a subagent carry its agent_id. Permission events are accepted
// by the log but not projected yet.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { SCHEMA_VERSION, isEventOfType } from "../../shared/dist/index.js";
import { EventLog } from "../../event-log/dist/index.js";
import { InMemoryReadModelStore, Projector, SqliteReadModelStore, readSnapshot } from "../dist/index.js";
import { MockInterceptor } from "../../hooks-provider/dist/index.js";

const SESSION = "sess_agent_events";

function at(second) {
  return `2026-10-02T12:00:${String(second).padStart(2, "0")}.000Z`;
}

function base(second) {
  return {
    schema_version: SCHEMA_VERSION,
    session_id: SESSION,
    occurred_at: at(second),
    recorded_at: at(second),
    interceptor: "claude-code-hook",
    platform: "claude-code",
  };
}

function agentEvents() {
  return [
    { ...base(1), event_id: "ev-prompt", event_type: "prompt.submitted", prompt: "Summarise /home/case/repo/README.md", prompt_id: "prompt-1" },
    { ...base(2), event_id: "ev-sub-start", event_type: "subagent.started", agent_id: "agent-1", agent_type: "Explore" },
    { ...base(3), event_id: "ev-sub-tool", event_type: "tool.invoked", agent_id: "agent-1", tool_call_id: "tc-sub", tool_name: "Read", mcp_server: "builtin", parameters: { file_path: "/home/case/repo/README.md" } },
    { ...base(4), event_id: "ev-perm-req", event_type: "permission.requested", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "npm test" }, permission_type: "execute" },
    { ...base(5), event_id: "ev-perm-deny", event_type: "permission.denied", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "rm -rf /" }, tool_call_id: "toolu_case", reason: "user" },
    { ...base(6), event_id: "ev-sub-stop", event_type: "subagent.stopped", agent_id: "agent-1", agent_type: "Explore", duration_ms: 4000, status: "completed", response_bytes: 512 },
  ];
}

async function sqliteStore(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-agent-events-"));
  const dbPath = path.join(root, "traces.db");
  const store = new SqliteReadModelStore({ dbPath });
  await store.init();
  t.after(async () => {
    await store.close();
    await fs.rm(root, { recursive: true, force: true });
  });
  return { store, dbPath };
}

async function replay(store, events) {
  await new Projector(store).replay((async function* () { for (const e of events) yield e; })());
  return store;
}

const STORES = [
  ["in-memory", async () => new InMemoryReadModelStore()],
  ["sqlite", async (t) => (await sqliteStore(t)).store],
];

test("the event log accepts every new event type at the current schema version", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-agent-log-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const log = new EventLog({ root });
  await log.init();
  for (const event of agentEvents()) await log.append(event);
  await log.close();
  const read = await new EventLog({ root }).readSession(SESSION);
  assert.deepEqual(read.map((e) => e.event_type), agentEvents().map((e) => e.event_type));
});

for (const [name, makeStore] of STORES) {
  test(`${name}: prompts, subagents and a subagent's tool calls are projected`, async (t) => {
    const store = await replay(await makeStore(t), agentEvents());
    assert.deepEqual(await store.listPrompts(SESSION), [
      { event_id: "ev-prompt", session_id: SESSION, prompt: "Summarise /home/case/repo/README.md", prompt_id: "prompt-1", at: at(1) },
    ]);
    assert.deepEqual(await store.listSubagents(SESSION), [{
      session_id: SESSION, agent_id: "agent-1", agent_type: "Explore", started_at: at(2), ended_at: at(6),
      duration_ms: 4000, status: "completed", response_bytes: 512,
    }]);
    const [call] = await store.listToolCalls(SESSION);
    assert.equal(call.agent_id, "agent-1");
    const session = await store.getSession(SESSION);
    assert.equal(session.last_event_at, at(6));
    assert.equal(session.tool_call_count, 1);
  });

  test(`${name}: replay is idempotent with the new rows`, async (t) => {
    const store = await makeStore(t);
    const projector = new Projector(store);
    for (const e of agentEvents()) await projector.apply(e);
    const first = await readSnapshot(store);
    for (const e of agentEvents()) await projector.apply(e);
    assert.deepEqual(await readSnapshot(store), first);
  });

  test(`${name}: a stop seen before its start leaves the subagent completed`, async (t) => {
    const events = agentEvents();
    const start = events.find((e) => e.event_type === "subagent.started");
    const stop = events.find((e) => e.event_type === "subagent.stopped");
    const store = await replay(await makeStore(t), [stop, start]);
    const [row] = await store.listSubagents(SESSION);
    assert.equal(row.status, "completed");
    assert.equal(row.started_at, at(2));
    assert.equal(row.duration_ms, 4000);
  });

  test(`${name}: a stop with no start still records the subagent`, async (t) => {
    const stop = agentEvents().find((e) => e.event_type === "subagent.stopped");
    const store = await replay(await makeStore(t), [{ ...stop, agent_type: undefined, status: undefined, response_bytes: undefined }]);
    const [row] = await store.listSubagents(SESSION);
    assert.equal(row.started_at, null);
    assert.equal(row.status, "completed");
    assert.equal("agent_type" in row, false);
  });
}

test("permission events are not projected: the read model matches one without them", async () => {
  const mock = new MockInterceptor({ sessionId: SESSION }).buildSessionEvents();
  const permissions = agentEvents().filter((e) => e.event_type.startsWith("permission."));
  const [start, ...rest] = mock;
  const withPermissions = await readSnapshot(await replay(new InMemoryReadModelStore(), [start, ...permissions, ...rest]));
  const without = await readSnapshot(await replay(new InMemoryReadModelStore(), mock));
  assert.deepEqual(withPermissions, without);
});

test("a database from before agent_id gains the column and reads it", async (t) => {
  const { store, dbPath } = await sqliteStore(t);
  await store.close();
  const db = new DatabaseSync(dbPath);
  db.exec("ALTER TABLE tool_calls DROP COLUMN agent_id");
  db.close();
  await store.init();
  await replay(store, agentEvents());
  const [call] = await store.listToolCalls(SESSION);
  assert.equal(call.agent_id, "agent-1");
});

test("isEventOfType narrows the new types", () => {
  const [prompt, started] = agentEvents();
  assert.equal(isEventOfType(prompt, "prompt.submitted"), true);
  assert.equal(isEventOfType(started, "prompt.submitted"), false);
  assert.equal(isEventOfType(started, "subagent.started"), true);
});
