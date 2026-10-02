// Prompt, subagent and permission events are part of the TraceEvent union
// before the read model has a place for them. Until it does, they must be
// accepted by the event log and pass through the projector without changing
// anything, so an interceptor can start emitting them at any time.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { SCHEMA_VERSION, isEventOfType } from "../../shared/dist/index.js";
import { EventLog } from "../../event-log/dist/index.js";
import { InMemoryReadModelStore, Projector } from "../dist/index.js";
import { MockInterceptor } from "../../hooks-provider/dist/index.js";

const SESSION = "sess_agent_events";

function agentEvents() {
  const at = "2026-10-02T12:00:00.000Z";
  const base = {
    schema_version: SCHEMA_VERSION,
    session_id: SESSION,
    occurred_at: at,
    recorded_at: at,
    interceptor: "claude-code-hook",
    platform: "claude-code",
  };
  return [
    { ...base, event_id: "ev-prompt", event_type: "prompt.submitted", prompt: "Summarise /home/case/repo/README.md", prompt_id: "prompt-1" },
    { ...base, event_id: "ev-sub-start", event_type: "subagent.started", agent_id: "agent-1", agent_type: "Explore" },
    { ...base, event_id: "ev-perm-req", event_type: "permission.requested", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "npm test" }, permission_type: "execute" },
    { ...base, event_id: "ev-perm-deny", event_type: "permission.denied", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "rm -rf /" }, tool_call_id: "toolu_case", reason: "user" },
    { ...base, event_id: "ev-sub-stop", event_type: "subagent.stopped", agent_id: "agent-1", agent_type: "Explore", duration_ms: 1200, status: "completed", response_bytes: 512 },
  ];
}

async function project(events) {
  const store = new InMemoryReadModelStore();
  await new Projector(store).replay((async function* () { for (const e of events) yield e; })());
  const sessions = await store.listSessions();
  const rows = {};
  for (const s of sessions) {
    rows[s.session_id] = {
      tools: await store.listToolCalls(s.session_id),
      files: await store.listFileEvents(s.session_id),
      risks: await store.listRiskEvents(s.session_id),
    };
  }
  return { sessions, rows };
}

test("the event log accepts every new event type at the current schema version", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-agent-events-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const log = new EventLog({ root });
  await log.init();
  for (const event of agentEvents()) await log.append(event);
  await log.close();

  const read = await new EventLog({ root }).readSession(SESSION);
  assert.deepEqual(read.map((e) => e.event_type), agentEvents().map((e) => e.event_type));
  assert.equal(read[0].prompt, "Summarise /home/case/repo/README.md");
});

test("the projector ignores the new types: the read model is unchanged", async () => {
  const mock = new MockInterceptor({ sessionId: SESSION }).buildSessionEvents();
  // A tool call made inside a subagent carries the subagent's id.
  const withAgent = mock.map((e) => (e.event_type === "tool.invoked" ? { ...e, agent_id: "agent-1" } : e));
  const [start, ...rest] = withAgent;
  const mixed = [start, ...agentEvents(), ...rest];

  assert.deepEqual(await project(mixed), await project(mock));
});

test("a session seen only through the new types creates no read-model rows", async () => {
  const { sessions } = await project(agentEvents());
  assert.deepEqual(sessions, []);
});

test("isEventOfType narrows the new types", () => {
  const [prompt, started] = agentEvents();
  assert.equal(isEventOfType(prompt, "prompt.submitted"), true);
  assert.equal(isEventOfType(started, "prompt.submitted"), false);
  assert.equal(isEventOfType(started, "subagent.started"), true);
});
