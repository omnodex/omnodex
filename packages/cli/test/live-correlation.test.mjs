/**
 * Tests for pairing routed MCP calls while the dashboard runs.
 *
 * A call routed through the MCP proxy is recorded by the agent's hook and by
 * the proxy, in two sessions, about a second apart. These tests confirm the
 * streaming loop pairs them once they arrive, without a restart:
 *   1. Both rows gain the same correlation_id.
 *   2. The page is told to reload (read_model.changed).
 *   3. The collapsed snapshot the page renders counts the call once.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../../event-log/dist/index.js";
import {
  collapseCorrelated,
  InMemoryReadModelStore,
  Projector,
  readSnapshot,
} from "../../projection/dist/index.js";
import { startStreamingLoop } from "../dist/streaming.js";

const HOOK_AT = "2026-09-29T12:00:00.000Z";
const PROXY_AT = "2026-09-29T12:00:01.400Z";
const PARAMS = { path: "/home/case/repo/README.md", head: 3 };

function event(sessionId, interceptor, at, n, body) {
  return {
    schema_version: 1,
    event_id: `${sessionId}-e${n}`,
    session_id: sessionId,
    occurred_at: at,
    recorded_at: at,
    interceptor,
    ...body,
  };
}

function started(sessionId, interceptor) {
  return event(sessionId, interceptor, HOOK_AT, 0, {
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
  });
}

async function waitFor(predicate, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise((r) => setTimeout(r, 25));
  }
  return false;
}

test("a routed call that arrives live is paired and counted once", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-livecorr-"));
  const log = new EventLog({ root });
  await log.init();
  let initialScanFinished = false;
  const listSessions = log.listSessions.bind(log);
  log.listSessions = async () => {
    const sessions = await listSessions();
    initialScanFinished = true;
    return sessions;
  };
  const store = new InMemoryReadModelStore();
  const messages = [];
  const server = { broadcast: (m) => messages.push(m) };

  const { stop } = startStreamingLoop(
    [{ rootPath: root, log }],
    store,
    new Projector(store),
    server,
    null,
    { correlationDelayMs: 100 },
  );
  t.after(async () => {
    await stop();
    await log.close();
    await fs.rm(root, { recursive: true, force: true });
  });

  // Sessions present when the loop starts are taken as already rebuilt (the
  // dashboard rebuilds first), so let its first pass finish before any
  // session exists. These then arrive as new, and are tailed from the start.
  assert.ok(await waitFor(() => initialScanFinished), "initial session scan did not finish");
  await log.append(started("hook", "claude-code-hook"));
  await log.append(started("proxy", "mcp-proxy"));
  assert.ok(await waitFor(async () => (await store.listSessions()).length === 2), "sessions were not tailed");

  // The routed call, as the hook and then the proxy recorded it.
  await log.append(event("hook", "claude-code-hook", HOOK_AT, 1, {
    event_type: "tool.invoked",
    tool_call_id: "toolu_hook_1",
    tool_name: "mcp__omnodex__filesystem__read_text_file",
    mcp_server: "omnodex",
    parameters: PARAMS,
  }));
  await log.append(event("proxy", "mcp-proxy", PROXY_AT, 1, {
    event_type: "tool.invoked",
    tool_call_id: "proxy-call-1",
    tool_name: "filesystem__read_text_file",
    mcp_server: "filesystem",
    parameters: PARAMS,
  }));

  const paired = await waitFor(async () => {
    const [hook] = await store.listToolCalls("hook");
    const [proxy] = await store.listToolCalls("proxy");
    return Boolean(hook?.correlation_id && hook.correlation_id === proxy?.correlation_id);
  });
  assert.ok(paired, "the hook and proxy rows were never paired");
  assert.ok(messages.some((m) => m.type === "read_model.changed"), "the page was not told to reload");

  const snapshot = collapseCorrelated(await readSnapshot(store));
  assert.equal(Object.values(snapshot.tool_calls).flat().length, 1);
  assert.equal(snapshot.sessions.reduce((n, s) => n + s.tool_call_count, 0), 1);
});
