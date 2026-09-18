import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  InMemoryReadModelStore,
  Projector,
  SqliteReadModelStore,
  correlateToolCalls,
  runCorrelation,
  upstreamSuffix,
} from "../dist/index.js";

/**
 * A routed MCP call is observed twice: by the platform hook before it leaves
 * the agent, and by the proxy as it forwards upstream. The two events share
 * no identifier, no session and no clock.
 *
 * The shapes below are taken from a real captured pair, recorded in
 * hooks-provider/test/fixtures/tool-name-mapping.json.
 */

const HOOK_SESSION = "4c379251-hook";
const PROXY_SESSION = "6ed63f79-proxy";
const HOOK_AT = "2026-09-18T14:57:41.951Z";
const PROXY_AT = "2026-09-18T14:57:43.360Z"; // 1.409s later, as measured
const PARAMS = { path: "/home/case/repo/PROJECT_TRACKER.md", head: 3 };

async function mkTmp() {
  return await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-corr-"));
}

function sessionEvent(sessionId, interceptor, at) {
  return {
    schema_version: 1,
    event_id: `start-${sessionId}`,
    session_id: sessionId,
    occurred_at: at,
    recorded_at: at,
    interceptor,
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
  };
}

function invoked({ eventId, sessionId, interceptor, toolCallId, toolName, mcpServer, at, parameters = PARAMS }) {
  return {
    schema_version: 1,
    event_id: eventId,
    session_id: sessionId,
    occurred_at: at,
    recorded_at: at,
    interceptor,
    event_type: "tool.invoked",
    tool_call_id: toolCallId,
    tool_name: toolName,
    mcp_server: mcpServer,
    parameters,
  };
}

/** The canonical routed call: one hook event and one proxy event. */
function routedCallEvents(overrides = {}) {
  return [
    sessionEvent(HOOK_SESSION, "claude-code-hook", HOOK_AT),
    sessionEvent(PROXY_SESSION, "mcp-proxy", HOOK_AT),
    invoked({
      eventId: "e-hook",
      sessionId: HOOK_SESSION,
      interceptor: "claude-code-hook",
      toolCallId: "toolu_01BWzDA9uN94mAP3SrKokFyb",
      toolName: "mcp__omnodex__filesystem__read_text_file",
      mcpServer: "omnodex",
      at: HOOK_AT,
      ...overrides.hook,
    }),
    invoked({
      eventId: "e-proxy",
      sessionId: PROXY_SESSION,
      interceptor: "mcp-proxy",
      toolCallId: "64af70a6-proxy",
      toolName: "filesystem__read_text_file",
      mcpServer: "filesystem",
      at: PROXY_AT,
      ...overrides.proxy,
    }),
  ];
}

async function project(events, store) {
  const projector = new Projector(store);
  for (const e of events) await projector.apply(e);
  return store;
}

// ---------------------------------------------------------------------------
// upstreamSuffix
// ---------------------------------------------------------------------------

test("upstreamSuffix recovers the name the proxy offered", () => {
  assert.equal(
    upstreamSuffix("mcp__omnodex__filesystem__read_text_file"),
    "filesystem__read_text_file",
  );
  assert.equal(
    upstreamSuffix("mcp__plugin_omnodex-cowork_omnodex__filesystem__read_text_file"),
    "filesystem__read_text_file",
    "a server name with underscores must not be split early",
  );
});

test("upstreamSuffix ignores calls the proxy could not have served", () => {
  assert.equal(upstreamSuffix("Bash"), null);
  assert.equal(upstreamSuffix("Read"), null);
  assert.equal(upstreamSuffix("mcp__plane__workitem"), "workitem");
});

// ---------------------------------------------------------------------------
// correlateToolCalls
// ---------------------------------------------------------------------------

test("pairs the hook and proxy views of one routed call", async () => {
  const store = await project(routedCallEvents(), new InMemoryReadModelStore());
  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });

  assert.equal(result.length, 1);
  assert.equal(result[0].hook_tool_call_id, "toolu_01BWzDA9uN94mAP3SrKokFyb");
  assert.equal(result[0].proxy_tool_call_id, "64af70a6-proxy");
  assert.equal(result[0].upstream_mcp_server, "filesystem");
});

test("does not pair a call the proxy never saw", async () => {
  const store = await project(
    [
      sessionEvent(HOOK_SESSION, "claude-code-hook", HOOK_AT),
      invoked({
        eventId: "e-hook",
        sessionId: HOOK_SESSION,
        interceptor: "claude-code-hook",
        toolCallId: "toolu_alone",
        toolName: "mcp__plane__workitem",
        mcpServer: "plane",
        at: HOOK_AT,
      }),
    ],
    new InMemoryReadModelStore(),
  );

  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });
  assert.equal(result.length, 0);
});

test("does not pair calls whose arguments differ", async () => {
  const store = await project(
    routedCallEvents({ proxy: { parameters: { path: "/home/case/repo/other.md", head: 3 } } }),
    new InMemoryReadModelStore(),
  );

  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });
  assert.equal(result.length, 0, "same tool, different call");
});

test("does not pair across a long gap", async () => {
  const store = await project(
    routedCallEvents({ proxy: { at: "2026-09-18T15:57:43.360Z" } }), // an hour later
    new InMemoryReadModelStore(),
  );

  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });
  assert.equal(result.length, 0);
});

test("does not pair a proxy call that started before the hook saw it", async () => {
  // PreToolUse fires before the call is forwarded, so this ordering means
  // the proxy row belongs to some other call.
  const store = await project(
    routedCallEvents({ proxy: { at: "2026-09-18T14:57:40.000Z" } }),
    new InMemoryReadModelStore(),
  );

  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });
  assert.equal(result.length, 0);
});

test("pairs redacted proxy parameters on argument shape alone", async () => {
  // An upstream with redact_parameters replaces the values before the proxy
  // records them, while the hook still holds the originals. The key set is
  // what survives.
  const store = await project(
    routedCallEvents({
      proxy: { parameters: { path: "[REDACTED]", head: "[REDACTED]" } },
    }),
    new InMemoryReadModelStore(),
  );

  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });
  assert.equal(result.length, 1);
  assert.equal(result[0].upstream_mcp_server, "filesystem");
});

test("redaction does not make two different calls interchangeable", async () => {
  // Different key sets must still fail, or redaction would pair anything.
  const store = await project(
    routedCallEvents({ proxy: { parameters: { path: "[REDACTED]" } } }),
    new InMemoryReadModelStore(),
  );

  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });
  assert.equal(result.length, 0);
});

test("two identical calls in quick succession pair up in order", async () => {
  const events = [
    sessionEvent(HOOK_SESSION, "claude-code-hook", HOOK_AT),
    sessionEvent(PROXY_SESSION, "mcp-proxy", HOOK_AT),
    invoked({
      eventId: "h1", sessionId: HOOK_SESSION, interceptor: "claude-code-hook",
      toolCallId: "hook-1", toolName: "mcp__omnodex__filesystem__read_text_file",
      mcpServer: "omnodex", at: "2026-09-18T14:57:41.000Z",
    }),
    invoked({
      eventId: "h2", sessionId: HOOK_SESSION, interceptor: "claude-code-hook",
      toolCallId: "hook-2", toolName: "mcp__omnodex__filesystem__read_text_file",
      mcpServer: "omnodex", at: "2026-09-18T14:57:42.000Z",
    }),
    invoked({
      eventId: "p1", sessionId: PROXY_SESSION, interceptor: "mcp-proxy",
      toolCallId: "proxy-1", toolName: "filesystem__read_text_file",
      mcpServer: "filesystem", at: "2026-09-18T14:57:41.500Z",
    }),
    invoked({
      eventId: "p2", sessionId: PROXY_SESSION, interceptor: "mcp-proxy",
      toolCallId: "proxy-2", toolName: "filesystem__read_text_file",
      mcpServer: "filesystem", at: "2026-09-18T14:57:42.500Z",
    }),
  ];

  const store = await project(events, new InMemoryReadModelStore());
  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });

  assert.equal(result.length, 2);
  const byHook = Object.fromEntries(
    result.map((c) => [c.hook_tool_call_id, c.proxy_tool_call_id]),
  );
  assert.deepEqual(byHook, { "hook-1": "proxy-1", "hook-2": "proxy-2" });
});

test("a proxy row is claimed by at most one hook row", async () => {
  const events = [
    sessionEvent(HOOK_SESSION, "claude-code-hook", HOOK_AT),
    sessionEvent(PROXY_SESSION, "mcp-proxy", HOOK_AT),
    invoked({
      eventId: "h1", sessionId: HOOK_SESSION, interceptor: "claude-code-hook",
      toolCallId: "hook-1", toolName: "mcp__omnodex__filesystem__read_text_file",
      mcpServer: "omnodex", at: "2026-09-18T14:57:41.000Z",
    }),
    invoked({
      eventId: "h2", sessionId: HOOK_SESSION, interceptor: "claude-code-hook",
      toolCallId: "hook-2", toolName: "mcp__omnodex__filesystem__read_text_file",
      mcpServer: "omnodex", at: "2026-09-18T14:57:41.100Z",
    }),
    invoked({
      eventId: "p1", sessionId: PROXY_SESSION, interceptor: "mcp-proxy",
      toolCallId: "proxy-only", toolName: "filesystem__read_text_file",
      mcpServer: "filesystem", at: "2026-09-18T14:57:41.500Z",
    }),
  ];

  const store = await project(events, new InMemoryReadModelStore());
  const result = correlateToolCalls({
    sessions: await store.listSessions(),
    toolCalls: await store.listAllToolCalls(),
  });

  assert.equal(result.length, 1);
  assert.equal(result[0].hook_tool_call_id, "hook-1", "earliest hook wins");
});

// ---------------------------------------------------------------------------
// runCorrelation, against both stores
// ---------------------------------------------------------------------------

for (const kind of ["in-memory", "sqlite"]) {
  test(`runCorrelation records the pair and the upstream server (${kind})`, async () => {
    let store;
    if (kind === "sqlite") {
      const root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }

    await project(routedCallEvents(), store);
    const summary = await runCorrelation(store);
    assert.equal(summary.correlations.length, 1);

    const hookRows = await store.listToolCalls(HOOK_SESSION);
    const proxyRows = await store.listToolCalls(PROXY_SESSION);

    assert.equal(hookRows.length, 1);
    assert.equal(proxyRows.length, 1);

    // One logical call, two rows, one id joining them.
    assert.ok(hookRows[0].correlation_id);
    assert.equal(hookRows[0].correlation_id, proxyRows[0].correlation_id);

    // The hook could only see the proxy; the proxy knows where the call
    // actually went, and that is the attribution worth keeping.
    assert.equal(hookRows[0].mcp_server, "filesystem");

    // Both rows survive. Nothing is dropped from the derived model, and
    // nothing was ever dropped from the log.
    assert.equal(hookRows[0].interceptor, "claude-code-hook");
    assert.equal(proxyRows[0].interceptor, "mcp-proxy");

    await store.close();
  });

  test(`runCorrelation is idempotent (${kind})`, async () => {
    let store;
    if (kind === "sqlite") {
      const root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }

    await project(routedCallEvents(), store);
    await runCorrelation(store);
    const first = await store.listToolCalls(HOOK_SESSION);

    const second = await runCorrelation(store);
    assert.equal(second.rowsUpdated, 0, "a second pass has nothing to change");
    assert.deepEqual(await store.listToolCalls(HOOK_SESSION), first);

    await store.close();
  });

  test(`an uncorrelated call keeps a null correlation_id (${kind})`, async () => {
    let store;
    if (kind === "sqlite") {
      const root = await mkTmp();
      store = new SqliteReadModelStore({ dbPath: path.join(root, "traces.db") });
      await store.init();
    } else {
      store = new InMemoryReadModelStore();
    }

    await project(
      [
        sessionEvent(HOOK_SESSION, "claude-code-hook", HOOK_AT),
        invoked({
          eventId: "e-bash", sessionId: HOOK_SESSION, interceptor: "claude-code-hook",
          toolCallId: "toolu_bash", toolName: "Bash", mcpServer: "builtin",
          at: HOOK_AT, parameters: { command: "ls" },
        }),
      ],
      store,
    );
    await runCorrelation(store);

    const rows = await store.listToolCalls(HOOK_SESSION);
    assert.equal(rows[0].correlation_id, null);
    assert.equal(rows[0].mcp_server, "builtin");

    await store.close();
  });
}
