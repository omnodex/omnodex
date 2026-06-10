// Unit tests for event-emitter.ts -- TraceEvent generation, redaction,
// error handling. Pool and config are mocked; no real MCP subprocess needed.

import { test } from "node:test";
import assert from "node:assert/strict";

import { callToolWithEvents } from "../dist/event-emitter.js";
import { McpToolNotFoundError } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

// Re-export for convenience -- McpToolNotFoundError is also exported from
// upstream-client but the event-emitter re-throws it so we test it here too.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_CONFIG = ProxyConfigSchema.parse({
  version: 1,
  upstream_servers: [
    { name: "filesystem", transport: "stdio", command: "node" },
    { name: "github", transport: "stdio", command: "node", redact_parameters: true },
  ],
});

/** Builds a minimal mock UpstreamClientPool. */
function makePool({
  knownTools = ["filesystem/read_file", "filesystem/write_file"],
  serverMap = { "filesystem/read_file": "filesystem", "filesystem/write_file": "filesystem" },
  callResult = { content: [{ type: "text", text: "file contents" }], isError: false },
  callError = null,
} = {}) {
  return {
    getTools: () => knownTools.map((n) => ({ prefixedName: n })),
    getServerName: (name) => serverMap[name],
    callTool: async (_name, _args) => {
      if (callError) throw callError;
      return callResult;
    },
  };
}

function collectEvents() {
  const events = [];
  const emit = (ev) => events.push(ev);
  return { events, emit };
}

const BASE_OPTS = {
  prefixedName: "filesystem/read_file",
  args: { path: "/etc/hosts" },
  toolCallId: "tc-001",
  sessionId: "sess-test",
};

// ---------------------------------------------------------------------------
// tool.invoked
// ---------------------------------------------------------------------------

test("emits tool.invoked before the call", async () => {
  const { events, emit } = collectEvents();
  const pool = makePool();

  await callToolWithEvents(pool, BASE_CONFIG, emit, BASE_OPTS);

  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.ok(invoked, "tool.invoked not emitted");
  assert.equal(invoked.event_type, "tool.invoked");
  assert.equal(invoked.interceptor, "mcp-proxy");
  assert.equal(invoked.tool_name, "filesystem/read_file");
  assert.equal(invoked.mcp_server, "filesystem");
  assert.equal(invoked.tool_call_id, "tc-001");
  assert.equal(invoked.session_id, "sess-test");
  assert.equal(invoked.schema_version, 1);
  assert.ok(invoked.event_id, "event_id should be set");
  assert.ok(invoked.occurred_at, "occurred_at should be set");
});

test("tool.invoked includes parameters when redact_parameters is false", async () => {
  const { events, emit } = collectEvents();
  await callToolWithEvents(makePool(), BASE_CONFIG, emit, {
    ...BASE_OPTS,
    args: { path: "/etc/hosts", encoding: "utf8" },
  });

  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.deepEqual(invoked.parameters, { path: "/etc/hosts", encoding: "utf8" });
});

// ---------------------------------------------------------------------------
// redact_parameters
// ---------------------------------------------------------------------------

test("redacts parameter VALUES but preserves KEYS when redact_parameters is true (global)", async () => {
  const { events, emit } = collectEvents();
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    redact_parameters: true,
    upstream_servers: [
      { name: "filesystem", transport: "stdio", command: "node" },
    ],
  });
  const pool = makePool({ serverMap: { "filesystem/read_file": "filesystem" } });

  await callToolWithEvents(pool, cfg, emit, {
    ...BASE_OPTS,
    args: { path: "/secrets/key.pem", flag: true },
  });

  const invoked = events.find((e) => e.event_type === "tool.invoked");
  // Keys present, values replaced
  assert.deepEqual(Object.keys(invoked.parameters), ["path", "flag"]);
  assert.equal(invoked.parameters.path, "[REDACTED]");
  assert.equal(invoked.parameters.flag, "[REDACTED]");
});

test("per-server redact_parameters override beats global false", async () => {
  const { events, emit } = collectEvents();
  // github server has redact_parameters: true per BASE_CONFIG
  const pool = makePool({
    knownTools: ["github/create_issue"],
    serverMap: { "github/create_issue": "github" },
  });

  await callToolWithEvents(pool, BASE_CONFIG, emit, {
    ...BASE_OPTS,
    prefixedName: "github/create_issue",
    args: { title: "secret bug", body: "private details" },
  });

  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.equal(invoked.parameters.title, "[REDACTED]");
  assert.equal(invoked.parameters.body, "[REDACTED]");
});

// ---------------------------------------------------------------------------
// tool.completed
// ---------------------------------------------------------------------------

test("emits tool.completed after a successful call", async () => {
  const { events, emit } = collectEvents();
  await callToolWithEvents(makePool(), BASE_CONFIG, emit, BASE_OPTS);

  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.ok(completed, "tool.completed not emitted");
  assert.equal(completed.event_type, "tool.completed");
  assert.equal(completed.interceptor, "mcp-proxy");
  assert.equal(completed.tool_call_id, "tc-001");
  assert.equal(completed.status, "success");
  assert.ok(typeof completed.duration_ms === "number" && completed.duration_ms >= 0);
  assert.ok(typeof completed.response_bytes === "number" && completed.response_bytes > 0);
  assert.equal(completed.error_message, undefined);
});

test("tool.completed has status=error when upstream returns isError:true", async () => {
  const { events, emit } = collectEvents();
  const pool = makePool({
    callResult: {
      content: [{ type: "text", text: "permission denied" }],
      isError: true,
    },
  });

  await callToolWithEvents(pool, BASE_CONFIG, emit, BASE_OPTS);

  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.status, "error");
  assert.equal(completed.error_message, "permission denied");
});

test("tool.completed has status=error when upstream throws", async () => {
  const { events, emit } = collectEvents();
  const pool = makePool({ callError: new Error("upstream crashed") });

  await callToolWithEvents(pool, BASE_CONFIG, emit, BASE_OPTS);

  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.status, "error");
  assert.equal(completed.error_message, "upstream crashed");
});

test("tool_call_id matches between tool.invoked and tool.completed", async () => {
  const { events, emit } = collectEvents();
  await callToolWithEvents(makePool(), BASE_CONFIG, emit, {
    ...BASE_OPTS,
    toolCallId: "tc-xyz-123",
  });

  const invoked = events.find((e) => e.event_type === "tool.invoked");
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.equal(invoked.tool_call_id, "tc-xyz-123");
  assert.equal(completed.tool_call_id, "tc-xyz-123");
});

test("response_bytes is non-zero for non-empty content", async () => {
  const { events, emit } = collectEvents();
  const pool = makePool({
    callResult: {
      content: [{ type: "text", text: "a".repeat(1000) }],
      isError: false,
    },
  });

  await callToolWithEvents(pool, BASE_CONFIG, emit, BASE_OPTS);

  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.ok(completed.response_bytes > 100);
});

// ---------------------------------------------------------------------------
// McpToolNotFoundError (thrown before any events)
// ---------------------------------------------------------------------------

test("throws McpToolNotFoundError for unknown tool (no events emitted)", async () => {
  const { events, emit } = collectEvents();
  const pool = makePool({ serverMap: {} }); // getServerName returns undefined

  await assert.rejects(
    () => callToolWithEvents(pool, BASE_CONFIG, emit, {
      ...BASE_OPTS,
      prefixedName: "unknown/tool",
    }),
    (err) => {
      assert.ok(err instanceof McpToolNotFoundError);
      assert.match(err.message, /not found/i);
      return true;
    }
  );

  // No events should have been emitted before the throw
  assert.equal(events.length, 0);
});

// ---------------------------------------------------------------------------
// Exactly 2 events per successful call
// ---------------------------------------------------------------------------

test("exactly 2 events emitted per successful call", async () => {
  const { events, emit } = collectEvents();
  await callToolWithEvents(makePool(), BASE_CONFIG, emit, BASE_OPTS);
  // Allow for async emit settling -- use setImmediate
  await new Promise((r) => setImmediate(r));
  assert.equal(events.length, 2);
  const types = events.map((e) => e.event_type).sort();
  assert.deepEqual(types, ["tool.completed", "tool.invoked"]);
});
