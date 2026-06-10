// Unit tests for mapAntigravityPayload. Runs against the compiled JS in dist/.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mapAntigravityPayload } from "../dist/antigravity-payload.js";

let counter = 0;
function makeOptions() {
  counter = 0;
  return {
    newEventId: () => `evt-${++counter}`,
    nowIso: () => "2026-05-31T00:00:00.000Z",
  };
}

const COMMON = {
  conversationId: "ec33ebf9-0cba-4100-8142-c61503f6c587",
  workspacePaths: ["/home/case/repo"],
  transcriptPath: "/home/case/repo/.gemini/jetski/transcript.jsonl",
  artifactDirectoryPath: "/home/case/repo/.gemini/jetski/artifacts",
};

// -- PreToolUse ---------------------------------------------------------------

test("PreToolUse maps to tool.invoked with builtin mcp_server", () => {
  const events = mapAntigravityPayload(
    "PreToolUse",
    {
      ...COMMON,
      toolCall: { name: "run_command", args: { CommandLine: "cat /etc/hosts" } },
      stepIdx: 3,
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.invoked");
  assert.equal(ev.interceptor, "antigravity-hook");
  assert.equal(ev.platform, "antigravity");
  assert.equal(ev.tool_call_id, "step-3");
  assert.equal(ev.tool_name, "run_command");
  assert.equal(ev.mcp_server, "builtin");
  assert.deepEqual(ev.parameters, { CommandLine: "cat /etc/hosts" });
  assert.equal(ev.session_id, "ec33ebf9-0cba-4100-8142-c61503f6c587");
});

test("PreToolUse with mcp__ tool name extracts server name", () => {
  const events = mapAntigravityPayload(
    "PreToolUse",
    {
      ...COMMON,
      toolCall: { name: "mcp__filesystem__read_file", args: { path: "/tmp/foo.txt" } },
      stepIdx: 5,
    },
    makeOptions(),
  );
  assert.equal(events[0].mcp_server, "filesystem");
});

test("PreToolUse uses workspacePaths[0] as cwd", () => {
  const events = mapAntigravityPayload(
    "PreToolUse",
    {
      ...COMMON,
      toolCall: { name: "view_file", args: { AbsolutePath: "/tmp/f.txt" } },
      stepIdx: 0,
    },
    makeOptions(),
  );
  assert.equal(events[0].cwd, "/home/case/repo");
});

// -- PostToolUse --------------------------------------------------------------

test("PostToolUse maps to tool.completed with correlated data", () => {
  const events = mapAntigravityPayload(
    "PostToolUse",
    {
      ...COMMON,
      stepIdx: 3,
    },
    makeOptions(),
    {
      toolName: "run_command",
      toolCallId: "step-3",
      durationMs: 42,
    },
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.completed");
  assert.equal(ev.status, "success");
  assert.equal(ev.tool_call_id, "step-3");
  assert.equal(ev.duration_ms, 42);
});

test("PostToolUse with error sets status to error", () => {
  const events = mapAntigravityPayload(
    "PostToolUse",
    {
      ...COMMON,
      stepIdx: 5,
      error: "exit status 1",
    },
    makeOptions(),
    {
      toolName: "run_command",
      toolCallId: "step-5",
      durationMs: 100,
    },
  );
  assert.equal(events[0].status, "error");
});

test("PostToolUse without correlation falls back to stepIdx", () => {
  const events = mapAntigravityPayload(
    "PostToolUse",
    {
      ...COMMON,
      stepIdx: 7,
    },
    makeOptions(),
    // No correlation data
    {
      toolName: null,
      toolCallId: null,
      durationMs: 0,
    },
  );
  assert.equal(events[0].tool_call_id, "step-7");
  assert.equal(events[0].duration_ms, 0);
});

test("PostToolUse defaults duration_ms to 0 when no correlation", () => {
  const events = mapAntigravityPayload(
    "PostToolUse",
    { ...COMMON, stepIdx: 9 },
    makeOptions(),
  );
  assert.equal(events[0].duration_ms, 0);
});

// -- Stop ---------------------------------------------------------------------

test("Stop maps to session.ended with status completed", () => {
  const events = mapAntigravityPayload(
    "Stop",
    {
      ...COMMON,
      executionNum: 1,
      terminationReason: "model_stop",
      fullyIdle: true,
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "session.ended");
  assert.equal(ev.status, "completed");
  assert.equal(ev.interceptor, "antigravity-hook");
  assert.equal(ev.platform, "antigravity");
  assert.equal(ev.duration_ms, 0);
});

test("Stop with error sets status to error", () => {
  const events = mapAntigravityPayload(
    "Stop",
    {
      ...COMMON,
      executionNum: 1,
      terminationReason: "error",
      error: "Something went wrong",
      fullyIdle: true,
    },
    makeOptions(),
  );
  assert.equal(events[0].status, "errored");
});

// -- Common fields ------------------------------------------------------------

test("all mapped events carry occurred_at and recorded_at from nowIso", () => {
  const opts = makeOptions();
  const events = mapAntigravityPayload(
    "PreToolUse",
    {
      ...COMMON,
      toolCall: { name: "view_file", args: {} },
      stepIdx: 0,
    },
    opts,
  );
  assert.equal(events[0].occurred_at, "2026-05-31T00:00:00.000Z");
  assert.equal(events[0].recorded_at, "2026-05-31T00:00:00.000Z");
});

test("event_id is unique per emitted event", () => {
  const opts = makeOptions();
  const a = mapAntigravityPayload(
    "PreToolUse",
    {
      ...COMMON,
      toolCall: { name: "view_file", args: {} },
      stepIdx: 0,
    },
    opts,
  );
  const b = mapAntigravityPayload(
    "PreToolUse",
    {
      ...COMMON,
      toolCall: { name: "run_command", args: {} },
      stepIdx: 1,
    },
    opts,
  );
  assert.notEqual(a[0].event_id, b[0].event_id);
});

test("session_id comes from conversationId", () => {
  const events = mapAntigravityPayload(
    "Stop",
    {
      ...COMMON,
      executionNum: 1,
      terminationReason: "model_stop",
      fullyIdle: true,
    },
    makeOptions(),
  );
  assert.equal(events[0].session_id, COMMON.conversationId);
});
