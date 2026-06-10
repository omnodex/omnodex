// Unit tests for mapCodexPayload. Runs against the compiled JS in dist/.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mapCodexPayload } from "../dist/codex-payload.js";

let counter = 0;
function makeOptions() {
  counter = 0;
  return {
    newEventId: () => `evt-${++counter}`,
    nowIso: () => "2026-05-14T00:00:00.000Z",
  };
}

const BASE = { session_id: "sess-1", cwd: "/home/case/repo" };

// ── SessionStart ──────────────────────────────────────────────────────────────

test("SessionStart maps to session.started", () => {
  const events = mapCodexPayload(
    { ...BASE, hook_event_name: "SessionStart", source: "startup" },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "session.started");
  assert.equal(ev.interceptor, "codex-hook");
  assert.equal(ev.session_id, "sess-1");
  assert.equal(ev.project_path, "/home/case/repo");
  assert.equal(ev.user, "codex");
  assert.deepEqual(ev.mcp_servers, []);
  assert.equal(ev.schema_version, 1);
});

test("SessionStart with resume source still maps cleanly", () => {
  const events = mapCodexPayload(
    { ...BASE, hook_event_name: "SessionStart", source: "resume" },
    makeOptions(),
  );
  assert.equal(events[0].event_type, "session.started");
});

// ── PreToolUse ────────────────────────────────────────────────────────────────

test("PreToolUse maps to tool.invoked with builtin mcp_server", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "tu-001",
      tool_input: { command: "cat /etc/hosts" },
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.invoked");
  assert.equal(ev.interceptor, "codex-hook");
  assert.equal(ev.tool_call_id, "tu-001");
  assert.equal(ev.tool_name, "Bash");
  assert.equal(ev.mcp_server, "builtin");
  assert.deepEqual(ev.parameters, { command: "cat /etc/hosts" });
});

test("PreToolUse with mcp__ tool name extracts server name", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "PreToolUse",
      tool_name: "mcp__filesystem__read_file",
      tool_use_id: "tu-002",
      tool_input: { path: "/tmp/foo.txt" },
    },
    makeOptions(),
  );
  assert.equal(events[0].mcp_server, "filesystem");
});

// ── PostToolUse ───────────────────────────────────────────────────────────────

test("PostToolUse maps to tool.completed with status success", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_use_id: "tu-001",
      tool_input: { command: "echo hello" },
      tool_response: { output: "hello\n", exit_code: 0 },
      duration_ms: 42,
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.completed");
  assert.equal(ev.status, "success");
  assert.equal(ev.tool_call_id, "tu-001");
  assert.equal(ev.duration_ms, 42);
  assert.ok(ev.response_bytes > 0);
});

test("PostToolUse defaults duration_ms to 0 when absent", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_use_id: "tu-003",
      tool_input: { command: "ls" },
      tool_response: "file1\nfile2",
    },
    makeOptions(),
  );
  assert.equal(events[0].duration_ms, 0);
});

test("PostToolUse with null response gives response_bytes=0", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_use_id: "tu-004",
      tool_input: { command: "true" },
      tool_response: null,
    },
    makeOptions(),
  );
  assert.equal(events[0].response_bytes, 0);
});

// ── Stop ─────────────────────────────────────────────────────────────────────

test("Stop maps to session.ended with status completed", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "Stop",
      stop_hook_active: false,
      last_assistant_message: "Done.",
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "session.ended");
  assert.equal(ev.status, "completed");
  assert.equal(ev.interceptor, "codex-hook");
  assert.equal(ev.duration_ms, 0);
});

// ── UserPromptSubmit ──────────────────────────────────────────────────────────

test("UserPromptSubmit returns empty array (no TraceEvent type yet)", () => {
  const events = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "UserPromptSubmit",
      turn_id: "turn-1",
      prompt: "fix the bug",
    },
    makeOptions(),
  );
  assert.equal(events.length, 0);
});

// ── Common fields ─────────────────────────────────────────────────────────────

test("all mapped events carry occurred_at and recorded_at from nowIso", () => {
  const opts = makeOptions();
  const events = mapCodexPayload(
    { ...BASE, hook_event_name: "SessionStart" },
    opts,
  );
  assert.equal(events[0].occurred_at, "2026-05-14T00:00:00.000Z");
  assert.equal(events[0].recorded_at, "2026-05-14T00:00:00.000Z");
});

test("event_id is unique per emitted event", () => {
  const opts = makeOptions();
  const a = mapCodexPayload(
    { ...BASE, hook_event_name: "SessionStart" },
    opts,
  );
  const b = mapCodexPayload(
    {
      ...BASE,
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "tu-x",
      tool_input: {},
    },
    opts,
  );
  assert.notEqual(a[0].event_id, b[0].event_id);
});
