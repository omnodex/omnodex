// Unit tests for mapClaudeCodePayload. Runs against the compiled JS in
// dist/ so we don't have to stand up ts-node. Run with `node --test`.

import { test } from "node:test";
import assert from "node:assert/strict";

import { mapClaudeCodePayload } from "../dist/claude-code-payload.js";

// Deterministic clock and id generator so the expected shape is stable.
let counter = 0;
function makeOptions() {
  counter = 0;
  return {
    newEventId: () => `evt-${++counter}`,
    nowIso: () => "2026-04-11T00:00:00.000Z",
  };
}

const BASE = {
  session_id: "sess-1",
  cwd: "/home/case/repo",
  permission_mode: "default",
};

test("SessionStart maps to a single session.started event", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "SessionStart",
      user: "case",
      mcp_servers: ["filesystem", "postgres"],
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "session.started");
  assert.equal(ev.interceptor, "claude-code-hook");
  assert.equal(ev.session_id, "sess-1");
  assert.equal(ev.user, "case");
  assert.equal(ev.project_path, "/home/case/repo");
  assert.deepEqual(ev.mcp_servers, ["filesystem", "postgres"]);
  assert.equal(ev.event_id, "evt-1");
  assert.equal(ev.schema_version, 1);
});

test("SessionStart falls back to agent_id when user is absent", () => {
  const events = mapClaudeCodePayload(
    { ...BASE, hook_event_name: "SessionStart", agent_id: "agent-42" },
    makeOptions(),
  );
  assert.equal(events[0].user, "agent-42");
  assert.deepEqual(events[0].mcp_servers, []);
});

test("SessionEnd maps to a session.ended event with status", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "SessionEnd",
      reason: "errored",
      duration_ms: 12345,
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, "session.ended");
  assert.equal(events[0].status, "errored");
  assert.equal(events[0].duration_ms, 12345);
});

test("SessionEnd defaults status=completed when reason missing", () => {
  const events = mapClaudeCodePayload(
    { ...BASE, hook_event_name: "SessionEnd" },
    makeOptions(),
  );
  assert.equal(events[0].status, "completed");
  assert.equal(events[0].duration_ms, 0);
});

test("PreToolUse maps a builtin tool to tool.invoked with mcp_server=builtin", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_use_id: "call-1",
      tool_input: { file_path: "/etc/hosts" },
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.invoked");
  assert.equal(ev.tool_name, "Read");
  assert.equal(ev.mcp_server, "builtin");
  assert.equal(ev.tool_call_id, "call-1");
  assert.deepEqual(ev.parameters, { file_path: "/etc/hosts" });
});

test("PreToolUse parses MCP tool name into mcp_server", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PreToolUse",
      tool_name: "mcp__postgres__query",
      tool_use_id: "call-2",
      tool_input: { sql: "select 1" },
    },
    makeOptions(),
  );
  assert.equal(events[0].mcp_server, "postgres");
  assert.equal(events[0].tool_name, "mcp__postgres__query");
});

test("PostToolUse on Read emits tool.completed and file.read", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Read",
      tool_use_id: "call-3",
      tool_input: { file_path: "/etc/hosts" },
      tool_response: "127.0.0.1 localhost\n",
      duration_ms: 17,
    },
    makeOptions(),
  );
  assert.equal(events.length, 2);
  assert.equal(events[0].event_type, "tool.completed");
  assert.equal(events[0].status, "success");
  assert.equal(events[0].duration_ms, 17);
  assert.equal(events[0].tool_call_id, "call-3");
  assert.equal(events[1].event_type, "file.read");
  assert.equal(events[1].path, "/etc/hosts");
  assert.ok(events[1].bytes > 0, "expected non-zero bytes");
});

test("PostToolUse on Write emits tool.completed and file.written with input size", () => {
  const content = "hello world";
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Write",
      tool_use_id: "call-4",
      tool_input: { file_path: "/tmp/out.txt", content },
      tool_response: { ok: true },
      duration_ms: 4,
    },
    makeOptions(),
  );
  assert.equal(events.length, 2);
  assert.equal(events[1].event_type, "file.written");
  assert.equal(events[1].path, "/tmp/out.txt");
  assert.equal(events[1].bytes, Buffer.byteLength(content, "utf8"));
});

test("PostToolUse on Grep emits tool.completed and file.read using glob as path", () => {
  // Grep uses "glob" as the file selector. "path" is a directory root and
  // must NOT be used as the file.read path.
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Grep",
      tool_use_id: "call-grep",
      tool_input: {
        pattern: "never",
        glob: "**/*.md",
        path: "/home/case/source/omnodex/scratch",  // directory root — must be ignored
        output_mode: "count",
      },
      tool_response: { "communication-style.md": 2, "preferences.md": 1 },
    },
    makeOptions(),
  );
  assert.equal(events.length, 2);
  assert.equal(events[0].event_type, "tool.completed");
  assert.equal(events[1].event_type, "file.read");
  assert.equal(events[1].path, "**/*.md",
    "file.read path should be the glob pattern, not the directory root");
  assert.ok(events[1].bytes > 0, "bytes estimated from response");
});

test("PostToolUse on Grep without glob produces only tool.completed", () => {
  // If Claude Code omits the glob field, no file.read event is produced.
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Grep",
      tool_use_id: "call-grep-nopath",
      tool_input: { pattern: "TODO" },
      tool_response: [],
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, "tool.completed");
});

test("PostToolUse on Glob emits tool.completed and file.read using pattern as path", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Glob",
      tool_use_id: "call-glob",
      tool_input: { pattern: "**/*.ts" },
      tool_response: ["src/index.ts", "src/util.ts"],
    },
    makeOptions(),
  );
  assert.equal(events.length, 2);
  assert.equal(events[1].event_type, "file.read");
  assert.equal(events[1].path, "**/*.ts");
  assert.ok(events[1].bytes > 0);
});

test("PostToolUse on a non-filesystem tool emits only tool.completed", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Bash",
      tool_use_id: "call-5",
      tool_input: { command: "ls" },
      tool_response: "a.txt\nb.txt\n",
      duration_ms: 3,
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, "tool.completed");
});

test("PostToolUseFailure emits tool.completed with status=error and error_message", () => {
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUseFailure",
      tool_name: "Bash",
      tool_use_id: "call-6",
      tool_input: { command: "exit 1" },
      error: "command failed with exit code 1",
      duration_ms: 8,
    },
    makeOptions(),
  );
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.completed");
  assert.equal(ev.status, "error");
  assert.equal(ev.error_message, "command failed with exit code 1");
  assert.equal(ev.duration_ms, 8);
  assert.equal(ev.response_bytes, 0);
});

test("PostToolUse on Edit uses new_string for file.written byte count, not JSON patch size", () => {
  const newString = "const x = 42;\nconst y = x + 1;\n";
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Edit",
      tool_use_id: "call-edit-1",
      tool_input: {
        file_path: "/src/util.ts",
        old_string: "const x = 1;",
        new_string: newString,
      },
      // tool_response is a patch-style object -- its JSON size must NOT be used
      tool_response: { ok: true, replacements: 1 },
    },
    makeOptions(),
  );
  assert.equal(events.length, 2);
  assert.equal(events[1].event_type, "file.written");
  assert.equal(events[1].path, "/src/util.ts");
  assert.equal(
    events[1].bytes,
    Buffer.byteLength(newString, "utf8"),
    "bytes should reflect new_string length, not JSON response size",
  );
});

test("PostToolUse on Edit with no new_string falls back to response size", () => {
  // Edge case: if new_string is missing, fall back to estimating response bytes.
  const events = mapClaudeCodePayload(
    {
      ...BASE,
      hook_event_name: "PostToolUse",
      tool_name: "Edit",
      tool_use_id: "call-edit-2",
      tool_input: { file_path: "/src/util.ts" }, // no new_string
      tool_response: "patched",
    },
    makeOptions(),
  );
  assert.equal(events.length, 2);
  assert.equal(events[1].event_type, "file.written");
  // response is "patched" => JSON.stringify => '"patched"' => 8 bytes
  assert.ok(events[1].bytes > 0, "fallback should produce non-zero bytes from response");
});
