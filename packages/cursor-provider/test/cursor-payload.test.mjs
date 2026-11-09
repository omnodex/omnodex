// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { claudeTool, hasPermissionHook, mapCursorPayload, normalizeCursorPayload, sessionEndStatus } from "../dist/index.js";

const common = { conversation_id: "conv-1", generation_id: "gen-1", model: "claude-test", workspace_roots: ["/home/case/repo", "/home/case/other"], user_email: "case@example.com", transcript_path: "/home/case/t.jsonl" };
let n = 0;
const map = (raw, opts = {}) => mapCursorPayload(normalizeCursorPayload({ ...common, ...raw }), { newEventId: () => `e${++n}`, nowIso: () => "2026-11-09T12:00:00.000Z", ...opts });

test("a payload without a conversation or a known event is not ours", () => {
  assert.equal(normalizeCursorPayload(null), null);
  assert.equal(normalizeCursorPayload([]), null);
  assert.equal(normalizeCursorPayload({ hook_event_name: "preToolUse" }), null);
  assert.equal(normalizeCursorPayload({ conversation_id: "c", hook_event_name: "afterAgentThought" }), null);
  assert.equal(normalizeCursorPayload({ conversation_id: "c", hook_event_name: "stop" }), null);
});

test("the normalized payload has no field for the user's email, and no event carries it", () => {
  const p = normalizeCursorPayload({ ...common, hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls" }, tool_use_id: "t1" });
  assert.ok(!JSON.stringify(p).includes("case@example.com"));
  for (const raw of [
    { hook_event_name: "sessionStart" },
    { hook_event_name: "beforeSubmitPrompt", prompt: "hi" },
    { hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls" }, tool_use_id: "t1" },
    { hook_event_name: "postToolUse", tool_name: "Shell", tool_input: { command: "ls" }, tool_output: "x", tool_use_id: "t1", duration: 12 },
    { hook_event_name: "sessionEnd", reason: "completed" },
  ]) {
    const events = map(raw);
    assert.ok(events.length > 0, raw.hook_event_name);
    assert.ok(!JSON.stringify(events).includes("case@example.com"), raw.hook_event_name);
  }
});

test("the session is the conversation and the project is the first workspace root", () => {
  const p = normalizeCursorPayload({ ...common, hook_event_name: "sessionStart" });
  assert.equal(p.sessionId, "conv-1");
  assert.equal(p.cwd, "/home/case/repo");
  const [started] = map({ hook_event_name: "sessionStart" });
  assert.equal(started.event_type, "session.started");
  assert.equal(started.session_id, "conv-1");
  assert.equal(started.interceptor, "cursor-hook");
  assert.equal(started.platform, "cursor");
});

test("a shell call is recorded as Bash with Cursor's own call id, and its result pairs with it", () => {
  const [pre] = map({ hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls -la" }, tool_use_id: "tool-9" });
  assert.equal(pre.event_type, "tool.invoked");
  assert.equal(pre.tool_call_id, "tool-9");
  assert.equal(pre.tool_name, "Bash");
  const done = map({ hook_event_name: "postToolUse", tool_name: "Shell", tool_input: { command: "ls -la" }, tool_output: "total 0", tool_use_id: "tool-9", duration: 40 });
  const completed = done.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.tool_call_id, "tool-9");
  assert.equal(completed.status, "success");
});

test("a failed call is recorded as an error", () => {
  const events = map({ hook_event_name: "postToolUseFailure", tool_name: "Shell", tool_input: { command: "false" }, error_message: "exit 1", tool_use_id: "t2" });
  assert.equal(events.find((e) => e.event_type === "tool.completed").status, "error");
});

test("an MCP tool is named the way the proxy and the rules name it", () => {
  assert.deepEqual(claudeTool("MCP:search", { q: "x" }, "docs"), { name: "mcp__docs__search", input: { q: "x" } });
  assert.equal(claudeTool("MCP:search", {}).name, "mcp__cursor__search");
  assert.equal(claudeTool("StrReplace", { path: "/a" }).name, "Edit");
  assert.deepEqual(claudeTool("Write", { path: "/a", contents: "hi" }).input, { path: "/a", file_path: "/a", contents: "hi", content: "hi" });
});

test("a file read through the read tool is a file event", () => {
  const events = map({ hook_event_name: "preToolUse", tool_name: "Read", tool_input: { file_path: "/home/case/repo/a.txt" }, tool_use_id: "t3" });
  assert.ok(events.some((e) => e.event_type === "tool.invoked"));
});

test("the permission hooks describe the same call as preToolUse would, with no id of their own", () => {
  const shell = map({ hook_event_name: "beforeShellExecution", command: "cat /etc/shadow", cwd: "/home/case/repo" }, { callId: "made" });
  assert.equal(shell[0].tool_name, "Bash");
  assert.equal(shell[0].tool_call_id, "made");
  const read = map({ hook_event_name: "beforeReadFile", file_path: "/etc/shadow" }, { callId: "made" });
  assert.equal(read[0].tool_name, "Read");
  const mcp = map({ hook_event_name: "beforeMCPExecution", server: "docs", tool_name: "search", tool_input: JSON.stringify({ q: "x" }) }, { callId: "made" });
  assert.equal(mcp[0].tool_name, "mcp__docs__search");
  assert.deepEqual(map({ hook_event_name: "beforeShellExecution" }), []);
});

test("which tools have a permission hook", () => {
  assert.equal(hasPermissionHook("Shell"), true);
  assert.equal(hasPermissionHook("Read"), true);
  assert.equal(hasPermissionHook("MCP:search"), true);
  assert.equal(hasPermissionHook("Write"), false);
  assert.equal(hasPermissionHook(undefined), false);
});

test("subagents are recorded with their id and type; a stop carries only the size of the summary", () => {
  const start = map({ hook_event_name: "subagentStart", subagent_id: "sub-1", subagent_type: "explore" });
  assert.equal(start[0].event_type, "subagent.started");
  assert.equal(start[0].agent_id, "sub-1");
  assert.equal(map({ hook_event_name: "subagentStart" }).length, 0);
  const stop = map({ hook_event_name: "subagentStop", subagent_id: "sub-1", summary: "found it" });
  assert.equal(stop[0].event_type, "subagent.stopped");
});

test("session end reasons", () => {
  assert.equal(sessionEndStatus("error"), "errored");
  assert.equal(sessionEndStatus("aborted"), "interrupted");
  assert.equal(sessionEndStatus("window_close"), "interrupted");
  assert.equal(sessionEndStatus("completed"), "completed");
  assert.equal(sessionEndStatus(undefined), "completed");
});
