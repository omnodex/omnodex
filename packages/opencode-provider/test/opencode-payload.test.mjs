// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { claudeTool, mapOpenCodePayload, normalizeOpenCodePayload, sessionEndStatus } from "../dist/index.js";

let n = 0;
const map = (raw, opts = {}) => mapOpenCodePayload(normalizeOpenCodePayload({ session_id: "s1", cwd: "/home/case/repo", ...raw }), { newEventId: () => `e${++n}`, nowIso: () => "2026-11-09T12:00:00.000Z", ...opts });

test("an envelope without a session or a known event is not ours", () => {
  assert.equal(normalizeOpenCodePayload(null), null);
  assert.equal(normalizeOpenCodePayload([]), null);
  assert.equal(normalizeOpenCodePayload({ event: "tool.before" }), null);
  assert.equal(normalizeOpenCodePayload({ session_id: "s", event: "nope" }), null);
});

test("session, prompt and call events are labeled as OpenCode's", () => {
  const [started] = map({ event: "session.start" });
  assert.equal(started.event_type, "session.started");
  assert.equal(started.interceptor, "opencode-plugin");
  assert.equal(started.platform, "opencode");
  assert.equal(map({ event: "prompt", prompt: "hi" })[0].event_type, "prompt.submitted");
  assert.equal(map({ event: "session.end", reason: "completed" })[0].event_type, "session.ended");
});

test("a call is recorded with OpenCode's own call id, and its result pairs with it", () => {
  const [pre] = map({ event: "tool.before", tool: "bash", call_id: "call-7", args: { command: "ls" } });
  assert.equal(pre.event_type, "tool.invoked");
  assert.equal(pre.tool_call_id, "call-7");
  assert.equal(pre.tool_name, "Bash");
  const done = map({ event: "tool.after", tool: "bash", call_id: "call-7", args: { command: "ls" }, output: "a", duration_ms: 12 });
  assert.equal(done.find((e) => e.event_type === "tool.completed").tool_call_id, "call-7");
  const failed = map({ event: "tool.error", tool: "bash", call_id: "call-8", args: { command: "false" }, error: "exit 1" });
  assert.equal(failed.find((e) => e.event_type === "tool.completed").status, "error");
});

test("OpenCode's lowercase tools and camelCase arguments become Claude Code's", () => {
  assert.deepEqual(claudeTool("read", { filePath: "/a" }), { name: "Read", input: { file_path: "/a" } });
  assert.deepEqual(claudeTool("edit", { filePath: "/a", oldString: "x", newString: "y" }), { name: "Edit", input: { file_path: "/a", old_string: "x", new_string: "y" } });
  assert.deepEqual(claudeTool("grep", { pattern: "p", include: "*.ts" }), { name: "Grep", input: { pattern: "p", glob: "*.ts" } });
  assert.equal(claudeTool("write", {}).name, "Write");
  assert.equal(claudeTool("docs_search", { q: "x" }).name, "docs_search");
  const events = map({ event: "tool.before", tool: "read", call_id: "c", args: { filePath: "/home/case/repo/a.txt" } });
  assert.ok(events.some((e) => e.event_type === "tool.invoked"));
});

test("a subagent is recorded with its id and type", () => {
  const start = map({ event: "subagent.start", agent_id: "child", agent_type: "explore" });
  assert.equal(start[0].event_type, "subagent.started");
  assert.equal(start[0].agent_id, "child");
  assert.equal(map({ event: "subagent.start" }).length, 0);
  assert.equal(map({ event: "subagent.stop", agent_id: "child" })[0].event_type, "subagent.stopped");
});

test("a call event without a tool is dropped", () => {
  assert.deepEqual(map({ event: "tool.before" }), []);
  assert.deepEqual(map({ event: "tool.after" }), []);
});

test("session end reasons", () => {
  assert.equal(sessionEndStatus("error"), "errored");
  assert.equal(sessionEndStatus("aborted"), "interrupted");
  assert.equal(sessionEndStatus("completed"), "completed");
  assert.equal(sessionEndStatus(undefined), "completed");
});
