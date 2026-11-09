// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loggedEvents, runShim, scratch } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/cursor-hook-shim.js");
const base = (id) => ({ conversation_id: id, generation_id: "g1", model: "composer-test", workspace_roots: ["/tmp/repo"], user_email: "case@example.com" });

test("a session: start, prompt, a call with its result, end", async (t) => {
  const s = await scratch(t);
  const id = "c-cursor-flow";
  const input = { command: "echo hi" };
  for (const payload of [
    { ...base(id), hook_event_name: "sessionStart" },
    { ...base(id), hook_event_name: "beforeSubmitPrompt", prompt: "say hi" },
    { ...base(id), hook_event_name: "preToolUse", tool_name: "Shell", tool_input: input, tool_use_id: "tu-1" },
    { ...base(id), hook_event_name: "postToolUse", tool_name: "Shell", tool_input: input, tool_output: "hi", tool_use_id: "tu-1", duration: 5 },
    { ...base(id), hook_event_name: "stop", status: "completed" },
    { ...base(id), hook_event_name: "sessionEnd", reason: "completed" },
  ]) {
    const r = await runShim(SHIM, s, payload);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, "{}", payload.hook_event_name);
  }
  const events = await loggedEvents(s.home);
  assert.deepEqual(
    events.filter((e) => e.event_type !== "risk.detected").map((e) => e.event_type),
    ["session.started", "session.model_changed", "prompt.submitted", "tool.invoked", "tool.completed", "session.ended"],
  );
  assert.ok(events.every((e) => e.interceptor === "cursor-hook" || e.interceptor === "analyzer"));
  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.equal(events.find((e) => e.event_type === "tool.completed").tool_call_id, invoked.tool_call_id);
  assert.equal(invoked.tool_call_id, "tu-1");
  assert.equal(events.find((e) => e.event_type === "session.started").platform, "cursor");
  assert.equal(events.find((e) => e.event_type === "session.model_changed").model, "composer-test");
});

test("the user's email is in no recorded event", async (t) => {
  const s = await scratch(t);
  const id = "c-cursor-email";
  await runShim(SHIM, s, { ...base(id), hook_event_name: "sessionStart" });
  await runShim(SHIM, s, { ...base(id), hook_event_name: "beforeSubmitPrompt", prompt: "hello" });
  await runShim(SHIM, s, { ...base(id), hook_event_name: "preToolUse", tool_name: "Read", tool_input: { file_path: "/tmp/repo/a" }, tool_use_id: "tu-e" });
  const events = await loggedEvents(s.home);
  assert.ok(events.length > 0);
  assert.ok(!JSON.stringify(events).includes("case@example.com"));
});

test("the permission hooks only judge: they write nothing and answer {}", async (t) => {
  const s = await scratch(t);
  const id = "c-cursor-perm";
  for (const payload of [
    { ...base(id), hook_event_name: "beforeShellExecution", command: "ls", cwd: "/tmp/repo" },
    { ...base(id), hook_event_name: "beforeReadFile", file_path: "/tmp/repo/a" },
    { ...base(id), hook_event_name: "beforeMCPExecution", server: "docs", tool_name: "search", tool_input: "{}" },
  ]) {
    const r = await runShim(SHIM, s, payload);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, "{}", payload.hook_event_name);
  }
  assert.deepEqual(await loggedEvents(s.home), []);
});

test("a failed call is recorded as an error", async (t) => {
  const s = await scratch(t);
  const id = "c-cursor-fail";
  const call = { ...base(id), tool_name: "Shell", tool_input: { command: "false" }, tool_use_id: "tu-f" };
  await runShim(SHIM, s, { ...call, hook_event_name: "preToolUse" });
  await runShim(SHIM, s, { ...call, hook_event_name: "postToolUseFailure", error_message: "exit 1" });
  const done = (await loggedEvents(s.home)).find((e) => e.event_type === "tool.completed");
  assert.equal(done.status, "error");
});

test("the contract holds on garbage: exit 0 and one valid JSON document, nothing recorded", async (t) => {
  const s = await scratch(t);
  for (const raw of ["", "not json", "[]", "null", '{"hook_event_name":"preToolUse"}', '{"conversation_id":"x","hook_event_name":"Nope"}', "\u0000\u0001"]) {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [SHIM], {
        env: { ...process.env, HOME: s.userHome, USERPROFILE: s.userHome, OMNODEX_HOME: s.home, OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0" },
        stdio: ["pipe", "pipe", "pipe"],
      });
      let stdout = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.on("error", reject);
      child.on("close", (code) => resolve({ code, stdout }));
      child.stdin.end(raw);
    });
    assert.equal(result.code, 0, JSON.stringify(raw));
    assert.equal(result.stdout, "{}", JSON.stringify(raw));
  }
  assert.deepEqual(await loggedEvents(s.home), []);
});

test("a home the shim cannot use does not fail the hook: no decision, exit 0", async (t) => {
  const s = await scratch(t);
  const r = await runShim(SHIM, { ...s, home: path.join(fileURLToPath(import.meta.url), "not-a-dir") }, { ...base("c-cursor-ro"), hook_event_name: "preToolUse", tool_name: "Shell", tool_input: { command: "ls" }, tool_use_id: "x" });
  assert.equal(r.code, 0);
  assert.equal(r.stdout, "{}");
});
