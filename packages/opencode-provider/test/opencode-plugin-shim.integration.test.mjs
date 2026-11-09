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
const SHIM = path.resolve(__dirname, "../dist/bin/opencode-plugin-shim.js");
const base = (id) => ({ session_id: id, cwd: "/tmp/repo", ts: new Date().toISOString() });

test("a session: start, prompt, a call with its result, end", async (t) => {
  const s = await scratch(t);
  const id = "s-opencode-flow";
  const args = { command: "echo hi" };
  for (const payload of [
    { ...base(id), event: "session.start" },
    { ...base(id), event: "prompt", prompt: "say hi", model: "free-model" },
    { ...base(id), event: "tool.before", tool: "bash", call_id: "c-1", args },
    { ...base(id), event: "tool.after", tool: "bash", call_id: "c-1", args, output: "hi", duration_ms: 5 },
    { ...base(id), event: "session.end", reason: "completed" },
  ]) {
    const r = await runShim(SHIM, s, payload);
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, "{}", payload.event);
  }
  const events = await loggedEvents(s.home);
  assert.deepEqual(
    events.filter((e) => e.event_type !== "risk.detected").map((e) => e.event_type),
    ["session.started", "prompt.submitted", "session.model_changed", "tool.invoked", "tool.completed", "session.ended"],
  );
  assert.ok(events.every((e) => e.interceptor === "opencode-plugin" || e.interceptor === "analyzer"));
  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.equal(invoked.tool_call_id, "c-1");
  assert.equal(events.find((e) => e.event_type === "tool.completed").tool_call_id, "c-1");
  assert.equal(events.find((e) => e.event_type === "session.started").platform, "opencode");
  assert.equal(events.find((e) => e.event_type === "session.model_changed").model, "free-model");
});

test("a failed call is recorded as an error", async (t) => {
  const s = await scratch(t);
  const id = "s-opencode-fail";
  await runShim(SHIM, s, { ...base(id), event: "tool.before", tool: "bash", call_id: "c-f", args: { command: "false" } });
  await runShim(SHIM, s, { ...base(id), event: "tool.error", tool: "bash", call_id: "c-f", args: { command: "false" }, error: "exit 1" });
  assert.equal((await loggedEvents(s.home)).find((e) => e.event_type === "tool.completed").status, "error");
});

test("the contract holds on garbage: exit 0 and one valid JSON document, nothing recorded", async (t) => {
  const s = await scratch(t);
  for (const raw of ["", "not json", "[]", "null", '{"event":"tool.before"}', '{"session_id":"x","event":"Nope"}', "\u0000\u0001"]) {
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

test("a home the shim cannot use does not fail the call: no decision, exit 0", async (t) => {
  const s = await scratch(t);
  const r = await runShim(SHIM, { ...s, home: path.join(fileURLToPath(import.meta.url), "not-a-dir") }, { ...base("s-opencode-ro"), event: "tool.before", tool: "bash", call_id: "x", args: { command: "ls" } });
  assert.equal(r.code, 0);
  assert.equal(r.stdout, "{}");
});
