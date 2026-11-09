// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
// The shim hands the guardrails module the call, and prints the answer in the
// shape the event reads. The module here is a stand-in that answers the way
// the real one does for Cursor (see the module's header).
import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { findingsIn, loggedEvents, runShim, scratch } from "../../analyzer/test/helpers/shim-harness.mjs";
import { installModule } from "../../analyzer/test/helpers/make-module.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/cursor-hook-shim.js");

const CURSOR_MODULE = `
export const GUARDRAILS_INTERFACE = 1;
const rank = { alert_only: 0, confirm: 1, deny: 2 };
export function decide({ host, verdicts, failure, onError }) {
  if (failure) return onError === "block" ? { action: "deny", held: [], output: { permission: "deny", decision: "deny", reason: "could not check", user_message: "could not check", agent_message: "could not check" } } : { action: "alert_only", held: [], output: null };
  let action = "alert_only";
  for (const v of verdicts) if (rank[v.action] > rank[action]) action = v.action;
  if (action === "alert_only") return { action, held: [], output: null };
  const rules = verdicts.filter((v) => v.action === action).map((v) => v.rule_id);
  const ask = action === "confirm";
  return { action, held: rules, output: { permission: ask ? "ask" : "deny", user_message: "user " + host, agent_message: "agent " + rules.join(","), decision: "deny", reason: "reason " + rules.join(",") } };
}
`;

const id = "c-cursor-guard";
const common = { conversation_id: id, workspace_roots: ["/tmp/repo"] };
const readCall = { ...common, hook_event_name: "preToolUse", tool_name: "Read", tool_input: { file_path: "/etc/shadow" }, tool_use_id: "tu-r" };
const writeCall = { ...common, hook_event_name: "preToolUse", tool_name: "Write", tool_input: { file_path: "/etc/shadow", contents: "x" }, tool_use_id: "tu-w" };

async function run(t, payload, verdict, { mode = "guardrails", module = true } = {}) {
  const s = await scratch(t);
  await mkdir(s.home, { recursive: true });
  await writeFile(path.join(s.home, "omnodex-config.json"), JSON.stringify({ enforcement: { mode, rules: { RULE_SENSITIVE_PATH_READ: verdict } } }));
  const env = module ? installModule(s.home, { source: CURSOR_MODULE }).env : {};
  const result = await runShim(SHIM, s, payload, { env });
  assert.equal(result.code, 0, result.stderr);
  return { result, logged: await loggedEvents(s.home), home: s.home };
}
const out = (result) => JSON.parse(result.stdout);

test("a deny on preToolUse prints decision and reason, and the finding records that it held the call", async (t) => {
  const { result, logged, home } = await run(t, readCall, "deny");
  assert.deepEqual(out(result), { decision: "deny", reason: "reason RULE_SENSITIVE_PATH_READ" });
  assert.equal(findingsIn(logged).find((f) => f.rule_id === "RULE_SENSITIVE_PATH_READ").enforcement.held, true);
  assert.ok((await readFile(path.join(home, "live-push-deferred.jsonl"), "utf8")).length > 0);
});

test("a deny on a tool with no permission hook of its own is the same", async (t) => {
  const { result } = await run(t, writeCall, "deny");
  assert.equal(out(result).decision, "deny");
});

test("a confirm verdict: preToolUse leaves a read to its permission hook, which asks", async (t) => {
  const pre = await run(t, readCall, "confirm");
  assert.equal(pre.result.stdout, "{}", "preToolUse does not block what the permission hook will ask about");
  const perm = await run(t, { ...common, hook_event_name: "beforeReadFile", file_path: "/etc/shadow" }, "confirm");
  assert.deepEqual(out(perm.result), { permission: "ask", user_message: "user cursor", agent_message: "agent RULE_SENSITIVE_PATH_READ" });
  assert.deepEqual(perm.logged, [], "a permission hook writes nothing");
});

test("a confirm verdict on a tool with no permission hook is a deny that carries the reason", async (t) => {
  const { result } = await run(t, writeCall, "confirm");
  assert.equal(out(result).decision, "deny");
});

test("a deny reaches the shell and MCP permission hooks as deny", async (t) => {
  for (const payload of [
    { ...common, hook_event_name: "beforeShellExecution", command: "cat /etc/shadow" },
    { ...common, hook_event_name: "beforeMCPExecution", server: "fs", tool_name: "read", tool_input: JSON.stringify({ file_path: "/etc/shadow" }) },
    { ...common, hook_event_name: "beforeReadFile", file_path: "/etc/shadow" },
  ]) {
    const { result } = await run(t, payload, "deny");
    assert.equal(out(result).permission, "deny", payload.hook_event_name);
  }
});

test("without a module, or in shadow mode, nothing is stopped", async (t) => {
  assert.equal((await run(t, readCall, "deny", { module: false })).result.stdout, "{}");
  assert.equal((await run(t, readCall, "deny", { mode: "shadow" })).result.stdout, "{}");
  assert.equal((await run(t, { ...common, hook_event_name: "beforeReadFile", file_path: "/etc/shadow" }, "deny", { mode: "shadow" })).result.stdout, "{}");
});
