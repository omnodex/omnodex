// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
// The shim hands the guardrails module the call and prints a deny for the
// plugin to throw. The module here is a stand-in that answers the way the real
// one does for OpenCode (see the module's header).
import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { findingsIn, loggedEvents, runShim, scratch } from "../../analyzer/test/helpers/shim-harness.mjs";
import { installModule } from "../../analyzer/test/helpers/make-module.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/opencode-plugin-shim.js");

const OPENCODE_MODULE = `
export const GUARDRAILS_INTERFACE = 1;
const rank = { alert_only: 0, confirm: 1, deny: 2 };
export function decide({ host, verdicts, failure, onError }) {
  if (failure) return onError === "block" ? { action: "deny", held: [], output: { decision: "deny", reason: "could not check" } } : { action: "alert_only", held: [], output: null };
  let action = "alert_only";
  for (const v of verdicts) if (rank[v.action] > rank[action]) action = v.action;
  if (action === "alert_only") return { action, held: [], output: null };
  const rules = verdicts.filter((v) => v.action === action).map((v) => v.rule_id);
  return { action, held: rules, output: { decision: "deny", reason: host + " " + action + " " + rules.join(",") } };
}
`;

const call = { event: "tool.before", session_id: "s-oc-guard", cwd: "/tmp/repo", tool: "read", call_id: "c-g", args: { filePath: "/etc/shadow" } };

async function run(t, verdict, { mode = "guardrails", module = true, env = {} } = {}) {
  const s = await scratch(t);
  await mkdir(s.home, { recursive: true });
  await writeFile(path.join(s.home, "omnodex-config.json"), JSON.stringify({ enforcement: { mode, rules: { RULE_SENSITIVE_PATH_READ: verdict } } }));
  const moduleEnv = module ? installModule(s.home, { source: OPENCODE_MODULE }).env : {};
  const result = await runShim(SHIM, s, call, { env: { ...moduleEnv, ...env } });
  assert.equal(result.code, 0, result.stderr);
  return { result, logged: await loggedEvents(s.home), home: s.home };
}

test("a deny is printed as a deny with the module's reason, and the finding records that it held the call", async (t) => {
  const { result, logged, home } = await run(t, "deny");
  assert.deepEqual(JSON.parse(result.stdout), { decision: "deny", reason: "opencode deny RULE_SENSITIVE_PATH_READ" });
  assert.equal(findingsIn(logged).find((f) => f.rule_id === "RULE_SENSITIVE_PATH_READ").enforcement.held, true);
  assert.ok((await readFile(path.join(home, "live-push-deferred.jsonl"), "utf8")).length > 0);
});

test("a confirm verdict is also a deny, since the plugin cannot ask", async (t) => {
  const { result } = await run(t, "confirm");
  assert.equal(JSON.parse(result.stdout).decision, "deny");
});

test("rules that fail let the call run; so do no module and shadow mode", async (t) => {
  const failed = await run(t, "deny", { env: { OMNODEX_TEST_CAPTURE: "throw" } });
  assert.equal(failed.result.stdout, "{}");
  assert.equal(failed.logged.find((e) => e.event_type === "risk.enforcement_error").outcome, "allowed");
  assert.equal((await run(t, "deny", { module: false })).result.stdout, "{}");
  assert.equal((await run(t, "deny", { mode: "shadow" })).result.stdout, "{}");
});
