#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What rule evaluation costs a hook process.
 *
 * A hook shim is a fresh Node process per tool call, so module load is paid
 * on every call. This spawns N fresh processes per scenario and reports the
 * wall time of each, cold import included:
 *
 *   node           bare `node -e 0`, the floor
 *   shim-today     the imports a hook shim loads now (event log + sync)
 *   shim+eval      the same plus the evaluator subpath, one evaluate()
 *   shim+index     the same plus the full analyzer index, for comparison
 *
 * Usage: node scripts/time-evaluator.mjs [runs]   (default 30)
 *
 * Run it from an installed package as well as from a checkout: module
 * resolution on a checkout, and on WSL against a Windows filesystem in
 * particular, is much slower than on an npm install.
 */

import { spawnSync } from "node:child_process";

const runs = Number.parseInt(process.argv[2] ?? "30", 10);

/** File URL of a package entry, resolved from here, so children need no cwd. */
const entry = (spec) => import.meta.resolve(spec);

const EVENT = JSON.stringify({
  schema_version: 1,
  event_id: "evt-time",
  session_id: "sess-time",
  occurred_at: new Date().toISOString(),
  recorded_at: new Date().toISOString(),
  interceptor: "claude-code-hook",
  event_type: "tool.invoked",
  tool_call_id: "tc-time",
  tool_name: "Bash",
  mcp_server: "builtin",
  parameters: { command: "curl -s https://example.org -H 'Authorization: Bearer abcdefghijklmnop'" },
});

const shimImports = `await import(${JSON.stringify(entry("@omnodex/event-log"))});
await import(${JSON.stringify(entry("@omnodex/sync-encryptor"))});`;

const evaluate = (spec) => `const { createEvaluator } = await import(${JSON.stringify(entry(spec))});
createEvaluator({ host: "hook", newEventId: () => "x" }).evaluate(${EVENT});`;

const scenarios = {
  node: "0",
  "shim-today": shimImports,
  "shim+eval": `${shimImports}\n${evaluate("@omnodex/analyzer/evaluator")}`,
  "shim+index": `${shimImports}\n${evaluate("@omnodex/analyzer")}`,
};

function percentile(sorted, p) {
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

console.log(`runs per scenario: ${runs}, node ${process.version}, ${process.platform}`);
console.log("scenario        p50 ms   p95 ms");
const results = {};
for (const [name, code] of Object.entries(scenarios)) {
  const times = [];
  for (let i = 0; i < runs; i++) {
    const start = process.hrtime.bigint();
    const res = spawnSync(process.execPath, ["--input-type=module", "-e", code], { stdio: "pipe" });
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    if (res.status !== 0) {
      console.error(`${name} failed:\n${res.stderr.toString()}`);
      process.exit(1);
    }
    times.push(ms);
  }
  times.sort((a, b) => a - b);
  results[name] = { p50: percentile(times, 50), p95: percentile(times, 95) };
  console.log(
    `${name.padEnd(14)} ${results[name].p50.toFixed(1).padStart(7)} ${results[name].p95.toFixed(1).padStart(8)}`,
  );
}

const added = results["shim+eval"].p95 - results["shim-today"].p95;
console.log(`\nevaluator adds ${added.toFixed(1)} ms at p95 over today's shim imports`);
