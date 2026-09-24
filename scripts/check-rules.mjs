#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Check a rule pack: against written cases, and against real activity.
 *
 * Advanced rules live outside this repository, so their tests cannot be
 * ordinary test files here. This is the harness they use instead. It takes a
 * pack (plain JSON, or a sealed bundle with a key) and either:
 *
 *   --cases <file>   run written cases: each is a session of tool calls with
 *                    the rule ids that must fire and must not fire on the
 *                    last call. Exits non-zero on any miss.
 *   --log <root>     replay a real event log and report findings per rule,
 *                    which is how a pack is checked for noise before it
 *                    ships. Reads only; nothing is written back.
 *
 * Usage:
 *   node scripts/check-rules.mjs <pack.json|bundle.json> --cases cases.json
 *   node scripts/check-rules.mjs <pack.json> --log ~/.omnodex/event-log
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { openBundle } from "../packages/analyzer/dist/bundle.js";
import { RuleEngine } from "../packages/analyzer/dist/engine.js";
import { createWorkspaceResolver } from "../packages/analyzer/dist/workspace.js";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

const packFile = process.argv[2];
if (!packFile || packFile.startsWith("--")) {
  console.error("usage: node scripts/check-rules.mjs <pack.json|bundle.json> (--cases <file> | --log <event-log root>)");
  process.exit(2);
}

/** A pack is either rules as written, or a sealed bundle plus a key. */
function loadPack(file) {
  const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  if (Array.isArray(parsed)) return parsed;
  const opened = openBundle(parsed);
  if (opened.skipped) {
    console.error(`${file}: bundle not opened (${opened.skipped}). Set OMNODEX_RULES_PUBLIC_KEY and OMNODEX_RULES_KEY.`);
    process.exit(2);
  }
  return opened.rules;
}

const rules = loadPack(packFile);
const engine = new RuleEngine(rules);
const workspaceRoots = createWorkspaceResolver();
const contextFor = (event) => ({
  workspaceRoots: event.cwd ? workspaceRoots(event.cwd) : undefined,
  home: process.env.HOME,
});

// ---------------------------------------------------------------------------
// Written cases
// ---------------------------------------------------------------------------

function runCases(file) {
  const cases = JSON.parse(fs.readFileSync(file, "utf8"));
  let failed = 0;

  for (const [index, testCase] of cases.entries()) {
    const sessionId = `case-${index}`;
    let at = Date.parse("2026-09-23T12:00:00.000Z");
    let fired = [];
    engine.endSession(sessionId);

    testCase.calls.forEach((call, i) => {
      at += (call.after_seconds ?? 1) * 1000;
      const event = {
        schema_version: 1,
        event_id: `${sessionId}-evt-${i}`,
        session_id: sessionId,
        occurred_at: new Date(at).toISOString(),
        recorded_at: new Date(at).toISOString(),
        interceptor: "claude-code-hook",
        event_type: "tool.invoked",
        tool_call_id: `${sessionId}-tc-${i}`,
        tool_name: call.tool,
        mcp_server: call.mcp_server ?? "builtin",
        parameters: call.parameters,
        cwd: call.cwd ?? testCase.cwd ?? "/home/case/repo",
      };
      fired = engine.evaluate(event, contextFor(event)).map((f) => f.rule_id);
    });

    const missing = (testCase.must_fire ?? []).filter((id) => !fired.includes(id));
    const unexpected = (testCase.must_not_fire ?? []).filter((id) => fired.includes(id));
    if (missing.length === 0 && unexpected.length === 0) {
      console.log(`  ok   ${testCase.name}`);
    } else {
      failed++;
      console.log(`  FAIL ${testCase.name}`);
      if (missing.length) console.log(`         expected but did not fire: ${missing.join(", ")}`);
      if (unexpected.length) console.log(`         fired but should not: ${unexpected.join(", ")}`);
      console.log(`         fired: ${fired.length ? fired.join(", ") : "(nothing)"}`);
    }
  }

  console.log(`\n${cases.length - failed}/${cases.length} cases passed`);
  return failed;
}

// ---------------------------------------------------------------------------
// Real activity
// ---------------------------------------------------------------------------

function runLog(root) {
  const dir = path.join(root, "sessions");
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".jsonl"));
  const perRule = new Map();
  let calls = 0;
  let sessions = 0;

  for (const file of files) {
    const sessionId = file.replace(/\.jsonl$/, "");
    sessions++;
    engine.endSession(sessionId);
    for (const line of fs.readFileSync(path.join(dir, file), "utf8").split("\n")) {
      if (!line.trim()) continue;
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }
      if (event.event_type !== "tool.invoked") continue;
      calls++;
      for (const finding of engine.evaluate(event, contextFor(event))) {
        const seen = perRule.get(finding.rule_id) ?? { count: 0, sessions: new Set(), example: finding.description };
        seen.count++;
        seen.sessions.add(event.session_id);
        perRule.set(finding.rule_id, seen);
      }
    }
  }

  console.log(`${calls} tool calls in ${sessions} session(s)\n`);
  if (perRule.size === 0) {
    console.log("  nothing fired");
    return 0;
  }
  for (const [ruleId, seen] of [...perRule].sort((a, b) => b[1].count - a[1].count)) {
    console.log(`  ${String(seen.count).padStart(5)}  ${ruleId}  (${seen.sessions.size} session(s))`);
    console.log(`         e.g. ${seen.example}`);
  }
  return 0;
}

const cases = arg("cases");
const log = arg("log");
if (!cases && !log) {
  console.error("nothing to do: pass --cases <file> or --log <event-log root>");
  process.exit(2);
}

console.log(`${rules.length} rule(s) from ${packFile}\n`);
let failures = 0;
if (cases) failures += runCases(cases);
if (log) failures += runLog(log);
process.exit(failures > 0 ? 1 : 0);
