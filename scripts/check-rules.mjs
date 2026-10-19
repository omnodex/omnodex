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
 *   --verbose        with --log, list every finding with its session and,
 *                    for a sequence rule, each step of its evidence
 *
 * Rules run through the same evaluator the proxy and background pass use,
 * with an in-memory machine store: fresh for each case, and one for the
 * whole replay, which takes sessions in the order they started, so a
 * first-seen rule judges each host against what came before it.
 *
 * Usage:
 *   node scripts/check-rules.mjs <pack.json|bundle.json> --cases cases.json
 *   node scripts/check-rules.mjs <pack.json> --log ~/.omnodex/event-log [--verbose]
 */

import * as fs from "node:fs";
import * as path from "node:path";

import { openBundle } from "../packages/analyzer/dist/bundle.js";
import { createEvaluator } from "../packages/analyzer/dist/evaluator.js";
import { RuleRegistry } from "../packages/analyzer/dist/registry.js";
import { memoryMachineState } from "../packages/analyzer/dist/machine-state.js";

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
let findingSeq = 0;
/** An evaluator over just this pack, as a long-lived host runs it. */
const evaluatorFor = (machineState, userHome) => createEvaluator({
  host: "batch",
  registry: new RuleRegistry(rules),
  newEventId: () => `check-${++findingSeq}`,
  machineState,
  userHome,
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
    // Cases are written for the user "case", whatever machine runs them.
    const evaluator = evaluatorFor(memoryMachineState(), testCase.home ?? "/home/case");

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
      fired = evaluator.evaluate(event).map((f) => f.rule_id);
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

function runLog(root, verbose) {
  const dir = path.join(root, "sessions");
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".jsonl"));
  const perRule = new Map();
  const all = [];
  let calls = 0;

  // Sessions in the order they started, so first-seen state builds as it did.
  const sessions = [];
  for (const file of files) {
    const events = [];
    for (const line of fs.readFileSync(path.join(dir, file), "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        events.push(JSON.parse(line));
      } catch {
        // Partial trailing write.
      }
    }
    if (events.length) sessions.push({ start: events[0].occurred_at ?? "", events });
  }
  sessions.sort((a, b) => a.start.localeCompare(b.start));

  const evaluator = evaluatorFor(memoryMachineState());
  for (const { events } of sessions) {
    for (const event of events) {
      // Findings already in the log would suppress the rules under test.
      if (event.event_type !== "tool.invoked" && event.event_type !== "session.started" && event.event_type !== "session.ended") continue;
      if (event.event_type === "tool.invoked") calls++;
      for (const finding of evaluator.evaluate(event)) {
        const seen = perRule.get(finding.rule_id) ?? { count: 0, sessions: new Set(), example: finding.description };
        seen.count++;
        seen.sessions.add(event.session_id);
        perRule.set(finding.rule_id, seen);
        all.push(finding);
      }
    }
  }

  console.log(`${calls} tool calls in ${sessions.length} session(s)\n`);
  for (const { rule_id, reason } of evaluator.stats().unreadableRules) {
    console.log(`  not run: ${rule_id} (${reason})`);
  }
  if (perRule.size === 0) {
    console.log("  nothing fired");
    return 0;
  }
  for (const [ruleId, seen] of [...perRule].sort((a, b) => b[1].count - a[1].count)) {
    console.log(`  ${String(seen.count).padStart(5)}  ${ruleId}  (${seen.sessions.size} session(s))`);
    console.log(`         e.g. ${seen.example}`);
  }
  if (verbose) {
    console.log("");
    for (const f of all) {
      console.log(`  ${f.rule_id}  ${f.session_id}  ${f.severity}`);
      console.log(`    ${f.description}`);
      for (const step of f.evidence?.steps ?? []) console.log(`      ${step.role.padEnd(8)} ${step.summary}`);
    }
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
if (log) failures += runLog(log, process.argv.includes("--verbose"));
process.exit(failures > 0 ? 1 : 0);
