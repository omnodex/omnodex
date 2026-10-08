// Advanced (Pro) usage counted by the background detection pass. A session
// is re-read whole whenever it grows, so the pass must count each tool call
// judged by advanced rules once, not once per rescan, and must not count
// history from before the counter existed.
//
// Run: node --test packages/analyzer/test/detect-log-usage.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog } from "@omnodex/event-log";
import { detectEventLogs, runBackgroundDetection, DETECT_STATE_FILE } from "../dist/detect-log.js";
import { RuleRegistry } from "../dist/registry.js";
import { COMMUNITY_RULES } from "../dist/rules/index.js";

/** An advanced rule that fires on any read under /home/case/secret. */
const ADVANCED_RULE = {
  rule_id: "RULE_CASE_ADVANCED_SECRET_READ",
  version: "1.0.0",
  tier: "advanced",
  event_types: ["tool.invoked"],
  conditions: [{ type: "path_match", patterns: [{ regex: "/home/case/secret/", label: "secret" }] }],
  severity: "MEDIUM",
  category: "case_advanced",
  description_template: "Read of a case secret via {{tool_name}}.",
};

const withAdvanced = () => new RuleRegistry([...COMMUNITY_RULES, ADVANCED_RULE]);
const communityOnly = () => new RuleRegistry([...COMMUNITY_RULES]);

function read(sessionId, file) {
  const now = new Date().toISOString();
  return {
    schema_version: 1, event_id: randomUUID(), session_id: sessionId, occurred_at: now, recorded_at: now,
    interceptor: "claude-code-hook", event_type: "tool.invoked", tool_call_id: `tc-${randomUUID()}`,
    tool_name: "Read", mcp_server: "builtin", parameters: { file_path: file },
  };
}

async function append(root, events) {
  const log = new EventLog({ root });
  await log.init();
  await log.appendMany(events);
  await log.close();
}

describe("advanced usage in detectEventLogs", () => {
  let dir;
  let root;
  let statePath;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-detect-usage-"));
    root = path.join(dir, "event-log");
    statePath = path.join(dir, DETECT_STATE_FILE);
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("counts each call once across rescans of a growing session", async () => {
    await append(root, [read("s1", "/home/case/repo/a.md"), read("s1", "/home/case/secret/key")]);
    let r = await detectEventLogs({ roots: [root], statePath, registry: withAdvanced() });
    assert.equal(r.advancedEvaluated, 2);
    assert.equal(r.advancedFindings, 1);

    // The session grows by one call (and by the run's own finding); the
    // rescan judges all three calls again but counts only the new one.
    await append(root, [read("s1", "/home/case/repo/b.md")]);
    r = await detectEventLogs({ roots: [root], statePath, registry: withAdvanced() });
    assert.equal(r.advancedEvaluated, 1);
    assert.equal(r.advancedFindings, 0);

    // Unchanged since: nothing.
    r = await detectEventLogs({ roots: [root], statePath, registry: withAdvanced() });
    assert.equal(r.advancedEvaluated, 0);
  });

  it("counts nothing while no advanced rule is loaded, and does not bill that history later", async () => {
    await append(root, [read("s1", "/home/case/secret/a"), read("s1", "/home/case/repo/b")]);
    let r = await detectEventLogs({ roots: [root], statePath, registry: communityOnly() });
    assert.equal(r.advancedEvaluated, 0);
    assert.equal(r.advancedFindings, 0);

    await append(root, [read("s1", "/home/case/repo/c")]);
    r = await detectEventLogs({ roots: [root], statePath, registry: withAdvanced() });
    assert.equal(r.advancedEvaluated, 1);
  });

  it("starts an upgraded state at each known session's current count", async () => {
    await append(root, [read("s1", "/home/case/repo/a"), read("s1", "/home/case/repo/b")]);
    await detectEventLogs({ roots: [root], statePath, registry: communityOnly() });
    // A state file from before the counter existed: sizes only.
    const state = JSON.parse(await readFile(statePath, "utf8"));
    delete state.counted;
    await writeFile(statePath, JSON.stringify(state));

    await append(root, [read("s1", "/home/case/repo/c")]);
    const r = await detectEventLogs({ roots: [root], statePath, registry: withAdvanced() });
    assert.equal(r.advancedEvaluated, 0, "the session's history is not counted at upgrade");
    await append(root, [read("s1", "/home/case/repo/d")]);
    assert.equal((await detectEventLogs({ roots: [root], statePath, registry: withAdvanced() })).advancedEvaluated, 1);
  });

  it("runBackgroundDetection reports the counts with the findings", async () => {
    const home = dir;
    await append(path.join(home, "event-log"), [read("s1", "/home/case/secret/x")]);
    const result = await runBackgroundDetection(home, { registry: withAdvanced() });
    assert.equal(result.findings.some((f) => f.rule_id === ADVANCED_RULE.rule_id), true);
    assert.deepEqual(result.advanced, { evaluated: 1, findings: 1 });
  });
});
