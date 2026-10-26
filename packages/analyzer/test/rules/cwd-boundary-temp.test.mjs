/**
 * Temp-folder boundary rule unit tests.
 *
 * Tests RULE_CWD_BOUNDARY_TEMP_WRITE, and that the agent harness's own
 * session scratch folder counts as workspace for both boundary rules.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as os from "node:os";
import * as path from "node:path";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_CWD_BOUNDARY_WRITE, RULE_CWD_BOUNDARY_TEMP_WRITE } from "../../dist/rules/index.js";
import { createEvaluator } from "../../dist/evaluator.js";
import { RuleRegistry } from "../../dist/registry.js";

const temp = new RuleEngine([RULE_CWD_BOUNDARY_TEMP_WRITE]);
const both = new RuleEngine([RULE_CWD_BOUNDARY_WRITE, RULE_CWD_BOUNDARY_TEMP_WRITE]);

const SESSION = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b";
const SCRATCH = `/tmp/claude-1000/-home-case-projects-myapp/${SESSION}/scratchpad`;

function makeEvent(overrides = {}) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: SESSION,
    occurred_at: "2026-06-02T00:00:00.000Z",
    recorded_at: "2026-06-02T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: "Write",
    mcp_server: "builtin",
    parameters: {},
    cwd: "/home/case/projects/myapp",
    ...overrides,
  };
}

function write(filePath, overrides = {}) {
  return makeEvent({ parameters: { file_path: filePath, content: "x" }, ...overrides });
}

const ruleIds = (findings) => findings.map((f) => f.rule_id);

// ---------------------------------------------------------------------------
// Cases that MUST fire
// ---------------------------------------------------------------------------

test("fires LOW on a write to /tmp, with no blocking hint", () => {
  const findings = temp.evaluate(write("/tmp/staging/payload.bin"));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "LOW");
  assert.equal(findings[0].category, "cwd_boundary");
  assert.ok(findings[0].description.includes("/tmp/staging/payload.bin"));
  assert.ok(findings[0].description.includes("temp folder"));
  assert.equal(RULE_CWD_BOUNDARY_TEMP_WRITE.blocking_hint, undefined);
});

test("fires on /var/tmp, macOS per-user temp and Windows %TEMP%", () => {
  assert.equal(temp.evaluate(write("/var/tmp/a.log")).length, 1);
  assert.equal(temp.evaluate(write("/private/var/folders/ab/cd1234/T/a.log")).length, 1);
  assert.equal(temp.evaluate(write("/var/folders/ab/cd1234/T/a.log")).length, 1);
  const win = write("C:\\Users\\case\\AppData\\Local\\Temp\\a.log", { cwd: "C:\\Users\\case\\projects\\myapp" });
  assert.equal(temp.evaluate(win).length, 1);
});

test("fires on a Bash redirect into /tmp", () => {
  const findings = temp.evaluate(makeEvent({
    tool_name: "Bash",
    parameters: { command: "cat .env > /tmp/out.txt" },
  }));
  assert.equal(findings.length, 1);
});

test("another session's scratch folder is a temp write, not workspace", () => {
  const other = "/tmp/claude-1000/-home-case-projects-myapp/9e8d7c6b-0000-4000-8000-000000000000/scratchpad/log.txt";
  assert.deepEqual(ruleIds(both.evaluate(write(other))), ["RULE_CWD_BOUNDARY_TEMP_WRITE"]);
});

test("the host's temp folder counts as temp", () => {
  const findings = temp.evaluate(write("/scratch/host-temp/a.log"), {
    workspaceRoots: ["/home/case/projects/myapp"],
    tempDirs: ["/scratch/host-temp"],
  });
  assert.equal(findings.length, 1);
});

test("the evaluator passes the OS temp folder to the rule", () => {
  const ev = createEvaluator({
    host: "batch",
    registry: new RuleRegistry([RULE_CWD_BOUNDARY_WRITE, RULE_CWD_BOUNDARY_TEMP_WRITE]),
    newEventId: () => "evt-x",
    workspaceRoots: (cwd) => [cwd],
  });
  const findings = ev.evaluate(write(path.join(os.tmpdir(), "omnodex-temp-rule", "a.log")));
  assert.deepEqual(findings.map((f) => f.rule_id), ["RULE_CWD_BOUNDARY_TEMP_WRITE"]);
});

// ---------------------------------------------------------------------------
// Cases that MUST NOT fire
// ---------------------------------------------------------------------------

test("no finding from either rule on the session's own scratch folder", () => {
  assert.deepEqual(both.evaluate(write(`${SCRATCH}/omx-ci.log`)), []);
  const bash = makeEvent({ tool_name: "Bash", parameters: { command: `npm test > ${SCRATCH}/test.log 2>&1` } });
  assert.deepEqual(both.evaluate(bash), []);
});

test("the scratch folder must be in a temp folder, under claude-<uid>", () => {
  const notTemp = `/home/case/claude-1000/-home-case-projects-myapp/${SESSION}/scratchpad/a.log`;
  assert.deepEqual(ruleIds(both.evaluate(write(notTemp))), ["RULE_CWD_BOUNDARY_WRITE"]);
  const noUid = `/tmp/other-1000/-home-case-projects-myapp/${SESSION}/scratchpad/a.log`;
  assert.deepEqual(ruleIds(both.evaluate(write(noUid))), ["RULE_CWD_BOUNDARY_TEMP_WRITE"]);
});

test("no finding on a write outside the workspace that is not in a temp folder", () => {
  assert.deepEqual(temp.evaluate(write("/home/case/other-project/config.json")), []);
  assert.deepEqual(temp.evaluate(write("/tmpfoo/a.log")), []);
  assert.deepEqual(temp.evaluate(write("~/.bashrc")), []);
});

test("no finding on a temp write inside the workspace", () => {
  assert.deepEqual(both.evaluate(write("/tmp/build/myapp/out.js", { cwd: "/tmp/build/myapp" })), []);
});

test("no finding on a read from /tmp", () => {
  const findings = temp.evaluate(makeEvent({ tool_name: "Bash", parameters: { command: "cat /tmp/notes.txt" } }));
  assert.deepEqual(findings, []);
});

test("no finding when cwd is not populated", () => {
  assert.deepEqual(temp.evaluate(write("/tmp/a.log", { cwd: undefined })), []);
});
