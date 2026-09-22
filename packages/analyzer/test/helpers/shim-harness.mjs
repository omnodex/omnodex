// Runs a hook shim as its host would, with capture-hooks.mjs loaded, and
// reads back what it wrote and pushed. Shared by the provider packages'
// capture evaluation tests.

import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const HOOKS = fileURLToPath(new URL("./capture-hooks.mjs", import.meta.url));

/** A scratch OMNODEX_HOME and HOME, removed after the test. */
export async function scratch(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-capture-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { home: path.join(dir, ".omnodex"), userHome: dir, pushLog: path.join(dir, "pushed.jsonl") };
}

/**
 * Run a shim once. `env` is added to a base that keeps the run off the real
 * ~/.omnodex and starts no background pass.
 */
export function runShim(shim, { home, userHome, pushLog }, payload, { env = {}, args = [] } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", HOOKS, shim, ...args], {
      env: {
        ...process.env,
        HOME: userHome,
        USERPROFILE: userHome,
        OMNODEX_HOME: home,
        OMNODEX_AUTO_SYNC: "0",
        OMNODEX_AUTO_DETECT: "0",
        OMNODEX_TEST_PUSH_LOG: pushLog,
        ...env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
}

async function readJsonl(file) {
  try {
    return (await readFile(file, "utf8")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

/** Every event the shim wrote to the log. */
export async function loggedEvents(home) {
  const dir = path.join(home, "event-log", "sessions");
  let entries = [];
  try {
    entries = await readdir(dir);
  } catch {
    return [];
  }
  const events = [];
  for (const entry of entries.sort()) {
    if (entry.endsWith(".jsonl")) events.push(...(await readJsonl(path.join(dir, entry))));
  }
  return events;
}

/** Every event the shim handed to pushEventsToCloud. */
export const pushedEvents = (pushLog) => readJsonl(pushLog);

export const findingsIn = (events) => events.filter((e) => e.event_type === "risk.detected");

/**
 * The capture evaluation cases every shim must pass.
 *
 *   shim           path to the built shim
 *   interceptor    the interceptor its events carry
 *   sensitiveRead  (sessionId) => { payload, args } for a PreToolUse that
 *                  reads /etc/shadow, which a per-event rule flags
 *   harmlessCall   (sessionId) => { payload, args } for a PreToolUse that
 *                  no rule flags
 *   checkResult    optional (result) => void, for host-specific stdout
 */
export function captureEvaluationCases(test, assert, { shim, interceptor, sensitiveRead, harmlessCall, checkResult = () => {} }) {
  async function run(t, call, env = {}) {
    const s = await scratch(t);
    const { payload, args } = call;
    const result = await runShim(shim, s, payload, { env, args });
    assert.equal(result.code, 0, `stderr: ${result.stderr}`);
    checkResult(result);
    return { logged: await loggedEvents(s.home), pushed: await pushedEvents(s.pushLog), result };
  }

  test("a matching call: the finding is written after the event and pushed with it", async (t) => {
    const { logged, pushed } = await run(t, sensitiveRead("s-cap-match"));
    const invoked = logged.find((e) => e.event_type === "tool.invoked");
    assert.equal(invoked.interceptor, interceptor);
    const findings = findingsIn(logged);
    assert.equal(findings.length, 1, JSON.stringify(logged.map((e) => e.rule_id ?? e.event_type)));
    assert.equal(findings[0].rule_id, "RULE_SENSITIVE_PATH_READ");
    assert.equal(findings[0].interceptor, "analyzer");
    assert.equal(findings[0].related_event_id, invoked.tool_call_id);
    assert.ok(logged.indexOf(invoked) < logged.indexOf(findings[0]), "event before its finding");
    assert.deepEqual(
      pushed.map((e) => e.event_id),
      logged.map((e) => e.event_id),
      "one push carrying the events and the finding",
    );
  });

  test("a harmless call writes and pushes no finding", async (t) => {
    const { logged, pushed } = await run(t, harmlessCall("s-cap-clean"));
    assert.equal(findingsIn(logged).length, 0);
    assert.equal(pushed.length, logged.length);
  });

  test("OMNODEX_CAPTURE_DETECT=0 skips evaluation", async (t) => {
    const { logged, pushed } = await run(t, sensitiveRead("s-cap-off"), { OMNODEX_CAPTURE_DETECT: "0" });
    assert.ok(logged.some((e) => e.event_type === "tool.invoked"));
    assert.equal(findingsIn(logged).length, 0);
    assert.equal(findingsIn(pushed).length, 0);
  });

  test("an evaluator that does not load in time: no finding, the event still recorded and pushed", async (t) => {
    const started = Date.now();
    const { logged, pushed } = await run(t, sensitiveRead("s-cap-hang"), {
      OMNODEX_TEST_CAPTURE: "hang",
      OMNODEX_CAPTURE_DETECT_TIMEOUT_MS: "150",
    });
    assert.ok(Date.now() - started < 10_000, "the shim exits instead of waiting on the load");
    assert.ok(logged.some((e) => e.event_type === "tool.invoked"));
    assert.equal(findingsIn(logged).length, 0);
    assert.equal(pushed.length, logged.length);
  });

  test("an evaluator that throws: no finding, the event still recorded and pushed", async (t) => {
    const { logged, pushed } = await run(t, sensitiveRead("s-cap-throw"), { OMNODEX_TEST_CAPTURE: "throw" });
    assert.ok(logged.some((e) => e.event_type === "tool.invoked"));
    assert.equal(findingsIn(logged).length, 0);
    assert.equal(pushed.length, logged.length);
  });
}
