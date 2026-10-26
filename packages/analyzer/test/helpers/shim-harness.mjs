// Runs a hook shim as its host would, with capture-hooks.mjs loaded, and
// reads back what it wrote and pushed. Shared by the provider packages'
// capture evaluation tests.

import { spawn } from "node:child_process";
import { installModule } from "./make-module.mjs";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { gitTestEnv } from "../../../../scripts/test-git.mjs";

const HOOKS = new URL("./capture-hooks.mjs", import.meta.url).href;

/** A scratch OMNODEX_HOME and HOME, removed after the test. */
export async function scratch(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-capture-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
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
        ...gitTestEnv(userHome),
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
  async function run(t, call, env = {}, config) {
    const s = await scratch(t);
    if (config !== undefined) {
      await mkdir(s.home, { recursive: true });
      await writeFile(path.join(s.home, "omnodex-config.json"), typeof config === "string" ? config : JSON.stringify(config));
    }
    const { payload, args } = call;
    const result = await runShim(shim, s, payload, { env, args });
    assert.equal(result.code, 0, `stderr: ${result.stderr}`);
    checkResult(result);
    return { logged: await loggedEvents(s.home), pushed: await pushedEvents(s.pushLog), result, home: s.home };
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

  test("monitor mode (the default): the finding carries no enforcement record", async (t) => {
    const { logged } = await run(t, sensitiveRead("s-enf-monitor"));
    assert.equal(findingsIn(logged)[0].enforcement, undefined);
  });

  test("shadow mode: the finding records what enforcement would have done, and the call is not touched", async (t) => {
    const config = { enforcement: { mode: "shadow", rules: { RULE_SENSITIVE_PATH_READ: "deny" } } };
    const { logged, pushed, home } = await run(t, sensitiveRead("s-enf-shadow"), {}, config);
    const [finding] = findingsIn(logged);
    assert.deepEqual(finding.enforcement, {
      mode: "shadow",
      candidate: "alert_only",
      action: "deny",
      held: false,
      source: "user-rule",
    });
    assert.deepEqual(findingsIn(pushed)[0].enforcement, finding.enforcement, "the record is pushed with the finding");
    const signals = (await readJsonl(path.join(home, "rule-signals.jsonl"))).map((l) => `${l.rule_id}:${l.kind}`);
    assert.deepEqual(signals, ["RULE_SENSITIVE_PATH_READ:would_block", "RULE_SENSITIVE_PATH_READ:in_force"]);
  });

  test("shadow mode with an allow exception: no record for the allowed rule", async (t) => {
    const config = {
      enforcement: {
        mode: "shadow",
        rules: { RULE_SENSITIVE_PATH_READ: "deny" },
        exceptions: [{ rule_id: "RULE_SENSITIVE_PATH_READ", kind: "allow" }],
      },
    };
    const { logged } = await run(t, sensitiveRead("s-enf-allow"), {}, config);
    const [finding] = findingsIn(logged);
    assert.equal(finding.enforcement?.action ?? "alert_only", "alert_only");
  });

  test("an unreadable configuration file: the finding is still written, unstamped", async (t) => {
    const { logged } = await run(t, sensitiveRead("s-enf-broken"), {}, "{ not json");
    const findings = findingsIn(logged);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].enforcement, undefined);
  });

  test("an evaluator that throws: no finding, the event still recorded and pushed", async (t) => {
    const { logged, pushed } = await run(t, sensitiveRead("s-cap-throw"), { OMNODEX_TEST_CAPTURE: "throw" });
    assert.ok(logged.some((e) => e.event_type === "tool.invoked"));
    assert.equal(findingsIn(logged).length, 0);
    assert.equal(pushed.length, logged.length);
  });
}

/**
 * The guardrails cases every shim that answers PreToolUse must pass. The
 * decision itself comes from the guardrails module; these tests install a
 * stand-in (helpers/make-module.mjs) and check that the shim hands it the
 * call, writes back what it answers, and stays out of the way without it.
 *
 *   shim           path to the built shim
 *   host           the host name the shim passes to the module
 *   sensitiveRead  (sessionId) => { payload, args } for a PreToolUse that
 *                  reads /etc/shadow (RULE_SENSITIVE_PATH_READ)
 *   passOutput     what the shim writes when nothing holds the call: "" or a JSON string
 */
export function guardrailsCases(test, assert, { shim, host, sensitiveRead, passOutput = "" }) {
  async function run(t, call, enforcement, { env = {}, module = true } = {}) {
    const s = await scratch(t);
    await mkdir(s.home, { recursive: true });
    await writeFile(path.join(s.home, "omnodex-config.json"), JSON.stringify({ enforcement }));
    const moduleEnv = module ? installModule(s.home).env : {};
    const { payload, args } = call;
    const result = await runShim(shim, s, payload, { env: { ...moduleEnv, ...env }, args });
    assert.equal(result.code, 0, `stderr: ${result.stderr}`);
    return { result, logged: await loggedEvents(s.home), pushed: await pushedEvents(s.pushLog), home: s.home };
  }

  test("guardrails: the module's decision is written back, and the finding records that it held the call", async (t) => {
    const { result, logged, pushed, home } = await run(t, sensitiveRead("s-gc-deny"), { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
    assert.deepEqual(JSON.parse(result.stdout), { test_decision: "deny", host, rules: ["RULE_SENSITIVE_PATH_READ"] });
    const finding = findingsIn(logged).find((f) => f.rule_id === "RULE_SENSITIVE_PATH_READ");
    assert.equal(finding.enforcement.held, true);
    assert.equal(pushed.length, 0, "the push waits for the next hook");
    assert.ok((await readFile(path.join(home, "live-push-deferred.jsonl"), "utf8")).length > 0);
  });

  test("guardrails: a confirm verdict reaches the module as confirm", async (t) => {
    const { result } = await run(t, sensitiveRead("s-gc-ask"), { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "confirm" } });
    assert.equal(JSON.parse(result.stdout).test_decision, "confirm");
  });

  test("guardrails: rules that fail let the call run", async (t) => {
    const { result, logged } = await run(t, sensitiveRead("s-gc-fail"), { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } }, { env: { OMNODEX_TEST_CAPTURE: "throw" } });
    assert.equal(result.stdout, passOutput);
    assert.equal(logged.find((e) => e.event_type === "risk.enforcement_error").outcome, "allowed");
  });

  test("guardrails without a module (no subscription): nothing is stopped, findings recorded as shadow", async (t) => {
    const { result, logged } = await run(t, sensitiveRead("s-gc-nomod"), { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } }, { module: false });
    assert.equal(result.stdout, passOutput);
    const finding = findingsIn(logged).find((f) => f.rule_id === "RULE_SENSITIVE_PATH_READ");
    assert.equal(finding.enforcement.mode, "shadow");
    assert.equal(finding.enforcement.held, false);
  });

  test("shadow mode never stops a call, module or not", async (t) => {
    const { result } = await run(t, sensitiveRead("s-gc-shadow"), { mode: "shadow", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
    assert.equal(result.stdout, passOutput);
  });
}
