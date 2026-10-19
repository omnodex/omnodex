// Validation: the proxy judges each recorded event against the rules.
//
// createProxyEvaluation queues events and judges them off the response
// path, loads the analyzer only on the first tool call, writes and pushes
// findings like events, and survives an evaluator that throws. The last
// tests run a real MCPProxy over HTTP against the mock upstream.
//
// Run: node --test packages/mcp-proxy/test/evaluation.test.mjs

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { createProxyEvaluation, loadProxyEvaluator } from "../dist/evaluation.js";
import { MCPProxy } from "../dist/mcp-proxy.js";
import { ProxyConfigSchema } from "../dist/config.js";
import { installModule } from "../../analyzer/test/helpers/make-module.mjs";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

let home;
beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-proxy-eval-"));
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

let seq = 0;
function base(sessionId, at = new Date()) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-pe-${seq}`,
    session_id: sessionId,
    occurred_at: at.toISOString(),
    recorded_at: at.toISOString(),
    interceptor: "mcp-proxy",
  };
}
const started = (sessionId) => ({
  ...base(sessionId),
  event_type: "session.started",
  user: "case",
  project_path: "/home/case/project",
  mcp_servers: ["filesystem"],
});
const call = (sessionId, args, server = "filesystem", at) => ({
  ...base(sessionId, at),
  event_type: "tool.invoked",
  tool_call_id: `tc-pe-${seq}`,
  tool_name: `${server}__read_file`,
  mcp_server: server,
  parameters: args,
});

function harness(overrides = {}) {
  const written = [];
  const pushed = [];
  const errors = [];
  const evaluation = createProxyEvaluation({
    home,
    emit: async (e) => {
      written.push(e);
    },
    push: (e) => pushed.push(e),
    onError: (err) => errors.push(err),
    ...overrides,
  });
  return { evaluation, written, pushed, errors };
}

const rules = (events) => events.map((e) => e.rule_id).sort();

// ---------------------------------------------------------------------------

test("a proxied call that matches a per-event rule yields one finding, written and pushed", async () => {
  const { evaluation, written, pushed } = harness();
  evaluation.observe(started("sess-a"));
  evaluation.observe(call("sess-a", { path: "/etc/passwd" }));
  await evaluation.drain();

  const findings = written.filter((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].event_type, "risk.detected");
  assert.equal(findings[0].session_id, "sess-a");
  assert.deepEqual(rules(pushed), rules(written));
});

test("monitor mode (the default): proxied findings carry no enforcement record", async () => {
  const { evaluation, written } = harness();
  evaluation.observe(started("sess-m"));
  evaluation.observe(call("sess-m", { path: "/etc/passwd" }));
  await evaluation.drain();
  const finding = written.find((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ");
  assert.equal(finding.enforcement, undefined);
});

test("shadow mode: a proxied finding records what enforcement would have done", async () => {
  await writeFile(
    path.join(home, "omnodex-config.json"),
    JSON.stringify({ enforcement: { mode: "shadow", rules: { RULE_SENSITIVE_PATH_READ: "confirm" } } }),
  );
  const { evaluation, written, pushed } = harness();
  evaluation.observe(started("sess-s"));
  evaluation.observe(call("sess-s", { path: "/etc/passwd" }));
  await evaluation.drain();
  const finding = written.find((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ");
  assert.deepEqual(finding.enforcement, {
    mode: "shadow",
    candidate: "alert_only",
    action: "confirm",
    held: false,
    source: "user-rule",
  });
  assert.deepEqual(pushed.find((e) => e.rule_id === "RULE_SENSITIVE_PATH_READ").enforcement, finding.enforcement);
});

test("a burst of calls trips the rate rule once", async () => {
  const { evaluation, written } = harness();
  evaluation.observe(started("sess-burst"));
  const t0 = Date.now();
  for (let i = 0; i < 55; i++) {
    evaluation.observe(call("sess-burst", { path: `/home/case/project/f${i}` }, "filesystem", new Date(t0 + i * 100)));
  }
  await evaluation.drain();
  assert.equal(written.filter((e) => e.rule_id === "RULE_UNBOUNDED_CONSUMPTION_BURST").length, 1);
});

test("a new MCP server is reported once per machine, not once per proxy launch", async () => {
  const first = harness();
  first.evaluation.observe(started("sess-1"));
  first.evaluation.observe(call("sess-1", {}, "plane"));
  await first.evaluation.drain();
  assert.equal(first.written.filter((e) => e.rule_id === "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER").length, 1);

  const relaunched = harness();
  relaunched.evaluation.observe(started("sess-2"));
  relaunched.evaluation.observe(call("sess-2", {}, "plane"));
  await relaunched.evaluation.drain();
  assert.equal(relaunched.written.filter((e) => e.rule_id === "RULE_SUPPLY_CHAIN_NEW_MCP_SERVER").length, 0);
});

test("the analyzer is not loaded until the first tool call", async () => {
  let loads = 0;
  const { evaluation } = harness({
    loadEvaluator: async (h) => {
      loads++;
      return loadProxyEvaluator(h);
    },
  });
  evaluation.observe(started("sess-lazy"));
  await evaluation.drain();
  assert.equal(loads, 0);
  evaluation.observe(call("sess-lazy", {}));
  await evaluation.drain();
  assert.equal(loads, 1);
});

test("observe returns before any rule runs", async () => {
  let evaluated = 0;
  const { evaluation } = harness({
    loadEvaluator: async () => ({
      evaluate: () => {
        evaluated++;
        return [];
      },
    }),
  });
  evaluation.observe(call("sess-sync", {}));
  assert.equal(evaluated, 0, "judged synchronously");
  await evaluation.drain();
  assert.equal(evaluated, 1);
});

test("an evaluator that throws, or fails to load, is reported and swallowed", async () => {
  const throwing = harness({
    loadEvaluator: async () => ({
      evaluate: () => {
        throw new Error("rule engine exploded");
      },
    }),
  });
  throwing.evaluation.observe(call("sess-x", {}));
  throwing.evaluation.observe(call("sess-x", {}));
  await throwing.evaluation.drain();
  assert.equal(throwing.written.length, 0);
  assert.equal(throwing.errors.length, 2);

  const unloadable = harness({ loadEvaluator: async () => { throw new Error("no analyzer"); } });
  unloadable.evaluation.observe(call("sess-y", {}));
  await unloadable.evaluation.drain();
  assert.equal(unloadable.errors.length, 1);
});

test("findings the evaluator wrote are not judged again", async () => {
  let seen = 0;
  const { evaluation } = harness({
    loadEvaluator: async () => ({ evaluate: () => { seen++; return []; } }),
  });
  evaluation.observe(call("sess-z", {}));
  evaluation.observe({ ...base("sess-z"), event_type: "risk.detected", interceptor: "analyzer",
    severity: "LOW", category: "x", description: "x", related_event_id: "tc", rule_id: "R" });
  await evaluation.drain();
  assert.equal(seen, 1);
});

// ---------------------------------------------------------------------------
// A real proxy over HTTP
// ---------------------------------------------------------------------------

function makeConfig(env = {}) {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "mock",
        transport: "stdio",
        command: process.execPath,
        args: [MOCK_SERVER],
        env: { MOCK_TOOLS: JSON.stringify(["ping"]), MOCK_RESULT_TEXT: "pong", ...env },
      },
    ],
  });
}

async function callThroughProxy(loadEvaluator, config = makeConfig()) {
  const proxy = new MCPProxy(config, {
    home,
    projectPath: "/home/case/project",
    http: { host: "127.0.0.1", port: 0 },
    hooks: { pushFn: async () => undefined, ...(loadEvaluator ? { loadEvaluator } : {}) },
  });
  const events = [];
  const stop = await proxy.start((e) => {
    events.push(e);
  });
  let text;
  try {
    const client = new Client({ name: "evaluation-test", version: "0.0.0" }, {});
    await client.connect(new StreamableHTTPClientTransport(new URL(proxy.httpUrl())));
    for (let i = 0; i < 100; i++) {
      const { tools } = await client.listTools();
      if (tools.some((t) => t.name === "mock__ping")) break;
      await new Promise((r) => setTimeout(r, 50));
    }
    const result = await client.callTool({ name: "mock__ping", arguments: { path: "/etc/passwd" } });
    text = result.content[0].text;
    await client.close();
  } finally {
    await stop();
  }
  await proxy.whenClosed();
  return { events, text };
}

test("MCPProxy records a finding for a proxied call that matches a rule", async () => {
  const { events, text } = await callThroughProxy();
  assert.match(text, /^pong/);
  const risk = events.filter((e) => e.event_type === "risk.detected" && e.rule_id === "RULE_SENSITIVE_PATH_READ");
  assert.equal(risk.length, 1);
  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.equal(risk[0].related_event_id, invoked.tool_call_id);
});

test("MCPProxy answers the tool call normally when the evaluator throws", async () => {
  const { events, text } = await callThroughProxy(async () => ({
    evaluate: () => {
      throw new Error("rule engine exploded");
    },
  }));
  assert.match(text, /^pong/);
  assert.equal(events.filter((e) => e.event_type === "risk.detected").length, 0);
  assert.ok(events.some((e) => e.event_type === "tool.completed"));
});

// Guardrails: in guardrails mode the proxy decides a call before forwarding it.

/** The stand-in guardrails module, opened through the development key variables. */
function withModule(t) {
  const { env } = installModule(home);
  Object.assign(process.env, env);
  t.after(() => {
    for (const k of Object.keys(env)) delete process.env[k];
  });
}

async function guardrailsRun(enforcement) {
  await writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement }));
  const callLog = path.join(home, "upstream-calls.log");
  const run = await callThroughProxy(undefined, makeConfig({ MOCK_CALL_LOG: callLog }));
  const upstreamCalls = (await readFile(callLog, "utf8").catch(() => "")).split("\n").filter(Boolean);
  return { ...run, upstreamCalls };
}

test("guardrails: a denied call never reaches the upstream, and the agent gets the module's reason", async (t) => {
  withModule(t);
  const { events, text, upstreamCalls } = await guardrailsRun({ mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
  assert.deepEqual(upstreamCalls, []);
  assert.equal(text, "test: deny RULE_SENSITIVE_PATH_READ");
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.status, "error");
  assert.match(completed.error_message, /Blocked by Omnodex guardrails \(RULE_SENSITIVE_PATH_READ\)/);
  const risk = events.filter((e) => e.event_type === "risk.detected" && e.rule_id === "RULE_SENSITIVE_PATH_READ");
  assert.equal(risk.length, 1, "written once, by the decision");
  assert.equal(risk[0].enforcement.held, true);
  const invoked = events.find((e) => e.event_type === "tool.invoked");
  assert.ok(events.indexOf(invoked) < events.indexOf(risk[0]), "the call before its finding");
});

test("guardrails: a confirm verdict holds the call too, since the proxy cannot prompt", async (t) => {
  withModule(t);
  const { text, upstreamCalls } = await guardrailsRun({ mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "confirm" } });
  assert.deepEqual(upstreamCalls, []);
  assert.equal(text, "test: confirm RULE_SENSITIVE_PATH_READ");
});

test("guardrails without a module (no subscription): the call is forwarded as usual", async () => {
  const { text, upstreamCalls, events } = await guardrailsRun({ mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
  assert.match(text, /^pong/);
  assert.deepEqual(upstreamCalls, ["ping"]);
  const finding = events.find((e) => e.event_type === "risk.detected" && e.rule_id === "RULE_SENSITIVE_PATH_READ");
  assert.equal(finding.enforcement.mode, "shadow");
});

test("guardrails: a call no setting holds is forwarded as usual", async (t) => {
  withModule(t);
  const { text, upstreamCalls, events } = await guardrailsRun({ mode: "guardrails" });
  assert.match(text, /^pong/);
  assert.deepEqual(upstreamCalls, ["ping"]);
  assert.equal(events.filter((e) => e.event_type === "risk.detected" && e.rule_id === "RULE_SENSITIVE_PATH_READ").length, 1);
});

test("shadow mode never stops a call", async () => {
  const { text, upstreamCalls } = await guardrailsRun({ mode: "shadow", rules: { RULE_SENSITIVE_PATH_READ: "deny" } });
  assert.match(text, /^pong/);
  assert.deepEqual(upstreamCalls, ["ping"]);
});

test("guardrails fail open: rules that fail let the call through and record why", async (t) => {
  withModule(t);
  await writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement: { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } } }));
  const { createProxyGuardrails } = await import("../dist/guardrails.js");
  const guardrails = createProxyGuardrails({
    home,
    newEventId: () => "evt-guard-err",
    judge: async (_events, { onError }) => {
      onError(new Error("rules failed to load"));
      return [];
    },
  });
  const event = { ...call("sess-g", { path: "/etc/passwd" }), tool_call_id: "tc-guard" };
  const decision = await guardrails.decide(event, event);
  assert.equal(decision.blocked, false);
  assert.equal(decision.events[0].event_type, "risk.enforcement_error");
  assert.equal(decision.events[0].outcome, "allowed");

  await writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement: { mode: "guardrails", on_error: "block" } }));
  const closed = await guardrails.decide(event, event);
  assert.equal(closed.blocked, true);
  assert.equal(closed.reason, "test: could not check");
});

test("guardrails: a redacted call is judged on what was sent, but its findings are left to the redacted evaluation", async (t) => {
  withModule(t);
  await writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement: { mode: "guardrails", rules: { RULE_SENSITIVE_PATH_READ: "deny" } } }));
  const { createProxyGuardrails } = await import("../dist/guardrails.js");
  const guardrails = createProxyGuardrails({ home });
  const full = call("sess-r", { path: "/etc/passwd" });
  const logged = { ...full, parameters: { path: "[REDACTED]" } };
  const decision = await guardrails.decide(full, logged);
  assert.equal(decision.blocked, true);
  assert.deepEqual(decision.events, []);
});

test("monitor mode: deciding a call does not load the rules", async () => {
  const { createProxyGuardrails } = await import("../dist/guardrails.js");
  let judged = false;
  const guardrails = createProxyGuardrails({ home, judge: async () => { judged = true; return []; } });
  const event = call("sess-m2", { path: "/etc/passwd" });
  assert.deepEqual(await guardrails.decide(event, event), { blocked: false, events: [] });
  assert.equal(judged, false);
});
