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
import { mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { createProxyEvaluation, loadProxyEvaluator } from "../dist/evaluation.js";
import { MCPProxy } from "../dist/mcp-proxy.js";
import { ProxyConfigSchema } from "../dist/config.js";

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

function makeConfig() {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "mock",
        transport: "stdio",
        command: process.execPath,
        args: [MOCK_SERVER],
        env: { MOCK_TOOLS: JSON.stringify(["ping"]), MOCK_RESULT_TEXT: "pong" },
      },
    ],
  });
}

async function callThroughProxy(loadEvaluator) {
  const proxy = new MCPProxy(makeConfig(), {
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
