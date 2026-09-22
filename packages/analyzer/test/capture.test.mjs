/**
 * Capture-time evaluation tests.
 *
 * judgeCaptured is what the hook shims call: event-class rules only, under
 * a time cap, never rejecting. classesLeftAfterCapture and evaluate()'s
 * class filter are what a later host (the dashboard's live loop) uses to
 * avoid writing a finding the capture path already wrote. The shims' own
 * end-to-end cases are in each provider package.
 *
 * Run: node --test packages/analyzer/test/capture.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  judgeCaptured,
  captureDetectEnabled,
  captureTimeoutMs,
  CaptureTimeoutError,
  CAPTURE_HOSTS,
  DEFAULT_CAPTURE_TIMEOUT_MS,
} from "../dist/capture.js";
import { createEvaluator, classesLeftAfterCapture, HOST_CLASSES } from "../dist/evaluator.js";

let counter = 0;
const newEventId = () => `evt-cap-${++counter}`;

let seq = 0;
function tool(overrides = {}) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-tool-${seq}`,
    session_id: "sess-cap",
    occurred_at: new Date().toISOString(),
    recorded_at: new Date().toISOString(),
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-${seq}`,
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: {},
    ...overrides,
  };
}
const sensitive = (o = {}) => tool({ parameters: { file_path: "/etc/shadow" }, ...o });
const mcpCall = (server, o = {}) =>
  tool({ tool_name: `mcp__${server}__list`, mcp_server: server, ...o });
const rules = (findings) => findings.map((f) => f.rule_id);

// ---------------------------------------------------------------------------

describe("judgeCaptured", () => {
  it("returns the per-event findings for a captured call", async () => {
    const call = sensitive();
    const findings = await judgeCaptured([call], { newEventId });
    assert.deepEqual(rules(findings), ["RULE_SENSITIVE_PATH_READ"]);
    assert.equal(findings[0].related_event_id, call.tool_call_id);
  });

  it("runs event-class rules only", async () => {
    const findings = await judgeCaptured([mcpCall("plane")], { newEventId });
    assert.ok(!rules(findings).includes("RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"));
  });

  it("does not load the evaluator for a batch with no tool call", async () => {
    let loads = 0;
    const load = async () => {
      loads++;
      return import("../dist/evaluator.js");
    };
    const started = { ...tool(), event_type: "session.started", user: "case", project_path: "/tmp", mcp_servers: [] };
    assert.deepEqual(await judgeCaptured([started], { newEventId, load }), []);
    assert.equal(loads, 0);
  });

  it("gives up at the time cap and reports it", async () => {
    const errors = [];
    const t0 = Date.now();
    const findings = await judgeCaptured([sensitive()], {
      newEventId,
      timeoutMs: 50,
      load: () => new Promise(() => {}),
      onError: (err) => errors.push(err),
    });
    assert.deepEqual(findings, []);
    assert.ok(Date.now() - t0 < 1000);
    assert.equal(errors.length, 1);
    assert.ok(errors[0] instanceof CaptureTimeoutError);
  });

  it("does not run the rules once the cap has passed", async () => {
    let created = 0;
    let release;
    const gate = new Promise((r) => (release = r));
    const findings = await judgeCaptured([sensitive()], {
      newEventId,
      timeoutMs: 20,
      load: async () => {
        await gate;
        return { createEvaluator: () => (created++, { evaluate: () => [] }) };
      },
    });
    assert.deepEqual(findings, []);
    release();
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(created, 0);
  });

  it("swallows and reports a failed load or a throwing evaluator", async () => {
    const errors = [];
    const onError = (err) => errors.push(err);
    assert.deepEqual(
      await judgeCaptured([sensitive()], { newEventId, onError, load: async () => { throw new Error("no analyzer"); } }),
      [],
    );
    assert.deepEqual(
      await judgeCaptured([sensitive()], {
        newEventId,
        onError,
        load: async () => ({ createEvaluator: () => ({ evaluate: () => { throw new Error("rule engine exploded"); } }) }),
      }),
      [],
    );
    assert.deepEqual(errors.map((e) => e.message), ["no analyzer", "rule engine exploded"]);
  });
});

describe("capture settings", () => {
  it("is on unless OMNODEX_CAPTURE_DETECT=0", () => {
    assert.equal(captureDetectEnabled({}), true);
    assert.equal(captureDetectEnabled({ OMNODEX_CAPTURE_DETECT: "1" }), true);
    assert.equal(captureDetectEnabled({ OMNODEX_CAPTURE_DETECT: "0" }), false);
  });

  it("reads the time cap, falling back to the default on anything unusable", () => {
    assert.equal(captureTimeoutMs({}), DEFAULT_CAPTURE_TIMEOUT_MS);
    assert.equal(captureTimeoutMs({ OMNODEX_CAPTURE_DETECT_TIMEOUT_MS: "250" }), 250);
    assert.equal(captureTimeoutMs({ OMNODEX_CAPTURE_DETECT_TIMEOUT_MS: "0" }), DEFAULT_CAPTURE_TIMEOUT_MS);
    assert.equal(captureTimeoutMs({ OMNODEX_CAPTURE_DETECT_TIMEOUT_MS: "soon" }), DEFAULT_CAPTURE_TIMEOUT_MS);
  });
});

// ---------------------------------------------------------------------------

describe("classesLeftAfterCapture", () => {
  it("leaves session and machine rules for hook events, nothing for proxy events", () => {
    for (const [interceptor, host] of Object.entries(CAPTURE_HOSTS)) {
      const left = classesLeftAfterCapture(tool({ interceptor }), "batch");
      assert.deepEqual(left, host === "hook" ? ["session", "machine"] : [], interceptor);
    }
  });

  it("leaves everything for events no capture path judges", () => {
    assert.deepEqual(classesLeftAfterCapture(tool({ interceptor: "mock" }), "batch"), [...HOST_CLASSES.batch]);
  });
});

describe("evaluate with a class filter", () => {
  it("skips the per-event rules a hook already ran but keeps the rest", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const call = sensitive({ tool_name: "mcp__vault__read", mcp_server: "vault" });
    const unfiltered = createEvaluator({ host: "batch", newEventId }).evaluate(call);
    assert.ok(rules(unfiltered).includes("RULE_SENSITIVE_PATH_READ"));
    const out = ev.evaluate(call, { classes: classesLeftAfterCapture(call, "batch") });
    assert.deepEqual(rules(out), ["RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"]);
  });

  it("emits nothing for a proxy event but still takes it into session state", () => {
    const ev = createEvaluator({ host: "batch", newEventId });
    const proxied = mcpCall("plane", { interceptor: "mcp-proxy" });
    assert.deepEqual(ev.evaluate(proxied, { classes: classesLeftAfterCapture(proxied, "batch") }), []);
    // The server is now known for the session, so an unfiltered call does not re-fire.
    assert.ok(!rules(ev.evaluate(mcpCall("plane"))).includes("RULE_SUPPLY_CHAIN_NEW_MCP_SERVER"));
  });
});
