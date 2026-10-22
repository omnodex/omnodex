/**
 * MCP server and tool drift rule tests.
 *
 *   RULE_MCP_SERVER_UPDATED          -- version or config changed (LOW)
 *   RULE_MCP_SERVER_TOOLS_CHANGED    -- tools added or removed, same version and config (LOW)
 *   RULE_MCP_TOOL_DEFINITION_CHANGED -- a tool's description or schema changed, same version and config (MEDIUM)
 *
 * Each case feeds a baseline server.observed and then a second one through
 * the evaluator with machine state, as the proxy and the background pass do.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createEvaluator } from "../../dist/evaluator.js";
import { memoryMachineState, openMachineState } from "../../dist/machine-state.js";

let n = 0;
const newEventId = () => `risk-${++n}`;

function observed(overrides = {}) {
  const tools = overrides.tools ?? [
    { name: "send_email", fingerprint: "a".repeat(32) },
    { name: "list_templates", fingerprint: "b".repeat(32) },
  ];
  return {
    schema_version: 1,
    event_id: `obs-${++n}`,
    session_id: overrides.session_id ?? "sess-drift",
    occurred_at: overrides.occurred_at ?? new Date(Date.UTC(2026, 9, 21, 12, 0, n)).toISOString(),
    recorded_at: "2026-10-21T12:00:00.000Z",
    interceptor: "mcp-proxy",
    event_type: "server.observed",
    mcp_server: overrides.mcp_server ?? "mail",
    transport: overrides.transport ?? "stdio",
    trigger: overrides.trigger ?? "connect",
    config_fingerprint: overrides.config_fingerprint ?? "c".repeat(32),
    ...(overrides.reported === null ? {} : { reported: overrides.reported ?? { name: "mail-server", version: "1.0.15" } }),
    ...(overrides.installed_version === null ? {} : { installed_version: overrides.installed_version ?? "1.0.15" }),
    tool_list_fingerprint: overrides.tool_list_fingerprint ?? tools.map((t) => t.fingerprint[0]).join("").padEnd(32, "0"),
    tools,
  };
}

function evaluator(machineState = memoryMachineState()) {
  return createEvaluator({ host: "batch", newEventId, machineState });
}

/** Findings for `next` after `baseline`, as [rule_id, severity, description]. */
function drift(baseline, next) {
  const ev = evaluator();
  assert.deepEqual(ev.evaluate(baseline), [], "a first observation is a baseline");
  return ev.evaluate(next).map((f) => [f.rule_id, f.severity, f.description, f.related_event_id]);
}

const BASE = observed();

// ---------------------------------------------------------------------------
// MUST_FIRE
// ---------------------------------------------------------------------------

test("MUST_FIRE: a reported version change is an update (LOW)", () => {
  const findings = drift(BASE, observed({ reported: { name: "mail-server", version: "1.0.16" }, installed_version: "1.0.16" }));
  assert.equal(findings.length, 1);
  const [rule, severity, description] = findings[0];
  assert.equal(rule, "RULE_MCP_SERVER_UPDATED");
  assert.equal(severity, "LOW");
  assert.match(description, /reported version 1\.0\.15 to 1\.0\.16/);
  assert.match(description, /installed version 1\.0\.15 to 1\.0\.16/);
});

test("MUST_FIRE: an installed version change with the reported version unchanged is an update", () => {
  // An unpinned npx package updated underneath a server that always reports the same version.
  const [[rule, , description]] = drift(BASE, observed({ installed_version: "1.0.16" }));
  assert.equal(rule, "RULE_MCP_SERVER_UPDATED");
  assert.match(description, /installed version 1\.0\.15 to 1\.0\.16/);
  assert.doesNotMatch(description, /reported version/);
});

test("MUST_FIRE: a config change is an update, and lists tool changes with it", () => {
  const [[rule, , description]] = drift(BASE, observed({
    config_fingerprint: "d".repeat(32),
    tools: [{ name: "send_email", fingerprint: "e".repeat(32) }, { name: "list_templates", fingerprint: "b".repeat(32) }],
  }));
  assert.equal(rule, "RULE_MCP_SERVER_UPDATED");
  assert.match(description, /configuration entry changed/);
  assert.match(description, /changed tools: send_email/);
});

test("MUST_FIRE: a tool added without a version change (LOW)", () => {
  const findings = drift(BASE, observed({ tools: [...BASE.tools, { name: "forward_all", fingerprint: "f".repeat(32) }] }));
  assert.deepEqual(findings.map(([r, s]) => [r, s]), [["RULE_MCP_SERVER_TOOLS_CHANGED", "LOW"]]);
  assert.match(findings[0][2], /now offers forward_all/);
});

test("MUST_FIRE: a tool removed without a version change", () => {
  const [[rule, , description]] = drift(BASE, observed({ tools: [BASE.tools[0]] }));
  assert.equal(rule, "RULE_MCP_SERVER_TOOLS_CHANGED");
  assert.match(description, /no longer offers list_templates/);
});

test("MUST_FIRE: a description changed without a version change is a definition change (MEDIUM)", () => {
  const findings = drift(BASE, observed({ tools: [{ name: "send_email", fingerprint: "9".repeat(32) }, BASE.tools[1]] }));
  assert.equal(findings.length, 1);
  const [rule, severity, description] = findings[0];
  assert.equal(rule, "RULE_MCP_TOOL_DEFINITION_CHANGED");
  assert.equal(severity, "MEDIUM");
  assert.match(description, /send_email/);
});

test("MUST_FIRE: a change announced mid-session says so", () => {
  const [[, , description]] = drift(BASE, observed({
    trigger: "list_changed",
    tools: [{ name: "send_email", fingerprint: "9".repeat(32) }, BASE.tools[1]],
  }));
  assert.match(description, /announced while in use/);
});

test("MUST_FIRE: added and changed tools under the same version raise both findings", () => {
  const findings = drift(BASE, observed({
    tools: [{ name: "send_email", fingerprint: "9".repeat(32) }, BASE.tools[1], { name: "forward_all", fingerprint: "f".repeat(32) }],
  }));
  assert.deepEqual(findings.map(([r]) => r).sort(), ["RULE_MCP_SERVER_TOOLS_CHANGED", "RULE_MCP_TOOL_DEFINITION_CHANGED"]);
});

test("MUST_FIRE: the finding points at the observation event", () => {
  const next = observed({ installed_version: "2.0.0" });
  const [[, , , related]] = drift(BASE, next);
  assert.equal(related, next.event_id);
});

test("MUST_FIRE: the baseline survives a restart through the machine state file", (t) => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-drift-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  assert.deepEqual(evaluator(openMachineState(home, { seedRoots: [] })).evaluate(observed()), []);
  const later = evaluator(openMachineState(home, { seedRoots: [] })).evaluate(observed({ installed_version: "1.0.16" }));
  assert.deepEqual(later.map((f) => f.rule_id), ["RULE_MCP_SERVER_UPDATED"]);
});

// ---------------------------------------------------------------------------
// MUST_NOT_FIRE
// ---------------------------------------------------------------------------

test("MUST_NOT_FIRE: the first observation of a server", () => {
  assert.deepEqual(evaluator().evaluate(observed()), []);
});

test("MUST_NOT_FIRE: an identical reconnect, or the same observation from another session", () => {
  assert.deepEqual(drift(BASE, observed()), []);
  assert.deepEqual(drift(BASE, observed({ session_id: "sess-other" })), []);
});

test("MUST_NOT_FIRE: a version that becomes unknown is not a change", () => {
  // The npx cache lookup is best effort; failing once is not an update.
  assert.deepEqual(drift(BASE, observed({ installed_version: null })), []);
  assert.deepEqual(drift(BASE, observed({ reported: null })), []);
});

test("MUST_NOT_FIRE: each change is reported once; the new observation is the baseline", () => {
  const ev = evaluator();
  ev.evaluate(observed());
  assert.equal(ev.evaluate(observed({ installed_version: "1.0.16" })).length, 1);
  assert.deepEqual(ev.evaluate(observed({ installed_version: "1.0.16" })), []);
});

test("MUST_NOT_FIRE: an older observation replayed after a newer one", () => {
  const ev = evaluator();
  ev.evaluate(observed({ occurred_at: "2026-10-21T12:00:00.000Z", installed_version: "1.0.16" }));
  assert.deepEqual(ev.evaluate(observed({ occurred_at: "2026-10-01T12:00:00.000Z", installed_version: "1.0.15" })), []);
});

test("MUST_NOT_FIRE: servers with the same name on different transports are separate", () => {
  const ev = evaluator();
  ev.evaluate(observed());
  assert.deepEqual(ev.evaluate(observed({ transport: "http", config_fingerprint: "d".repeat(32), installed_version: null })), []);
});

test("MUST_NOT_FIRE: the hook host does not run drift rules", () => {
  const ev = createEvaluator({ host: "hook", newEventId, machineState: memoryMachineState() });
  ev.evaluate(observed());
  assert.deepEqual(ev.evaluate(observed({ installed_version: "9.9.9" })), []);
});

test("MUST_FIRE: a host leaving machine rules to the capture path does not move the baseline first", () => {
  // The live dashboard tails the log and leaves proxy-captured events to the
  // proxy. If it recorded the observation, the proxy would then see no change.
  const state = memoryMachineState();
  const tail = evaluator(state);
  const proxy = evaluator(state);
  proxy.evaluate(observed());
  const next = observed({ installed_version: "1.0.16" });
  assert.deepEqual(tail.evaluate(next, { classes: ["event"] }), []);
  assert.deepEqual(proxy.evaluate(next).map((f) => f.rule_id), ["RULE_MCP_SERVER_UPDATED"]);
});

test("MUST_FIRE: a drift finding carries the change as structured evidence, with no call steps", () => {
  const ev = evaluator();
  ev.evaluate(observed());
  const [finding] = ev.evaluate(observed({
    trigger: "list_changed",
    tools: [{ name: "send_email", fingerprint: "9".repeat(32) }, BASE.tools[1]],
  }));
  assert.deepEqual(finding.evidence.steps, []);
  assert.deepEqual(finding.evidence.drift, {
    server: "mail",
    transport: "stdio",
    change: "definition",
    mid_session: true,
    config_changed: false,
    tools_added: [],
    tools_removed: [],
    tools_changed: ["send_email"],
  });
  const [update] = (() => {
    const e2 = evaluator();
    e2.evaluate(observed());
    return e2.evaluate(observed({ installed_version: "1.0.16", tools: [...BASE.tools, { name: "forward_all", fingerprint: "f".repeat(32) }] }));
  })();
  assert.equal(update.evidence.drift.change, "updated");
  assert.deepEqual(update.evidence.drift.installed_version, { from: "1.0.15", to: "1.0.16" });
  assert.deepEqual(update.evidence.drift.tools_added, ["forward_all"]);
});
