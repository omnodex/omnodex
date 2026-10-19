/**
 * Advanced-tier findings on this machine.
 *
 * The local dashboard, `omnodex detect` and `omnodex report` say how many
 * advanced findings there are and where to read them, nothing more. These
 * tests confirm:
 *   1. No advanced finding leaves the dashboard server, not even as a masked
 *      row pointing at its call: snapshot, per-session API and live stream.
 *   2. A count per session does, and sessions are rescored from what is shown,
 *      so a score's band does not give a hidden finding's severity away.
 *   3. Community findings, and findings from logs that predate tiers, are
 *      shown as before.
 *   4. The count says which: open the dashboard, or available with Pro.
 */

import { test, before, after } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { InMemoryReadModelStore, Projector } from "../../projection/dist/index.js";
import { DashboardServer } from "../dist/dashboard-server.js";
import {
  advancedEntitled,
  advancedFindingsText,
  shownFindings,
  withoutAdvancedFindings,
} from "../dist/advanced-findings.js";
import { selectView, ALL_SESSIONS } from "../dist/dashboard-model/index.js";

const AT = "2026-10-18T12:00:00.000Z";
const SECRET_TEXT = "Credential read, then sent to paste.example.net";

function event(overrides) {
  return { schema_version: 1, session_id: "sess-case", occurred_at: AT, recorded_at: AT, interceptor: "claude-code-hook", ...overrides };
}

const START = event({ event_id: "e0", event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] });
const CALL = event({ event_id: "e1", event_type: "tool.invoked", tool_call_id: "tc-1", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "ls" } });
const SINK = event({ event_id: "e2", event_type: "tool.invoked", tool_call_id: "tc-sink", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "make" } });

const ADVANCED = event({
  event_id: "e-adv",
  event_type: "risk.detected",
  interceptor: "analyzer",
  severity: "CRITICAL",
  category: "credential_exfiltration",
  description: SECRET_TEXT,
  related_event_id: "tc-sink",
  rule_id: "RULE_ADV_CREDENTIAL_SENT",
  rule_tier: "advanced",
  related_event_ids: ["tc-0", "tc-sink"],
  evidence: { steps: [{ tool_call_id: "tc-0", role: "source", summary: "Read /home/case/.aws/credentials" }, { tool_call_id: "tc-sink", role: "sink", summary: "Network call to paste.example.net" }] },
});
const COMMUNITY = event({
  event_id: "e-com", event_type: "risk.detected", interceptor: "analyzer", severity: "HIGH",
  category: "sensitive_path_read", description: "Read of an SSH key", related_event_id: "tc-1",
  rule_id: "RULE_SENSITIVE_PATH_READ", rule_tier: "community",
});
const UNTIERED = { ...COMMUNITY, event_id: "e-old", rule_id: "RULE_OLD", rule_tier: undefined };

const row = (e) => ({
  event_id: e.event_id, session_id: e.session_id, related_event_id: e.related_event_id, severity: e.severity,
  category: e.category, description: e.description, rule_id: e.rule_id, detected_at: e.occurred_at,
  ...(e.rule_tier ? { rule_tier: e.rule_tier } : {}),
  ...(e.related_event_ids ? { related_event_ids: e.related_event_ids } : {}),
  ...(e.evidence ? { evidence: e.evidence } : {}),
});

/** No trace of the advanced finding in a response's findings: not its text, rule, severity or call. */
function assertNoAdvanced(rows) {
  const text = JSON.stringify(rows);
  for (const fragment of [SECRET_TEXT, "credential_exfiltration", "RULE_ADV_CREDENTIAL_SENT", "paste.example.net", ".aws/credentials", "tc-0", "tc-sink", "CRITICAL", "e-adv"]) {
    assert.ok(!text.includes(fragment), `"${fragment}" reached the page`);
  }
}

test("advanced findings are removed and counted per session", () => {
  const out = withoutAdvancedFindings({ sessions: [], risk_events: { s: [row(ADVANCED), row(COMMUNITY), row(UNTIERED)] } }, false);
  assert.deepEqual(out.risk_events.s.map((r) => r.event_id), ["e-com", "e-old"]);
  assert.deepEqual(out.advanced, { hidden: { s: 1 }, entitled: false });
  assertNoAdvanced(out.risk_events);
  assert.deepEqual(shownFindings([row(ADVANCED), row(COMMUNITY)]).map((r) => r.event_id), ["e-com"]);
});

test("the count says where to read them", () => {
  assert.equal(advancedFindingsText(1, false), "1 more finding from the advanced rules, available with Omnodex Pro.");
  assert.equal(advancedFindingsText(3, true), "3 more findings from the advanced rules. Open your Omnodex dashboard to see them.");
});

test("a session with only advanced findings is still listed, with its count", () => {
  const snapshot = {
    sessions: [{ session_id: "only-adv", started_at: AT, tool_call_count: 0, file_read_count: 0, file_write_count: 0 }],
    tool_calls: {}, file_events: {}, risk_events: { "only-adv": [] },
    advanced: { hidden: { "only-adv": 2 }, entitled: true },
  };
  const view = selectView(snapshot, ALL_SESSIONS);
  assert.equal(view.sessions.length, 1);
  assert.equal(view.hiddenAdvanced, 2);
  assert.equal(view.advancedEntitled, true);
});

test("entitlement comes from the cached license tier", async (t) => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-entitled-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  assert.equal(advancedEntitled(home), false, "no cache");
  for (const [tier, expected] of [["pro", true], ["enterprise", true], ["hosted", false], ["free", false]]) {
    await fs.writeFile(path.join(home, "license-cache.json"), JSON.stringify({ response: { tier } }));
    assert.equal(advancedEntitled(home), expected, tier);
  }
  await fs.writeFile(path.join(home, "license-cache.json"), "not json");
  assert.equal(advancedEntitled(home), false, "unreadable cache");
});

// ---------------------------------------------------------------------------
// The dashboard server
// ---------------------------------------------------------------------------

let assetsDir;
let server;
let store;
let port;
let entitled = false;

before(async () => {
  assetsDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-dash-adv-"));
  await fs.writeFile(path.join(assetsDir, "dashboard.html"), "<!doctype html><title>t</title>");
  store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  for (const e of [START, CALL, SINK, ADVANCED, COMMUNITY]) await projector.apply(e);
  server = new DashboardServer({ store, port: 0, assetsDir, advancedEntitled: () => entitled });
  await server.ready;
  port = server.port;
});

after(async () => {
  await server.close();
  await fs.rm(assetsDir, { recursive: true, force: true });
});

function get(pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: pathname, headers: { host: `localhost:${port}` } }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve(body));
    }).on("error", reject);
  });
}

test("the snapshot holds no advanced finding, only its count, and the session is rescored", async () => {
  const snapshot = JSON.parse(await get("/api/snapshot"));
  assertNoAdvanced(snapshot.risk_events);
  const rows = snapshot.risk_events["sess-case"];
  assert.deepEqual(rows.map((r) => r.description), ["Read of an SSH key"], "the community finding is shown in full");
  assert.deepEqual(snapshot.advanced, { hidden: { "sess-case": 1 }, entitled: false });
  const [session] = snapshot.sessions;
  assert.equal(session.risk_score, 0.7, "the HIGH that is shown; the hidden CRITICAL does not count here");
});

test("the per-session API holds no advanced finding", async () => {
  assertNoAdvanced(JSON.parse(await get("/api/sessions/sess-case/risk-events")));
});

test("the count follows the installation's entitlement", async () => {
  entitled = true;
  assert.equal(JSON.parse(await get("/api/snapshot")).advanced.entitled, true);
  entitled = false;
});

test("a live advanced finding is not sent; the page is told to reload instead", async () => {
  const received = await new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/api/events", headers: { host: `localhost:${port}` } }, (res) => {
      let buffer = "";
      res.on("data", (chunk) => {
        buffer += chunk;
        if (buffer.includes("read_model.changed")) {
          req.destroy();
          resolve(buffer);
        }
      });
      // Once connected, push the advanced finding as the live loop would.
      setTimeout(() => server.broadcast({ type: "risk_event.inserted", payload: row(ADVANCED) }), 50);
    });
    req.on("error", (err) => (err.code === "ECONNRESET" ? undefined : reject(err)));
  });
  assert.ok(!received.includes("risk_event.inserted"));
  assertNoAdvanced(received);
});
