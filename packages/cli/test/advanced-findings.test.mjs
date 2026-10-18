/**
 * Advanced-tier findings on this machine.
 *
 * The local dashboard, `omnodex detect` and `omnodex report` show an
 * advanced finding's severity and where to read it, never its detail.
 * These tests confirm:
 *   1. No category, description, rule, sequence or evidence of an advanced
 *      finding leaves the dashboard server: snapshot, per-session API and
 *      live stream alike.
 *   2. The row stays, so counts and risk scores are unchanged.
 *   3. Community findings, and findings from logs that predate tiers, are
 *      shown as before.
 *   4. The placeholder says which: open the dashboard, or available with Pro.
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
  advancedFindingText,
  lockAdvancedFinding,
  lockAdvancedFindings,
} from "../dist/advanced-findings.js";

const AT = "2026-10-18T12:00:00.000Z";
const SECRET_TEXT = "Credential read, then sent to paste.example.net";

function event(overrides) {
  return { schema_version: 1, session_id: "sess-case", occurred_at: AT, recorded_at: AT, interceptor: "claude-code-hook", ...overrides };
}

const START = event({ event_id: "e0", event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] });
const CALL = event({ event_id: "e1", event_type: "tool.invoked", tool_call_id: "tc-1", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "ls" } });

const ADVANCED = event({
  event_id: "e-adv",
  event_type: "risk.detected",
  interceptor: "analyzer",
  severity: "CRITICAL",
  category: "credential_exfiltration",
  description: SECRET_TEXT,
  related_event_id: "tc-1",
  rule_id: "RULE_ADV_CREDENTIAL_SENT",
  rule_tier: "advanced",
  related_event_ids: ["tc-0", "tc-1"],
  evidence: { steps: [{ tool_call_id: "tc-0", role: "source", summary: "Read /home/case/.aws/credentials" }, { tool_call_id: "tc-1", role: "sink", summary: "Network call to paste.example.net" }] },
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

/** No trace of the advanced finding's detail in a serialized response. */
function assertNoDetail(text) {
  for (const fragment of [SECRET_TEXT, "credential_exfiltration", "RULE_ADV_CREDENTIAL_SENT", "paste.example.net", ".aws/credentials", "tc-0"]) {
    assert.ok(!text.includes(fragment), `"${fragment}" reached the page`);
  }
}

test("an advanced finding keeps its severity and call, and loses its detail", () => {
  const locked = lockAdvancedFinding(row(ADVANCED), false);
  assert.equal(locked.severity, "CRITICAL");
  assert.equal(locked.related_event_id, "tc-1");
  assert.equal(locked.detected_at, AT);
  assert.equal(locked.rule_tier, "advanced");
  assert.equal(locked.description, "Advanced finding, available with Omnodex Pro.");
  assert.equal(locked.category, "advanced");
  assert.match(locked.rule_id, /^advanced-[0-9a-f]{8}$/);
  assert.ok(!("evidence" in locked) && !("related_event_ids" in locked));
  assertNoDetail(JSON.stringify(locked));
});

test("two advanced rules on one call stay two distinct rows", () => {
  const a = lockAdvancedFinding(row(ADVANCED), true);
  const b = lockAdvancedFinding({ ...row(ADVANCED), rule_id: "RULE_ADV_OTHER" }, true);
  assert.notEqual(a.rule_id, b.rule_id);
});

test("community and untiered findings pass through unchanged", () => {
  const community = row(COMMUNITY);
  const old = row(UNTIERED);
  assert.equal(lockAdvancedFinding(community, false), community);
  assert.equal(lockAdvancedFinding(old, false), old);
  const snapshot = { risk_events: { s: [community, old] } };
  assert.equal(lockAdvancedFindings(snapshot, false), snapshot, "nothing to lock, same object");
});

test("the placeholder points an entitled installation at the dashboard", () => {
  assert.equal(advancedFindingText(true), "Advanced finding. Open your Omnodex dashboard to see it.");
  assert.equal(advancedFindingText(false), "Advanced finding, available with Omnodex Pro.");
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
  for (const e of [START, CALL, ADVANCED, COMMUNITY]) await projector.apply(e);
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

test("the snapshot carries the row without its detail, and scores are unchanged", async () => {
  const body = await get("/api/snapshot");
  assertNoDetail(body);
  const snapshot = JSON.parse(body);
  const rows = snapshot.risk_events["sess-case"];
  assert.equal(rows.length, 2, "both findings are still counted");
  assert.deepEqual(rows.map((r) => r.severity).sort(), ["CRITICAL", "HIGH"]);
  assert.ok(rows.some((r) => r.description === "Read of an SSH key"), "the community finding is shown in full");
  const [session] = snapshot.sessions;
  assert.equal(session.risk_score, 1.7, "CRITICAL 1.0 + HIGH 0.7, as before");
});

test("the per-session API carries no advanced detail", async () => {
  assertNoDetail(await get("/api/sessions/sess-case/risk-events"));
});

test("the placeholder follows the installation's entitlement", async () => {
  entitled = true;
  const rows = JSON.parse(await get("/api/snapshot")).risk_events["sess-case"];
  assert.ok(rows.some((r) => r.description === advancedFindingText(true)));
  entitled = false;
});

test("a live finding carries no advanced detail either", async () => {
  const received = await new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/api/events", headers: { host: `localhost:${port}` } }, (res) => {
      let buffer = "";
      res.on("data", (chunk) => {
        buffer += chunk;
        if (buffer.includes("risk_event.inserted")) {
          req.destroy();
          resolve(buffer);
        }
      });
      // Once connected, push the advanced finding as the live loop would.
      setTimeout(() => server.broadcast({ type: "risk_event.inserted", payload: row(ADVANCED) }), 50);
    });
    req.on("error", (err) => (err.code === "ECONNRESET" ? undefined : reject(err)));
  });
  assertNoDetail(received);
  assert.match(received, /Advanced finding, available with Omnodex Pro\./);
});
