/**
 * Finding actions on the local dashboard: the entry an action makes, the
 * preview, and who may save what.
 *
 * The rule under test: this dashboard saves only an entry that tightens this
 * machine's policy. Anything that loosens it, and anything for the whole
 * account, writes nothing here, so an agent that can reach the dashboard's
 * port cannot turn protection down.
 *
 * Run: node --test packages/cli/test/dashboard-policy.test.mjs
 */

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as http from "node:http";
import os from "node:os";
import path from "node:path";
import { InMemoryReadModelStore } from "../../projection/dist/index.js";
import { DashboardServer } from "../dist/dashboard-server.js";
import { draftPolicy, savePolicy, parseDraftRequest, targetChoices } from "../dist/dashboard-policy.js";
import { commandForEntry, entryFromArgs } from "../dist/policy-command.js";
import { readUserEnforcement } from "@omnodex/analyzer/enforcement";

const NOW = new Date("2026-11-04T12:00:00.000Z");
const SESSION = "s1";
const CALL = "c1";
const FILE = "/home/case/proj/.env";

let home;
let store;
let guardrails;

const hooks = () => ({
  home: () => home,
  guardrailsEntitled: async () => guardrails,
  ruleSeverity: (id) => (id === "sensitive-path-read" ? "HIGH" : undefined),
  machineEntries: () => readUserEnforcement(home).policy ?? [],
  accountEntries: () => [],
  now: () => NOW,
  newId: () => "p-test",
});

async function seed(recent = true) {
  await store.upsertSession({
    session_id: SESSION, user: "case", project_path: "/home/case/proj", mcp_servers: [], interceptor: "claude-code-hook",
    started_at: NOW.toISOString(), ended_at: null, duration_ms: null, status: "in_progress",
    tool_call_count: 1, file_read_count: 0, file_write_count: 0, risk_score: 0, last_event_at: NOW.toISOString(), source_root: null,
  });
  await store.insertToolCall({
    tool_call_id: CALL, session_id: SESSION, tool_name: "Read", mcp_server: "builtin",
    parameters_json: JSON.stringify({ file_path: FILE }), started_at: NOW.toISOString(), ended_at: null,
    duration_ms: null, status: "success", response_bytes: null, error_message: null,
  });
  await store.insertRiskEvent({
    event_id: "e1", session_id: SESSION, related_event_id: CALL, severity: "HIGH", category: "sensitive-path-read",
    description: "read a secrets file", rule_id: "sensitive-path-read",
    detected_at: recent ? NOW.toISOString() : "2025-01-01T00:00:00.000Z",
  });
}

const req = (over = {}) => ({
  session_id: SESSION, rule_id: "sensitive-path-read", related_event_id: CALL, action: "block", scope: "machine", ...over,
});
const snap = async () => {
  const { readSnapshot } = await import("../../projection/dist/index.js");
  return readSnapshot(store);
};
const config = async () => JSON.parse(await fs.readFile(path.join(home, "omnodex-config.json"), "utf8").catch(() => "{}"));

beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-dashpolicy-case-"));
  store = new InMemoryReadModelStore();
  guardrails = true;
  await seed();
});
afterEach(async () => {
  await fs.rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

describe("drafting an action", () => {
  it("offers the rule and the path the call touched, and previews over the last 30 days", async () => {
    const d = await draftPolicy(await snap(), req({ action: "mute" }), hooks());
    assert.equal(d.choices[0].kind, "rule");
    assert.ok(d.choices.some((c) => c.kind === "path" && c.value === FILE));
    assert.equal(d.project, "/home/case/proj");
    assert.equal(d.own_severity, "HIGH");
    assert.equal(d.preview.reach, 1);
    assert.equal(d.preview.muted, 1);
  });

  it("does not count findings older than the window", async () => {
    store = new InMemoryReadModelStore();
    await seed(false);
    const d = await draftPolicy(await snap(), req({ action: "mute" }), hooks());
    assert.equal(d.preview.reach, 0);
  });

  it("builds the entry from the target the person chose", async () => {
    const d = await draftPolicy(await snap(), req({ action: "block", target: { kind: "path", value: FILE }, here: true }), hooks());
    assert.deepEqual(d.entry.match, { rule_id: "sensitive-path-read", target: { path: FILE }, project: "/home/case/proj" });
    assert.deepEqual(d.entry.effect, { verdict: "deny" });
  });

  it("returns null for a finding that is not there", async () => {
    assert.equal(await draftPolicy(await snap(), req({ related_event_id: "nope" }), hooks()), null);
  });

  it("asks for a different severity than the rule's own", async () => {
    const same = await draftPolicy(await snap(), req({ action: "severity", severity: "HIGH" }), hooks());
    assert.match(same.error, /already/);
    const none = await draftPolicy(await snap(), req({ action: "severity" }), hooks());
    assert.match(none.error, /choose/);
  });

  it("previews a lower severity as lowered", async () => {
    const d = await draftPolicy(await snap(), req({ action: "severity", severity: "LOW" }), hooks());
    assert.equal(d.preview.lowered, 1);
  });
});

describe("who may save what", () => {
  it("lets a machine entry that tightens be saved", async () => {
    for (const r of [req({ action: "block" }), req({ action: "hold" }), req({ action: "severity", severity: "CRITICAL" })]) {
      const d = await draftPolicy(await snap(), r, hooks());
      assert.equal(d.save_blocked, undefined, JSON.stringify(r));
    }
  });

  it("blocks saving anything that loosens, and offers the terminal command", async () => {
    for (const r of [req({ action: "allow" }), req({ action: "mute" }), req({ action: "severity", severity: "LOW" })]) {
      const d = await draftPolicy(await snap(), r, hooks());
      assert.equal(d.save_blocked, "loosens", JSON.stringify(r));
      assert.match(d.command, /^omnodex policy add --rule sensitive-path-read /);
    }
  });

  it("MUST_NOT_FIRE: saving a loosening entry writes nothing", async () => {
    for (const r of [req({ action: "allow" }), req({ action: "mute" }), req({ action: "severity", severity: "LOW" })]) {
      const out = await savePolicy(await snap(), r, hooks());
      assert.equal(out.blocked, "loosens");
    }
    assert.deepEqual(await config(), {});
  });

  it("MUST_NOT_FIRE: saving a whole-account entry writes nothing, and hands over a hosted link", async () => {
    const out = await savePolicy(await snap(), req({ action: "block", scope: "account" }), hooks());
    assert.equal(out.blocked, "account");
    assert.deepEqual(await config(), {});
    const d = await draftPolicy(await snap(), req({ action: "mute", scope: "account", target: { kind: "path", value: FILE } }), hooks());
    assert.ok(d.hosted_url.startsWith("https://dashboard.omnodex.com/policies#add="));
    const payload = JSON.parse(Buffer.from(d.hosted_url.split("#add=")[1], "base64url").toString("utf8"));
    assert.equal(payload.v, 1);
    assert.deepEqual(payload.entry.match.target, { path: FILE });
    assert.deepEqual(payload.entry.effect, { mute: true });
    assert.equal(payload.entry.id, undefined, "the hosted page assigns the id");
  });

  it("keeps block and hold behind the plan that includes guardrails", async () => {
    guardrails = false;
    const out = await savePolicy(await snap(), req({ action: "block" }), hooks());
    assert.equal(out.blocked, "pro");
    assert.deepEqual(await config(), {});
    const sev = await savePolicy(await snap(), req({ action: "severity", severity: "CRITICAL" }), hooks());
    assert.ok(sev.saved, "a higher severity is free");
  });

  it("saves a block through the same file `omnodex policy add` writes, which the machine then reads", async () => {
    const out = await savePolicy(await snap(), req({ action: "block", target: { kind: "path", value: FILE } }), hooks());
    assert.equal(out.saved.id, "p-test");
    const entries = readUserEnforcement(home).policy;
    assert.equal(entries.length, 1);
    assert.deepEqual(entries[0].effect, { verdict: "deny" });
    assert.deepEqual(entries[0].match.target, { path: FILE });
  });
});

describe("the command shown for a loosening entry", () => {
  it("round-trips through `policy add`'s own parser", () => {
    const e = entryFromArgs(
      ["--rule", "r1", "--path", "/tmp/a b/c", "--project", "/home/case/p q", "--mute", "--note", "it's fine"],
      { now: NOW, id: "x" },
    ).entry;
    for (const windows of [false, true]) {
      const cmd = commandForEntry(e, windows);
      assert.match(cmd, /^omnodex policy add /);
      assert.ok(cmd.includes(windows ? "'it''s fine'" : "'it'\\''s fine'"));
    }
    const plain = entryFromArgs(["--rule", "r1", "--tool", "Bash", "--server", "builtin", "--set-severity", "LOW"], { now: NOW, id: "x" }).entry;
    const back = entryFromArgs(commandForEntry(plain, false).split(" ").slice(3), { now: NOW, id: "x" }).entry;
    assert.deepEqual(back.match, plain.match);
    assert.deepEqual(back.effect, plain.effect);
  });
});

describe("reading a request", () => {
  it("refuses what is not a finding or an action", () => {
    assert.equal(typeof parseDraftRequest(null), "string");
    assert.equal(typeof parseDraftRequest({}), "string");
    assert.equal(typeof parseDraftRequest(req({ action: "delete" })), "string");
    assert.equal(typeof parseDraftRequest(req({ scope: "cloud" })), "string");
    assert.equal(typeof parseDraftRequest(req({ severity: "SEVERE" })), "string");
    assert.equal(typeof parseDraftRequest(req({ target: { kind: "regex", value: "x" } })), "string");
    assert.equal(parseDraftRequest(req()).scope, "machine");
  });

  it("offers no targets for a finding whose call was not recorded", () => {
    assert.deepEqual(targetChoices(undefined), [{ kind: "rule", value: "" }]);
  });
});

describe("over HTTP", () => {
  let server;
  let assetsDir;
  beforeEach(async () => {
    assetsDir = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-dashpolicy-assets-"));
    await fs.writeFile(path.join(assetsDir, "dashboard.html"), "<!doctype html><title>t</title>");
    server = new DashboardServer({ store, port: 0, assetsDir, policy: hooks() });
    await server.ready;
  });
  afterEach(async () => {
    await server.close();
    await fs.rm(assetsDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  function call(method, pathname, body, headers = {}) {
    return new Promise((resolve, reject) => {
      const r = http.request(
        { host: "127.0.0.1", port: server.port, path: pathname, method, headers: { host: `localhost:${server.port}`, ...headers } },
        (res) => {
          let text = "";
          res.on("data", (c) => (text += c));
          res.on("end", () => resolve({ status: res.statusCode, json: text ? JSON.parse(text) : null }));
        },
      );
      r.on("error", reject);
      if (body !== undefined) r.write(typeof body === "string" ? body : JSON.stringify(body));
      r.end();
    });
  }
  const json = { "content-type": "application/json" };

  it("reports whether actions are offered", async () => {
    assert.equal((await call("GET", "/api/info")).json.policy, true);
  });

  it("drafts, and saves a tightening entry", async () => {
    const d = await call("POST", "/api/policy/draft", req({ action: "hold" }), json);
    assert.equal(d.status, 200);
    assert.equal(d.json.entry.effect.verdict, "confirm");
    const s = await call("POST", "/api/policy/save", req({ action: "hold" }), json);
    assert.equal(s.status, 200);
    assert.equal(readUserEnforcement(home).policy.length, 1);
  });

  it("MUST_NOT_FIRE: refuses to save a loosening entry or an account entry, and writes nothing", async () => {
    const a = await call("POST", "/api/policy/save", req({ action: "allow" }), json);
    assert.equal(a.status, 403);
    assert.equal(a.json.blocked, "loosens");
    const b = await call("POST", "/api/policy/save", req({ action: "block", scope: "account" }), json);
    assert.equal(b.status, 403);
    assert.deepEqual(await config(), {});
  });

  it("refuses a request from another origin, a GET, a non-JSON body and an oversized one", async () => {
    assert.equal((await call("POST", "/api/policy/save", req(), { ...json, origin: "https://evil.example" })).status, 403);
    assert.equal((await call("GET", "/api/policy/save")).status, 405);
    assert.equal((await call("POST", "/api/policy/save", "x=1", { "content-type": "application/x-www-form-urlencoded" })).status, 415);
    assert.equal((await call("POST", "/api/policy/draft", "{not json", json)).status, 400);
    assert.equal((await call("POST", "/api/policy/draft", " ".repeat(70_000), json)).status, 413);
    assert.deepEqual(await config(), {});
  });

  it("answers 404 for a finding that is not there", async () => {
    assert.equal((await call("POST", "/api/policy/draft", req({ related_event_id: "nope" }), json)).status, 404);
  });

  it("has no policy routes when the process lends no policy", async () => {
    const bare = new DashboardServer({ store, port: 0, assetsDir });
    await bare.ready;
    try {
      const status = await new Promise((resolve) => {
        const r = http.request(
          { host: "127.0.0.1", port: bare.port, path: "/api/policy/save", method: "POST", headers: { host: `localhost:${bare.port}`, ...json } },
          (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); },
        );
        r.end("{}");
      });
      assert.equal(status, 404);
    } finally {
      await bare.close();
    }
  });
});
