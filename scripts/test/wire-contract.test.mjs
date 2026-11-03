/**
 * Wire contract: everything the client sends the hosted service is listed.
 *
 * Drives every sender against a recording fetch and compares each request
 * with scripts/wire-contract.json: the endpoint, whether it carries the
 * API token, and every field outside the ciphertext. A new endpoint or
 * field fails here until it is listed, with its reason.
 *
 * Marked values ride along: a session ID, a machine label, an event ID and
 * a piece of captured content. Each may appear only in the fields whose
 * entry says it carries it; captured content may appear nowhere, not even
 * in the bytes of an encrypted body.
 *
 * A source scan backs this up: every endpoint path in the client's source
 * is listed, and every file that makes a network request is a known sender.
 *
 * Run: node --test scripts/test/wire-contract.test.mjs
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs, readFileSync, readdirSync, statSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { EventLog } from "../../packages/event-log/dist/index.js";
import {
  SEALED_LABEL_RE,
  StreamingTransport,
  deriveLabelKey,
  deriveStreamingKey,
  openLabel,
  pushEventsToCloud,
  refreshGuardrailsModule,
  refreshRuleBundle,
  sendMonitoringHeartbeat,
  submitRuleSignals,
} from "../../packages/sync-encryptor/dist/index.js";
import { syncReadModel } from "../../packages/sync-encryptor/dist/sync-runner.js";
import { addAdvancedUsage, submitAdvancedUsage } from "../../packages/sync-encryptor/dist/advanced-usage.js";
import { collectRotatedToken, probeStreamToken, streamHasSecret } from "../../packages/sync-encryptor/dist/stream-credentials.js";
import { bytesToBase64, generateStreamKeyPair } from "../../packages/sync-encryptor/dist/hpke-event.js";
import { validateLicense } from "../../packages/license-client/dist/index.js";
import { createClaim } from "../../packages/cli/dist/connect.js";
import { pollForAuthorization, requestDeviceCode } from "../../packages/cli/dist/device-auth.js";
import { activePolls, handleConnect } from "../../packages/mcp-proxy/dist/connect-tool.js";
import { handleHookPayload, parseIngestConfig, postWithFetch } from "../../packages/hooks-provider/dist/container-hook.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const CONTRACT = JSON.parse(readFileSync(path.join(ROOT, "scripts", "wire-contract.json"), "utf8"));

const API = "https://api.example.test";
const SECRET = "wire contract case secret";

/** Marked values, and where each may show up. */
const MARKS = {
  event_id: "evt-wiremark-0001",
  machine_id: "c0ffee00c0ffee01",
  previous_machine_id: "0dd0dd0dd0dd0d01",
};
/** An agent session ID: it may leave the machine only inside ciphertext. */
const SESSION = "sess-wiremark-0001";
/** The user-set machine label: it may leave the machine only sealed. */
const LABEL = "wirelabel-case-laptop";
const CONTENT = "WIRECANARY-captured-content";

// ---------------------------------------------------------------------------
// Recording fetch
// ---------------------------------------------------------------------------

const LICENSE = {
  customer_id: "cust_case",
  tier: "pro",
  features: ["encrypted_sync", "live_streaming"],
  ttl_seconds: 3600,
};

/** A plausible answer per endpoint, enough for each sender to finish. */
function answer(method, pathname) {
  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  if (pathname === "/api/v1/stream/verifier") return method === "GET" ? json({ registered: true }) : json({ status: "registered" });
  if (pathname.startsWith("/api/v1/sync/segments/")) return json({}, 201);
  if (pathname === "/api/v1/sync/manifest") return json({ commit_id: "commit_case" });
  if (pathname === "/api/v1/sync/push") return json({ blob_id: "blob_case", received_at: new Date().toISOString(), payload_bytes: 1 }, 201);
  if (pathname === "/api/v1/sync/events") return json({ live: true });
  if (pathname === "/api/v1/license/validate") return json(LICENSE);
  if (pathname === "/api/v1/stream/collect-token") return json({ api_token: "omx_collected_case" });
  if (pathname === "/api/v1/connect/claim") {
    return json({ claim_token: "omx_claim_case", expires_at: new Date(Date.now() + 600_000).toISOString(), connect_url: "https://app.example.test/connect" });
  }
  if (pathname === "/api/v1/device/code") {
    return json({ device_code: "dc_case", user_code: "CASE-CODE", verification_url: "https://app.example.test/device", expires_in: 30, interval: 0 });
  }
  if (pathname === "/api/v1/device/token") return json({ api_token: "omx_device_case", customer_id: "cust_case" });
  if (pathname === "/api/v1/ingest/events") return json({ accepted: 1 }, 202);
  if (pathname === "/api/v1/rules/update" || pathname === "/api/v1/guardrails/update") return new Response(null, { status: 503 });
  if (pathname.startsWith("/api/v1/")) return json({});
  return new Response("not found", { status: 404 });
}

function headersOf(init) {
  const out = {};
  for (const [k, v] of new Headers(init?.headers ?? {}).entries()) out[k.toLowerCase()] = v;
  return out;
}

function bodyBytes(body) {
  if (body === undefined || body === null) return null;
  if (typeof body === "string") return Buffer.from(body, "utf8");
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  throw new Error(`unrecorded body type: ${Object.prototype.toString.call(body)}`);
}

function installRecorder(t) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = String(init.method ?? "GET").toUpperCase();
    calls.push({ method, url, headers: headersOf(init), body: bodyBytes(init.body) });
    return answer(method, url.pathname);
  };
  t.after(() => { globalThis.fetch = original; });
  return calls;
}

// ---------------------------------------------------------------------------
// Matching requests to the contract
// ---------------------------------------------------------------------------

const ENDPOINTS = Object.entries(CONTRACT.endpoints).map(([key, spec]) => {
  const [method, template] = key.split(" ");
  const names = [];
  const pattern = template.replace(/:([a-z_]+)/g, (_, name) => {
    names.push(name);
    return "([^/]+)";
  });
  return { key, method, template, names, re: new RegExp(`^${pattern}$`), spec };
});
function endpointFor(call) {
  for (const e of ENDPOINTS) {
    if (e.method !== call.method) continue;
    const m = e.re.exec(call.url.pathname);
    if (m) return { endpoint: e, params: Object.fromEntries(e.names.map((n, i) => [n, decodeURIComponent(m[i + 1])])) };
  }
  return null;
}

/** Leaf fields of a JSON value, keyed like "events[].event_id". */
function flatten(value, prefix, out) {
  if (Array.isArray(value)) {
    if (value.length === 0) out.push([`${prefix}[]`, ""]);
    for (const v of value) flatten(v, `${prefix}[]`, out);
  } else if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
  } else {
    out.push([prefix, value === null ? "" : String(value)]);
  }
  return out;
}

/** Every field of a request outside Authorization and Content-Type, with its values. */
function fieldsOf(call, params) {
  const fields = [];
  for (const [k, v] of Object.entries(params)) fields.push([`path:${k}`, v]);
  for (const [k, v] of call.url.searchParams) fields.push([`query:${k}`, v]);
  for (const [k, v] of Object.entries(call.headers)) {
    if (k === "authorization" || k === "content-type") continue;
    fields.push([`header:${k}`, v]);
  }
  if (call.body && call.body.length > 0) {
    let parsed;
    try {
      parsed = JSON.parse(call.body.toString("utf8"));
    } catch {
      parsed = undefined;
    }
    if (parsed === undefined) fields.push(["body:<binary>", ""]);
    else for (const [k, v] of flatten(parsed, "", [])) fields.push([`body:${k}`, v]);
  }
  return fields;
}

function checkCalls(calls) {
  const problems = [];
  const seen = new Map();
  for (const call of calls) {
    const where = `${call.method} ${call.url.pathname}`;
    const found = endpointFor(call);
    if (!found) {
      problems.push(`${where}: endpoint not in scripts/wire-contract.json`);
      continue;
    }
    const { endpoint, params } = found;
    const fieldsSeen = seen.get(endpoint.key) ?? new Set();
    seen.set(endpoint.key, fieldsSeen);

    const bearer = (call.headers.authorization ?? "").startsWith("Bearer ");
    if (bearer !== (endpoint.spec.auth === "bearer")) {
      problems.push(`${endpoint.key}: auth is "${endpoint.spec.auth}" in the contract, but the request ${bearer ? "carries" : "lacks"} a bearer token`);
    }

    // Captured content never leaves in a readable form, ciphertext included.
    const raw = [call.url.href, JSON.stringify(call.headers), call.body ? call.body.toString("latin1") : ""].join("\n");
    if (raw.includes(CONTENT)) problems.push(`${endpoint.key}: captured content went out readable`);
    if (raw.includes(SESSION)) problems.push(`${endpoint.key}: a session ID went out readable`);

    for (const [name, value] of fieldsOf(call, params)) {
      fieldsSeen.add(name);
      const spec = endpoint.spec.fields[name];
      if (!spec) {
        problems.push(`${endpoint.key}: field ${name} is not in the contract`);
        continue;
      }
      if (spec.class === "ciphertext") continue;
      const allowed = new Set(spec.carries ?? []);
      for (const [kind, mark] of Object.entries(MARKS)) {
        if (value.includes(mark) && !allowed.has(kind)) {
          problems.push(`${endpoint.key}: field ${name} carries ${kind}, which its entry does not allow`);
        }
      }
    }
  }
  return { problems, seen };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async function tempHome(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-wire-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

const AT = new Date().toISOString();
const event = (n, body) => ({
  schema_version: 1,
  event_id: n === 1 ? MARKS.event_id : `evt-other-${n}`,
  session_id: SESSION,
  occurred_at: AT,
  recorded_at: AT,
  interceptor: "claude-code-hook",
  ...body,
});
const EVENTS = [
  event(1, { event_type: "session.started", user: "case", project_path: `/home/case/${CONTENT}`, mcp_servers: [] }),
  event(2, {
    event_type: "tool.invoked",
    tool_call_id: "call-case-1",
    tool_name: "Read",
    mcp_server: "builtin",
    parameters: { file_path: `/home/case/repo/${CONTENT}.md` },
  }),
];

/** A connected Pro machine with a set machine label and recorded events. */
async function connectedHome(t) {
  const home = await tempHome(t);
  await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_test_case", passphrase: SECRET, api_url: API }));
  await fs.writeFile(path.join(home, "license-cache.json"), JSON.stringify({ response: LICENSE, fetched_at: Date.now() }));
  await fs.writeFile(path.join(home, "config.json"), JSON.stringify({ machine: { label: LABEL } }));
  // A machine that synced under the hostname-derived ID, not yet remapped.
  await fs.writeFile(path.join(home, "machine-id.json"), JSON.stringify({ id: MARKS.machine_id, previous: MARKS.previous_machine_id }));
  await fs.writeFile(path.join(home, "monitoring-check.json"), JSON.stringify({
    first_run_at: AT, last_run_at: AT, slots: { "claude-code|hooks": "ok", "claude-code|mcp": "ok" },
  }));
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  for (const e of EVENTS) await log.append(e);
  await log.close();
  return home;
}

function withEnv(t, vars) {
  const prior = {};
  for (const [k, v] of Object.entries(vars)) {
    prior[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  t.after(() => {
    for (const [k, v] of Object.entries(prior)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

async function until(check, ms = 5000) {
  const end = Date.now() + ms;
  while (!check()) {
    if (Date.now() > end) return false;
    await new Promise((r) => setTimeout(r, 10));
  }
  return true;
}

/** Runs every sender once against the recorder. */
async function exercise(t, calls) {
  const home = await connectedHome(t);
  withEnv(t, {
    OMNODEX_HOME: home,
    OMNODEX_API_TOKEN: undefined,
    OMNODEX_API_URL: undefined,
    OMNODEX_STREAM_SECRET: undefined,
    OMNODEX_SYNC_PASSPHRASE: undefined,
    OMNODEX_SYNC_SEGMENTS: undefined,
  });
  const opts = { home, apiUrl: API, apiToken: "omx_test_case", passphrase: SECRET };

  // Sync, both paths.
  await syncReadModel({ ...opts, customerId: "cust_case" });
  process.env.OMNODEX_SYNC_SEGMENTS = "0";
  await syncReadModel({ ...opts, customerId: "cust_case" });
  delete process.env.OMNODEX_SYNC_SEGMENTS;

  // Live push: a hook or the proxy, then the local dashboard.
  assert.equal(await pushEventsToCloud(EVENTS, home), true, "the live push did not send");
  const streaming = new StreamingTransport({
    apiBase: API, apiToken: "omx_test_case", keyId: "case0001", streamingKey: await deriveStreamingKey(SECRET, "cust_case"), home,
  });
  for (const e of EVENTS) await streaming.push(e);
  await streaming.stop();

  // Stream credentials and licensing.
  await collectRotatedToken(opts);
  await probeStreamToken(opts);
  await streamHasSecret(opts);
  await validateLicense({ apiBaseUrl: API, apiToken: "omx_test_case", cacheDir: home, force: true });

  // Counts and the heartbeat.
  await fs.writeFile(path.join(home, "rule-signals.json"), JSON.stringify({
    version: 1, pending: { [`${AT.slice(0, 10)}|rule_case|would_block`]: 3 },
  }));
  assert.equal(await submitRuleSignals(home, { apiUrl: API, apiToken: "omx_test_case" }), "submitted");
  await addAdvancedUsage(home, { evaluated: 5, findings: 1 });
  assert.equal(await submitAdvancedUsage(home, { apiUrl: API, apiToken: "omx_test_case" }), "submitted");
  assert.equal(await sendMonitoringHeartbeat(home, { apiUrl: API, apiToken: "omx_test_case" }), "sent");

  // Pro rule and guardrails refresh.
  await refreshRuleBundle(home);
  await refreshGuardrailsModule(home, { force: true });

  // Connecting from the CLI.
  await createClaim({ apiUrl: API, apiToken: "omx_test_case", passphrase: SECRET, platform: "claude-code" });
  const code = await requestDeviceCode({ apiUrl: API, passphrase: SECRET });
  await pollForAuthorization(API, code.deviceCode, { interval: 0, expiresIn: 30 });

  // Connecting from the MCP proxy: with a token, then without one.
  await handleConnect({ platform: "cowork-plugin" });
  await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "", passphrase: SECRET, api_url: API }));
  const polls = calls.filter((c) => c.url.pathname === "/api/v1/device/token").length;
  await handleConnect({ platform: "cowork-plugin" });
  await until(() => calls.filter((c) => c.url.pathname === "/api/v1/device/token").length > polls);
  for (const p of activePolls.values()) p.cancel();

  // Capture from a cloud agent container.
  const keys = await generateStreamKeyPair();
  const ingest = await parseIngestConfig({
    version: 1,
    ingest_token: "oxi_wirecontractcase0001",
    source_id: "src_case",
    key_id: keys.keyId,
    public_key: bytesToBase64(keys.publicKey),
    api_base: "http://127.0.0.1:9",
  });
  assert.ok(ingest, "ingest config rejected");
  const containerHome = await tempHome(t);
  const hook = { session_id: SESSION, cwd: `/home/case/${CONTENT}`, transcript_path: "/tmp/case.jsonl" };
  await handleHookPayload(
    { ...hook, hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "toolu_case", tool_input: { command: `cat ${CONTENT}` } },
    ingest,
    { home: containerHome, post: postWithFetch },
  );
  await handleHookPayload({ ...hook, hook_event_name: "Stop" }, ingest, { home: containerHome, post: postWithFetch });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("every request matches the wire contract", async (t) => {
  const calls = installRecorder(t);
  await exercise(t, calls);
  const { problems, seen } = checkCalls(calls);

  for (const e of ENDPOINTS) {
    const fieldsSeen = seen.get(e.key);
    if (!fieldsSeen) {
      problems.push(`${e.key}: listed but never sent; drive its sender in this test or remove it`);
      continue;
    }
    for (const [name, spec] of Object.entries(e.spec.fields)) {
      if (!spec.optional && !fieldsSeen.has(name)) problems.push(`${e.key}: field ${name} is listed but was not sent`);
    }
  }
  assert.deepEqual(problems, []);
});

test("the marked values reach the requests, so the checks above can see them", async (t) => {
  const calls = installRecorder(t);
  await exercise(t, calls);
  const text = calls.map((c) => [c.url.href, JSON.stringify(c.headers), c.body ? c.body.toString("latin1") : ""].join("\n")).join("\n");
  for (const [kind, mark] of Object.entries(MARKS)) assert.ok(text.includes(mark), `${kind} never appeared in any request`);
});

test("the machine label leaves the machine only sealed, and the stream secret opens it", async (t) => {
  const calls = installRecorder(t);
  await exercise(t, calls);
  // The proxy's connect without a token starts a new stream with a new secret.
  const config = JSON.parse(await fs.readFile(path.join(process.env.OMNODEX_HOME, "stream-config.json"), "utf8"));
  const keys = [await deriveLabelKey(SECRET), await deriveLabelKey(config.stream_secret ?? config.passphrase)];
  const open = async (s) => (await openLabel(keys[0], "machine_label", s)) ?? (await openLabel(keys[1], "machine_label", s));
  const sealed = [];
  for (const c of calls) {
    const raw = [c.url.href, JSON.stringify(c.headers), c.body ? c.body.toString("latin1") : ""].join("\n");
    assert.ok(!raw.includes(LABEL), `${c.method} ${c.url.pathname}: the machine label went out readable`);
    if (c.headers["x-omnodex-machine-label"]) sealed.push(c.headers["x-omnodex-machine-label"]);
    if (c.body && c.headers["content-type"] === "application/json") {
      const label = JSON.parse(c.body.toString("utf8")).machine_label;
      if (label) sealed.push(label);
    }
  }
  // The three sync requests, the claim, and a device code each from the CLI and the proxy.
  assert.ok(sealed.length >= 6, `only ${sealed.length} sealed labels sent`);
  for (const s of sealed) {
    assert.match(s, SEALED_LABEL_RE);
    assert.equal(await open(s), LABEL, s);
  }
  // The claim's platform leaves sealed too; the connect page opens it.
  const platforms = calls.filter((c) => c.url.pathname === "/api/v1/connect/claim").map((c) => JSON.parse(c.body.toString("utf8")).platform);
  assert.ok(platforms.length >= 2);
  for (const p of platforms) {
    assert.match(p, SEALED_LABEL_RE);
    assert.ok(["claude-code", "cowork-plugin"].includes(
      (await openLabel(keys[0], "platform", p)) ?? (await openLabel(keys[1], "platform", p))), p);
  }
  // One sync seals once for all its requests; each seal takes a fresh nonce.
  assert.ok(new Set(sealed).size >= 5, "sealed labels repeat across separate seals");
});

// ---------------------------------------------------------------------------
// Source scan
// ---------------------------------------------------------------------------

function sourceFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) sourceFiles(full, out);
    else if (/\.tsx?$/.test(name) && !name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

const SOURCES = readdirSync(path.join(ROOT, "packages")).flatMap((pkg) => {
  const src = path.join(ROOT, "packages", pkg, "src");
  try {
    return sourceFiles(src).map((f) => ({ rel: path.relative(ROOT, f).split(path.sep).join("/"), text: readFileSync(f, "utf8") }));
  } catch {
    return [];
  }
});

test("every endpoint path in the client's source is listed", () => {
  const listed = new Set(ENDPOINTS.map((e) => e.template.replace(/:[a-z_]+$/, "").replace(/\/$/, "")));
  for (const p of CONTRACT.documented_only.paths) listed.add(p);
  const missing = [];
  for (const { rel, text } of SOURCES) {
    for (const m of text.matchAll(/\/api\/v1\/[a-z0-9_/-]*[a-z0-9_]/g)) {
      if (!listed.has(m[0])) missing.push(`${rel}: ${m[0]}`);
    }
  }
  assert.deepEqual(missing, []);
});

test("every file that makes a network request is a known sender", () => {
  const known = new Set([...CONTRACT.senders, ...Object.keys(CONTRACT.other_requests.files)]);
  const network = /\bfetch\(|\?\? fetch\)|\bhttps?\.(get|request)\(/;
  const found = SOURCES.filter((s) => network.test(s.text)).map((s) => s.rel);
  assert.deepEqual(found.filter((f) => !known.has(f)), [], "new network code: list its requests in scripts/wire-contract.json");
  assert.deepEqual([...known].filter((f) => !found.includes(f)), [], "listed senders that no longer make requests");
});
