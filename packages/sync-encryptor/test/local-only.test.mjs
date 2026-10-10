/**
 * Events recorded while uploads are paused never leave the machine: not by
 * live push from a hook or proxy, not by the local dashboard's live stream,
 * and not in a blob or segment sync, even when the local dashboard's read
 * model already holds them.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import { webcrypto } from "node:crypto";
import { gunzipSync } from "node:zlib";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog, applyCapturePause, startPause } from "../../event-log/dist/index.js";
import { Projector, SqliteReadModelStore } from "../../projection/dist/index.js";
import {
  ENVELOPE_VERSION_GZIP,
  StreamingTransport,
  decodeEnvelope,
  decrypt,
  deriveKey,
  pushEventsToCloud,
} from "../dist/index.js";
import { syncReadModel } from "../dist/sync-runner.js";

const SECRET = "TOP-SECRET-PARAM-case";
const SECRET_PHRASE = "correct horse battery staple";
const AT = new Date().toISOString();

function ev(sessionId, n, body) {
  return {
    schema_version: 1,
    event_id: `${sessionId}-e${n}`,
    session_id: sessionId,
    occurred_at: AT,
    recorded_at: AT,
    interceptor: "claude-code-hook",
    ...body,
  };
}

const start = (sid) => ev(sid, 0, { event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] });
const call = (sid, n, value) => ev(sid, n, {
  event_type: "tool.invoked",
  tool_call_id: `${sid}-call-${n}`,
  tool_name: "Read",
  mcp_server: "builtin",
  parameters: { file_path: `/home/case/repo/${value}` },
});

async function tempHome(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-localonly-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

/** Writes the visible session, then a session recorded under a sync pause. */
async function recordUnderPause(home) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  for (const e of [start("visible"), call("visible", 1, "visible.md")]) await log.append(e);
  const { markers } = await startPause(home, "sync", { untilMs: null });
  for (const m of markers) await log.append(m);
  const paused = await applyCapturePause([start("hidden"), call("hidden", 1, SECRET)], home);
  for (const e of paused) await log.append(e);
  // A finding a later detection pass wrote about the hidden call, without
  // the local-only flag: the sync must still leave it out.
  await log.append(ev("hidden", 2, {
    interceptor: "analyzer",
    event_type: "risk.detected",
    severity: "HIGH",
    category: "sensitive_path_read",
    description: `read ${SECRET}`,
    related_event_id: "hidden-call-1",
    rule_id: "rule_case",
  }));
  await log.close();
  return { paused };
}

function withFetch(t, handler) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: init?.body ? String(init.body) : "" });
    return handler(String(url), init);
  };
  t.after(() => { globalThis.fetch = original; });
  return calls;
}

test("live push from a hook or proxy skips local-only events", async (t) => {
  const home = await tempHome(t);
  await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({
    api_token: "omx_test_case", stream_secret: SECRET_PHRASE, api_url: "https://api.example.test",
  }));
  await fs.writeFile(path.join(home, "license-cache.json"), JSON.stringify({
    response: { customer_id: "cust_case", tier: "hosted", features: ["live_streaming"], ttl_seconds: 3600 },
    fetched_at: Date.now(),
  }));
  const calls = withFetch(t, async () => new Response(JSON.stringify({ live: true }), { status: 200 }));

  const visible = call("visible", 1, "visible.md");
  const hidden = { ...call("hidden", 1, SECRET), local_only: true };
  assert.equal(await pushEventsToCloud([hidden], home), false);
  assert.equal(calls.length, 0, "a batch of only local-only events made a request");

  assert.equal(await pushEventsToCloud([visible, hidden], home), true);
  assert.equal(calls.length, 1);
  const sent = JSON.parse(calls[0].body).events.map((e) => e.event_id);
  assert.deepEqual(sent, [visible.event_id]);

  // While uploads are paused, an event a writer forgot to flag stays home
  // too; the pause marker goes out.
  const { markers } = await startPause(home, "sync", { untilMs: null });
  assert.equal(await pushEventsToCloud([call("late", 1, SECRET), ...markers], home), true);
  const lastSent = JSON.parse(calls.at(-1).body).events.map((e) => e.event_id);
  assert.deepEqual(lastSent, markers.map((m) => m.event_id));
});

test("the local dashboard's live stream skips local-only events", async (t) => {
  const home = await tempHome(t);
  const calls = withFetch(t, async () => new Response(JSON.stringify({ live: true }), { status: 200 }));
  const key = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const transport = new StreamingTransport({
    apiBase: "https://api.example.test", apiToken: "omx_test_case", keyId: "case0001", streamingKey: key, home,
  });
  await transport.push({ ...call("hidden", 1, SECRET), local_only: true });
  await transport.push(call("visible", 1, "visible.md"));
  await transport.stop();
  const sent = calls.flatMap((c) => JSON.parse(c.body).events.map((e) => e.event_id));
  assert.deepEqual(sent, ["visible-e1"]);
});

/** A sync API that keeps every upload body. */
async function startSyncServer() {
  const bodies = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      bodies.push(Buffer.concat(chunks));
      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ blob_id: "blob_case_1", received_at: new Date().toISOString(), payload_bytes: 1 }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    bodies,
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => server.close(r)),
  };
}

/** Every encrypted upload, decrypted back to its JSON text. */
async function openUploads(bodies) {
  const texts = [];
  for (const body of bodies) {
    let env;
    try {
      env = decodeEnvelope(new Uint8Array(body));
    } catch {
      continue; // not an envelope (a commit or manifest request)
    }
    const key = await deriveKey(SECRET_PHRASE, env.salt);
    let plain = Buffer.from(await decrypt(key, env.iv, env.ciphertext));
    if (env.version === ENVELOPE_VERSION_GZIP) plain = gunzipSync(plain);
    texts.push(plain.toString("utf8"));
  }
  return texts;
}

for (const mode of ["segments", "blob"]) {
  test(`a ${mode} sync leaves out local-only events and findings about them`, async (t) => {
    const home = await tempHome(t);
    const api = await startSyncServer();
    t.after(() => api.close());
    const prev = process.env.OMNODEX_SYNC_SEGMENTS;
    if (mode === "blob") process.env.OMNODEX_SYNC_SEGMENTS = "0";
    else delete process.env.OMNODEX_SYNC_SEGMENTS;
    t.after(() => {
      if (prev === undefined) delete process.env.OMNODEX_SYNC_SEGMENTS;
      else process.env.OMNODEX_SYNC_SEGMENTS = prev;
    });

    await recordUnderPause(home);
    // The local dashboard has already built its read model with everything.
    const local = new SqliteReadModelStore({ dbPath: path.join(home, "traces.db") });
    await local.init();
    const all = new EventLog({ root: path.join(home, "event-log") });
    await all.init();
    await new Projector(local).replay(all.readAll());
    await all.close();
    assert.ok((await local.listSessions()).some((s) => s.session_id === "hidden"));
    await local.close();

    await syncReadModel({
      home, apiUrl: api.url, apiToken: "omx_test_case", passphrase: SECRET_PHRASE, customerId: "cust_case",
    });

    const uploads = await openUploads(api.bodies);
    assert.ok(uploads.length > 0, "nothing was uploaded");
    assert.ok(uploads.some((u) => u.includes("visible.md")), "the visible session was not uploaded");
    for (const u of uploads) {
      assert.ok(!u.includes(SECRET), "a local-only event or a finding about one was uploaded");
      assert.ok(!u.includes("\"hidden\""), "the session recorded under the pause was uploaded");
    }

    // The local dashboard's model is untouched.
    const after = new SqliteReadModelStore({ dbPath: path.join(home, "traces.db") });
    await after.init();
    assert.ok((await after.listSessions()).some((s) => s.session_id === "hidden"));
    await after.close();
  });
}
