// Segmented sync: which segments a sync uploads, what each holds, what is
// committed, and what the local manifest records, across the cases a
// machine meets over time.
//
// Run: node --test packages/sync-encryptor/test/segment-sync.test.mjs

import { describe, it, before, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { gunzipSync } from "node:zlib";
import { argon2id } from "hash-wasm";
import { InMemoryReadModelStore, Projector } from "../../projection/dist/index.js";
import { EventLog } from "../../event-log/dist/index.js";
import {
  syncSegments,
  decodeEnvelope,
  MissingSegmentsError,
  SEGMENT_MANIFEST_FILE,
} from "../dist/index.js";
import { syncReadModel } from "../dist/sync-runner.js";

const PASSPHRASE = "case-segment-passphrase";
const SALT = new Uint8Array(16).fill(3);
const DAY = 86_400_000;
const NOW = Date.parse("2026-10-09T12:00:00.000Z");
const iso = (t) => new Date(t).toISOString();

let key;
before(async () => {
  const bytes = await argon2id({ password: PASSPHRASE, salt: SALT, parallelism: 1, iterations: 3, memorySize: 65536, hashLength: 32, outputType: "binary" });
  key = await webcrypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["decrypt"]);
});

async function open(envelope) {
  const { iv, ciphertext } = decodeEnvelope(envelope);
  const pt = new Uint8Array(await webcrypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  return JSON.parse(gunzipSync(pt).toString("utf8"));
}

// ---------------------------------------------------------------------------
// A machine's activity, projected into an in-memory read model
// ---------------------------------------------------------------------------

let n = 0;
const ev = (sid, at, body) => ({
  schema_version: 1, event_id: `e${++n}`, session_id: sid, occurred_at: iso(at), recorded_at: iso(at),
  interceptor: "claude-code-hook", ...body,
});

async function addSession(projector, sid, at, { calls = 1, padding = 0 } = {}) {
  await projector.apply(ev(sid, at, { event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] }));
  for (let i = 0; i < calls; i++) {
    await projector.apply(ev(sid, at + i, {
      event_type: "tool.invoked", tool_call_id: `${sid}-c${i}`, tool_name: "Bash", mcp_server: "",
      parameters: { command: "echo " + "x".repeat(padding) },
    }));
  }
}

async function addFinding(projector, sid, at, toolCallId) {
  await projector.apply({
    ...ev(sid, at, {}), interceptor: "analyzer", event_type: "risk.detected", severity: "HIGH",
    category: "sensitive_path_read", description: "late finding", related_event_id: toolCallId, rule_id: "rule_late",
  });
}

/** The cloud's side: uploads, the committed list, and switches to make it fail. */
function fakeCloud() {
  const cloud = {
    uploads: [],          // [{ id, envelope, meta }]
    stored: new Map(),    // id -> envelope
    current: [],
    commits: 0,
    failCommit: false,
    forget: null,         // ids the cloud no longer holds
    async putSegment(id, envelope, meta) {
      cloud.uploads.push({ id, envelope, meta });
      cloud.stored.set(id, envelope);
      return envelope.byteLength;
    },
    async commit(ids) {
      if (cloud.failCommit) throw new Error("sync commit failed: HTTP 503");
      const missing = ids.filter((id) => !cloud.stored.has(id) || cloud.forget?.has(id));
      if (missing.length) throw new MissingSegmentsError(missing);
      cloud.commits++;
      cloud.current = [...ids];
      return `commit-${cloud.commits}`;
    },
  };
  return cloud;
}

let home, store, projector, cloud;
beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-segments-"));
  store = new InMemoryReadModelStore();
  projector = new Projector(store);
  cloud = fakeCloud();
});
afterEach(async () => {
  await fs.rm(home, { recursive: true, force: true });
});

const sync = (extra = {}) => syncSegments({
  store, transport: cloud, passphrase: PASSPHRASE, kdfSalt: SALT, customerId: "cust_case",
  apiUrl: "https://api.example.test", machineId: "case-machine", machineLabel: "case laptop", home, now: NOW, ...extra,
});
const manifest = async () => JSON.parse(await fs.readFile(path.join(home, SEGMENT_MANIFEST_FILE), "utf8"));
const sessionsIn = async (upload) => (await open(upload.envelope)).session_ids;
const newUploads = (before) => cloud.uploads.slice(before);

// ---------------------------------------------------------------------------

describe("segmented sync", () => {
  it("first sync: one segment holding every session, committed, and the manifest saved", async () => {
    await addSession(projector, "s1", NOW - 3 * DAY);
    await addSession(projector, "s2", NOW - 2 * DAY);
    const r = await sync();

    assert.equal(cloud.uploads.length, 1);
    const payload = await open(cloud.uploads[0].envelope);
    assert.deepEqual(payload.session_ids, ["s1", "s2"]);
    assert.equal(payload.tool_calls.s2.length, 1);
    assert.equal(payload.payload_version, 2);
    assert.deepEqual(cloud.uploads[0].meta, {
      machineId: "case-machine", machineLabel: "case laptop", sessions: 2,
      firstAt: iso(NOW - 3 * DAY), lastAt: iso(NOW - 2 * DAY),
    });
    assert.match(cloud.uploads[0].id, /^[A-Za-z0-9_-]{22}$/);
    assert.deepEqual(cloud.current, [cloud.uploads[0].id]);
    assert.deepEqual(r, {
      commitId: "commit-1", sessionsIncluded: ["s1", "s2"], segments: 1, uploaded: 1,
      uploadedBytes: cloud.uploads[0].envelope.byteLength, totalBytes: cloud.uploads[0].envelope.byteLength,
      largestBytes: cloud.uploads[0].envelope.byteLength, payloadBytes: r.payloadBytes,
    });

    const m = await manifest();
    assert.deepEqual(m.segments.map((s) => [s.id, s.sessions, s.sealed]), [[cloud.uploads[0].id, ["s1", "s2"], false]]);
    assert.match(m.sessions.s1.hash, /^[0-9a-f]{64}$/);
    // The manifest records ids and hashes, never content.
    assert.ok(!JSON.stringify(m).includes("/home/case/repo"));
  });

  it("an unchanged sync uploads nothing and commits nothing", async () => {
    await addSession(projector, "s1", NOW - DAY);
    await sync();
    const r = await sync();
    assert.equal(cloud.uploads.length, 1);
    assert.equal(cloud.commits, 1);
    assert.equal(r.uploaded, 0);
    assert.equal(r.commitId, "commit-1");
  });

  it("a new session rewrites only the open segment", async () => {
    await addSession(projector, "s1", NOW - 5 * DAY, { padding: 300 });
    await addSession(projector, "s2", NOW - 4 * DAY, { padding: 300 });
    await addSession(projector, "s3", NOW - 3 * DAY, { padding: 300 });
    await sync({ sealBytes: 1000 });
    const sealed = (await manifest()).segments.filter((s) => s.sealed);
    assert.ok(sealed.length >= 1, "some segment sealed");

    const before = cloud.uploads.length;
    await addSession(projector, "s4", NOW - DAY, { padding: 10 });
    await sync({ sealBytes: 1000 });
    const fresh = newUploads(before);
    assert.equal(fresh.length, 1);
    assert.ok((await sessionsIn(fresh[0])).includes("s4"));
    // Sealed segments keep their ids and stay listed.
    for (const s of sealed) assert.ok(cloud.current.includes(s.id));
  });

  it("seals the open segment once it passes the seal size, and starts a new one", async () => {
    await addSession(projector, "s1", NOW - 3 * DAY, { padding: 600 });
    await addSession(projector, "s2", NOW - 2 * DAY, { padding: 600 });
    await addSession(projector, "s3", NOW - 1 * DAY, { padding: 600 });
    await sync({ sealBytes: 1500 });
    const m = await manifest();
    assert.ok(m.segments.length >= 2);
    assert.deepEqual(m.segments.flatMap((s) => s.sessions), ["s1", "s2", "s3"]);
    assert.equal(m.segments.filter((s) => !s.sealed).length <= 1, true);
    assert.ok(m.segments.slice(0, -1).every((s) => s.sealed));
    assert.equal(cloud.current.length, m.segments.length);
  });

  it("a late finding on a sealed session moves it to the open segment", async () => {
    await addSession(projector, "s1", NOW - 5 * DAY, { padding: 700 });
    await addSession(projector, "s2", NOW - 4 * DAY, { padding: 700 });
    await addSession(projector, "s3", NOW - 1 * DAY, { padding: 10 });
    await sync({ sealBytes: 1200 });
    const m1 = await manifest();
    const holder = m1.segments.find((s) => s.sessions.includes("s1"));
    assert.ok(holder.sealed);

    const before = cloud.uploads.length;
    await addFinding(projector, "s1", NOW - 5 * DAY + 10, "s1-c0");
    await sync({ sealBytes: 1200 });
    const fresh = newUploads(before);
    // The old segment without s1 (if anything is left in it), and the open one with it.
    const contents = await Promise.all(fresh.map(sessionsIn));
    assert.ok(contents.some((ids) => ids.includes("s1")));
    const withFinding = await open(fresh.find((u, i) => contents[i].includes("s1")).envelope);
    assert.equal(withFinding.risk_events.s1.length, 1);
    assert.ok(!cloud.current.includes(holder.id), "the old segment was replaced");
    const m2 = await manifest();
    assert.equal(m2.segments.filter((s) => s.sessions.includes("s1")).length, 1);
    // Its new segment is one this sync uploaded.
    assert.ok(fresh.some((u) => u.id === m2.segments.find((s) => s.sessions.includes("s1")).id));
  });

  it("a session that leaves the window leaves the cloud, and an emptied segment is dropped", async () => {
    await addSession(projector, "old", NOW - 100 * DAY, { padding: 900 });
    await addSession(projector, "new", NOW - DAY, { padding: 10 });
    await sync({ sealBytes: 500 });
    const m1 = await manifest();
    assert.equal(m1.segments.length, 2);

    // Thirty days later the old session is past 120 days.
    const r = await sync({ sealBytes: 500, now: NOW + 30 * DAY });
    assert.deepEqual(r.sessionsIncluded, ["new"]);
    const m2 = await manifest();
    assert.deepEqual(m2.segments.map((s) => s.sessions), [["new"]]);
    assert.equal(m2.sessions.old, undefined);
    assert.deepEqual(cloud.current, [m2.segments[0].id]);
  });

  it("a failed commit leaves the manifest as it was, and the next sync uploads again", async () => {
    await addSession(projector, "s1", NOW - 2 * DAY);
    await sync();
    const saved = await fs.readFile(path.join(home, SEGMENT_MANIFEST_FILE), "utf8");

    await addSession(projector, "s2", NOW - DAY);
    cloud.failCommit = true;
    await assert.rejects(sync(), /HTTP 503/);
    assert.equal(await fs.readFile(path.join(home, SEGMENT_MANIFEST_FILE), "utf8"), saved);

    cloud.failCommit = false;
    const before = cloud.uploads.length;
    await sync();
    assert.equal(newUploads(before).length, 1);
    assert.deepEqual(await sessionsIn(newUploads(before)[0]), ["s1", "s2"]);
  });

  it("a lost or corrupt manifest means one full upload", async () => {
    await addSession(projector, "s1", NOW - 2 * DAY);
    await addSession(projector, "s2", NOW - DAY);
    await sync();
    await fs.writeFile(path.join(home, SEGMENT_MANIFEST_FILE), "{ not json");
    const before = cloud.uploads.length;
    await sync();
    assert.equal(newUploads(before).length, 1);
    assert.deepEqual(await sessionsIn(newUploads(before)[0]), ["s1", "s2"]);
    assert.deepEqual(cloud.current, [newUploads(before)[0].id]);

    await fs.rm(path.join(home, SEGMENT_MANIFEST_FILE));
    await sync();
    assert.equal(cloud.commits, 3);
  });

  it("another machine's or stream's manifest is not trusted", async () => {
    await addSession(projector, "s1", NOW - DAY);
    await sync();
    const before = cloud.uploads.length;
    await sync({ machineId: "other-machine" });
    assert.equal(newUploads(before).length, 1);
    await sync({ customerId: "cust_other" });
    assert.equal(newUploads(before).length, 2);
  });

  it("uploads afresh when the cloud no longer holds a listed segment", async () => {
    await addSession(projector, "s1", NOW - 2 * DAY);
    await sync();
    const gone = cloud.current[0];
    cloud.forget = new Set([gone]);
    await addSession(projector, "s2", NOW - DAY);
    const r = await sync();
    assert.equal(r.uploaded, 1);
    assert.ok(!cloud.current.includes(gone));
    assert.deepEqual(await sessionsIn(cloud.uploads.at(-1)), ["s1", "s2"]);
  });
});

// ---------------------------------------------------------------------------
// Through the sync runner, against a local stand-in for the API
// ---------------------------------------------------------------------------

function startApi({ segments = true } = {}) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      seen.push(`${req.method} ${req.url}`);
      const json = (status, body) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(body)); };
      if (req.url.startsWith("/api/v1/sync/segments/") || req.url === "/api/v1/sync/manifest") {
        if (!segments) { res.writeHead(404); res.end("404 Not Found"); return; }
        if (req.url === "/api/v1/sync/manifest") return json(200, { commit_id: "commit-http" });
        return json(201, { segment_id: req.url.split("/").pop() });
      }
      if (req.url === "/api/v1/sync/push") return json(201, { blob_id: "blob-http" });
      json(500, {});
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    url: `http://127.0.0.1:${server.address().port}`, seen, close: () => new Promise((r) => server.close(r)),
  })));
}

async function writeLog(dir) {
  const log = new EventLog({ root: path.join(dir, "event-log") });
  await log.init();
  const at = Date.now() - DAY;
  for (const e of [
    ev("r1", at, { event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] }),
    ev("r1", at + 1, { event_type: "tool.invoked", tool_call_id: "r1-c0", tool_name: "Bash", mcp_server: "", parameters: { command: "ls" } }),
  ]) await log.append(e);
  await log.close();
}

describe("sync runner", () => {
  it("syncs as segments, and a second sync with nothing new sends nothing", async () => {
    await writeLog(home);
    const api = await startApi();
    try {
      const opts = { home, apiUrl: api.url, apiToken: "omx_test_case", passphrase: PASSPHRASE, customerId: "cust_case" };
      const first = await syncReadModel(opts);
      assert.equal(first.blobId, "commit-http");
      assert.deepEqual(first.segments, { count: 1, uploaded: 1, totalBytes: first.blobBytes });
      assert.deepEqual(api.seen.map((s) => s.split(" ")[1].replace(/segments\/.*/, "segments/:id")), [
        "/api/v1/sync/segments/:id", "/api/v1/sync/manifest",
      ]);

      // The replay and the sync's own audit event change no session, so the
      // next sync sends nothing and writes no audit event.
      const syncEvents = async () => {
        const log = new EventLog({ root: path.join(home, "event-log") });
        await log.init();
        let count = 0;
        for await (const e of log.readAll()) if (e.event_type === "sync.pushed") count++;
        await log.close();
        return count;
      };
      assert.equal(await syncEvents(), 1);
      api.seen.length = 0;
      const second = await syncReadModel(opts);
      assert.deepEqual(api.seen, []);
      assert.equal(second.segments.uploaded, 0);
      assert.equal(await syncEvents(), 1);

      // A new event: the next sync uploads one segment and commits.
      const log = new EventLog({ root: path.join(home, "event-log") });
      await log.init();
      await log.append(ev("r1", Date.now(), { event_type: "tool.invoked", tool_call_id: "r1-c1", tool_name: "Bash", mcp_server: "", parameters: { command: "pwd" } }));
      await log.close();
      const third = await syncReadModel(opts);
      assert.equal(third.segments.uploaded, 1);
      assert.equal(api.seen.length, 2);
      assert.equal(await syncEvents(), 2);
    } finally {
      await api.close();
    }
  });

  it("falls back to the single blob on an API without segment routes", async () => {
    await writeLog(home);
    const api = await startApi({ segments: false });
    try {
      const r = await syncReadModel({ home, apiUrl: api.url, apiToken: "omx_test_case", passphrase: PASSPHRASE, customerId: "cust_case" });
      assert.equal(r.blobId, "blob-http");
      assert.equal(r.segments, undefined);
      assert.ok(api.seen.includes("PUT /api/v1/sync/push"));
    } finally {
      await api.close();
    }
  });

  it("OMNODEX_SYNC_SEGMENTS=0 and a partial sync push the single blob", async () => {
    await writeLog(home);
    const api = await startApi();
    try {
      const opts = { home, apiUrl: api.url, apiToken: "omx_test_case", passphrase: PASSPHRASE, customerId: "cust_case" };
      assert.equal((await syncReadModel({ ...opts, sessionIds: ["r1"] })).blobId, "blob-http");
      process.env.OMNODEX_SYNC_SEGMENTS = "0";
      try {
        assert.equal((await syncReadModel(opts)).blobId, "blob-http");
      } finally {
        delete process.env.OMNODEX_SYNC_SEGMENTS;
      }
      assert.ok(!api.seen.some((s) => s.includes("/segments/")));
    } finally {
      await api.close();
    }
  });
});
