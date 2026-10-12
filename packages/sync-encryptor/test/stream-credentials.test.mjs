// Stream credentials: the stream secret's verifier, and a
// sync that collects the new token after the owner rotated it.
//
// Run: node --test packages/sync-encryptor/test/stream-credentials.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import { createServer } from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "../../event-log/dist/index.js";
import {
  deriveStreamVerifier,
  ensureSecretVerifier,
  collectRotatedToken,
  readVerifierState,
  SecretMismatchError,
  TokenCollectionError,
} from "../dist/index.js";
import { syncReadModel } from "../dist/sync-runner.js";

const SECRET = "correct horse battery staple";
// The hosted dashboard tests the same vector.
const VECTOR = "7qX9Bdrou5eLXVY1J/bjm3SIAWXuB4ky1YUMm/q4pWo=";

let home;
beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-credentials-"));
});
afterEach(async () => {
  await fs.rm(home, { recursive: true, force: true });
});

/**
 * A cloud with one stream. `verifier` is the registered one (null: none);
 * `rotatedFrom` is an old token that may collect `token` once per machine.
 */
function startCloud({ token = "omx_new", verifier = null, rotatedFrom = null } = {}) {
  const state = { token, verifier, collected: new Set(), requests: [] };
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const auth = (req.headers.authorization ?? "").replace(/^Bearer /, "");
      const body = chunks.length ? Buffer.concat(chunks) : null;
      state.requests.push({ method: req.method, url: req.url, auth });
      const json = (status, value) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(value)); };
      if (req.url === "/api/v1/stream/collect-token") {
        const b = JSON.parse(body.toString("utf8"));
        if (b.old_token !== rotatedFrom) return json(401, { error: "not_collectable" });
        if (b.secret_verifier !== state.verifier) return json(409, { error: "secret_mismatch" });
        if (state.collected.has(b.machine_id)) return json(409, { error: "already_collected" });
        state.collected.add(b.machine_id);
        return json(200, { api_token: state.token, customer_id: "cust_case" });
      }
      if (auth !== state.token) {
        return auth === rotatedFrom ? json(401, { error: "token_rotated" }) : json(401, { error: "invalid_token" });
      }
      if (req.url === "/api/v1/stream/verifier") {
        const v = JSON.parse(body.toString("utf8")).secret_verifier;
        if (!state.verifier) { state.verifier = v; return json(200, { ok: true, status: "registered" }); }
        return v === state.verifier ? json(200, { ok: true, status: "matched" }) : json(409, { error: "secret_mismatch" });
      }
      if (req.url.startsWith("/api/v1/sync/segments/")) return json(201, {});
      if (req.url === "/api/v1/sync/manifest") return json(200, { commit_id: "commit-case" });
      json(404, {});
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    url: `http://127.0.0.1:${server.address().port}`, state, close: () => new Promise((r) => server.close(r)),
  })));
}

const opts = (cloud, extra = {}) => ({ home, apiUrl: cloud.url, apiToken: "omx_new", passphrase: SECRET, ...extra });

describe("stream secret verifier", () => {
  it("derives the same value as the hosted dashboard", async () => {
    assert.equal(await deriveStreamVerifier(SECRET), VECTOR);
  });

  it("registers once per token and secret, then checks nothing", async () => {
    const cloud = await startCloud();
    try {
      assert.equal(await ensureSecretVerifier(opts(cloud)), "registered");
      assert.equal(cloud.state.verifier, VECTOR);
      assert.equal(await ensureSecretVerifier(opts(cloud)), "registered");
      assert.equal(cloud.state.requests.length, 1);
      assert.equal((await readVerifierState(home)).status, "registered");
    } finally {
      await cloud.close();
    }
  });

  it("stops on a secret that is not the stream's, and remembers it", async () => {
    const cloud = await startCloud({ verifier: await deriveStreamVerifier("another secret") });
    try {
      await assert.rejects(ensureSecretVerifier(opts(cloud)), SecretMismatchError);
      await assert.rejects(ensureSecretVerifier(opts(cloud)), SecretMismatchError);
      assert.equal(cloud.state.requests.length, 1);
      // A different secret is checked afresh.
      assert.equal(await ensureSecretVerifier(opts(cloud, { passphrase: "another secret" })), "matched");
    } finally {
      await cloud.close();
    }
  });

  it("skips quietly when the cloud cannot be reached", async () => {
    assert.equal(await ensureSecretVerifier({ home, apiUrl: "http://127.0.0.1:9", apiToken: "omx_new", passphrase: SECRET, timeoutMs: 2000 }), "skipped");
    assert.equal(await readVerifierState(home), null);
  });
});

describe("rotated token", () => {
  it("collects the new token by proving the secret, once per machine, and keeps the config", async () => {
    const cloud = await startCloud({ verifier: VECTOR, rotatedFrom: "omx_old" });
    await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_old", stream_secret: SECRET, auto_sync: false }));
    try {
      assert.equal(await collectRotatedToken(opts(cloud, { apiToken: "omx_old" })), "omx_new");
      const config = JSON.parse(await fs.readFile(path.join(home, "stream-config.json"), "utf8"));
      assert.equal(config.api_token, "omx_new");
      assert.equal(config.stream_secret, SECRET);
      assert.equal(config.auto_sync, false);

      await assert.rejects(collectRotatedToken(opts(cloud, { apiToken: "omx_old" })),
        (err) => err instanceof TokenCollectionError && err.code === "already_collected" && /omnodex connect --token/.test(err.message));
    } finally {
      await cloud.close();
    }
  });

  it("refuses a machine without the secret", async () => {
    const cloud = await startCloud({ verifier: VECTOR, rotatedFrom: "omx_old" });
    try {
      await assert.rejects(collectRotatedToken(opts(cloud, { apiToken: "omx_old", passphrase: "guess" })),
        (err) => err instanceof TokenCollectionError && err.code === "secret_mismatch");
    } finally {
      await cloud.close();
    }
  });

  it("a sync with the old token collects the new one and uploads with it", async () => {
    const cloud = await startCloud({ verifier: VECTOR, rotatedFrom: "omx_old" });
    await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_old", stream_secret: SECRET }));
    const log = new EventLog({ root: path.join(home, "event-log") });
    await log.init();
    const at = new Date(Date.now() - 60_000).toISOString();
    await log.append({
      schema_version: 1, event_id: "e1", session_id: "s1", occurred_at: at, recorded_at: at,
      interceptor: "hook", event_type: "session.started", user: "case", project_path: "/case", mcp_servers: [],
    });
    await log.close();
    try {
      const result = await syncReadModel({ home, apiUrl: cloud.url, apiToken: "omx_old", passphrase: SECRET, customerId: "cust_case" });
      assert.equal(result.collectedToken, "omx_new");
      const uploads = cloud.state.requests.filter((r) => r.url.startsWith("/api/v1/sync/"));
      assert.ok(uploads.some((r) => r.auth === "omx_new" && r.url === "/api/v1/sync/manifest"));
      const config = JSON.parse(await fs.readFile(path.join(home, "stream-config.json"), "utf8"));
      assert.equal(config.api_token, "omx_new");
    } finally {
      await cloud.close();
    }
  });
});
