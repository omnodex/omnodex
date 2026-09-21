// Validation: finishing a cloud connection
//
// After connect or install has a token, bootstrapCloudConnection caches the
// license in the home and uploads existing sessions once, so live push and
// automatic sync work without a manual `omnodex sync`. Runs against a local
// HTTP stand-in for the license and sync endpoints.
//
// Run: node --test packages/cli/test/cloud-bootstrap.test.mjs

import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog } from "../../event-log/dist/index.js";
import { bootstrapCloudConnection, describeBootstrap } from "../dist/cloud-bootstrap.js";

const HOSTED = {
  customer_id: "cust_case",
  tier: "hosted",
  features: ["encrypted_sync", "live_streaming"],
  ttl_seconds: 86400,
};

async function startApi({ license = HOSTED, licenseStatus = 200, pushStatus = 201 } = {}) {
  const requests = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url });
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/api/v1/license/validate") {
        res.writeHead(licenseStatus);
        res.end(licenseStatus < 300 ? JSON.stringify(license) : "{}");
      } else if (req.url === "/api/v1/sync/push") {
        res.writeHead(pushStatus);
        res.end(
          pushStatus < 300
            ? JSON.stringify({ blob_id: "blob_case_1", received_at: new Date().toISOString(), payload_bytes: 1 })
            : JSON.stringify({ error: "server_error" }),
        );
      } else {
        res.writeHead(404);
        res.end("{}");
      }
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    hits: (url) => requests.filter((r) => r.url === url).length,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

async function writeJson(home, name, value) {
  await writeFile(path.join(home, name), JSON.stringify(value));
}

async function readJson(home, name) {
  try {
    return JSON.parse(await readFile(path.join(home, name), "utf8"));
  } catch {
    return null;
  }
}

async function writeSession(home) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  const sessionId = randomUUID();
  const now = new Date().toISOString();
  const base = {
    schema_version: 1,
    session_id: sessionId,
    occurred_at: now,
    recorded_at: now,
    interceptor: "codex-hook",
  };
  await log.append({
    ...base,
    event_id: randomUUID(),
    event_type: "session.started",
    user: "case",
    project_path: "/home/case/repo",
    mcp_servers: [],
  });
  await log.close();
}

describe("bootstrapCloudConnection", () => {
  let home;
  let api;
  let savedEnv;

  async function connect(apiOpts, bootstrapOpts = {}) {
    api = await startApi(apiOpts);
    await writeJson(home, "stream-config.json", {
      api_token: "omx_test_case",
      passphrase: "case-passphrase",
      api_url: api.url,
    });
    return bootstrapCloudConnection({
      home,
      apiToken: "omx_test_case",
      apiUrl: api.url,
      refresh: true,
      ...bootstrapOpts,
    });
  }

  beforeEach(async () => {
    home = await mkdtemp(path.join(os.tmpdir(), "omnodex-bootstrap-"));
    await writeSession(home);
    savedEnv = process.env.OMNODEX_API_URL;
    delete process.env.OMNODEX_API_URL;
  });

  afterEach(async () => {
    if (savedEnv === undefined) delete process.env.OMNODEX_API_URL;
    else process.env.OMNODEX_API_URL = savedEnv;
    await api?.close();
    api = undefined;
    await rm(home, { recursive: true, force: true });
  });

  it("caches the license in a fresh home and uploads existing sessions", async () => {
    const result = await connect();

    assert.deepEqual(result, { status: "synced", tier: "hosted" });
    assert.equal((await readJson(home, "license-cache.json")).response.customer_id, "cust_case");
    assert.equal(api.hits("/api/v1/sync/push"), 1);
    const state = await readJson(home, "auto-sync-state.json");
    assert.ok(state.last_success_at);
    assert.equal(state.last_blob_id, "blob_case_1");
  });

  it("does not upload again for a home that has already synced", async () => {
    await writeJson(home, "auto-sync-state.json", {
      last_success_at: "2026-09-18T20:32:00.000Z",
    });

    const result = await connect({}, { refresh: false });

    assert.deepEqual(result, { status: "ready", tier: "hosted" });
    assert.equal(api.hits("/api/v1/sync/push"), 0);
    assert.ok(await readJson(home, "license-cache.json"));
  });

  it("replaces a cache written for an earlier token when refreshing", async () => {
    await writeJson(home, "license-cache.json", {
      response: { ...HOSTED, customer_id: "cust_old" },
      fetched_at: Date.now(),
    });

    await connect();

    assert.equal((await readJson(home, "license-cache.json")).response.customer_id, "cust_case");
    assert.equal(api.hits("/api/v1/license/validate"), 1);
  });

  it("keeps a valid cache for an existing token", async () => {
    await writeJson(home, "license-cache.json", {
      response: { ...HOSTED, customer_id: "cust_cached" },
      fetched_at: Date.now(),
    });
    await writeJson(home, "auto-sync-state.json", {
      last_success_at: "2026-09-18T20:32:00.000Z",
    });

    const result = await connect({}, { refresh: false });

    assert.equal(result.status, "ready");
    assert.equal(api.hits("/api/v1/license/validate"), 0);
  });

  it("uploads nothing for a license without encrypted sync", async () => {
    const result = await connect({
      license: { ...HOSTED, tier: "free", features: ["local_dashboard"] },
    });

    assert.deepEqual(result, { status: "not-entitled", tier: "free" });
    assert.equal(api.hits("/api/v1/sync/push"), 0);
  });

  it("reports an unverified license when the service refuses", async () => {
    const result = await connect({ licenseStatus: 401 });

    assert.deepEqual(result, { status: "unverified" });
    assert.equal(await readJson(home, "license-cache.json"), null);
    assert.equal(api.hits("/api/v1/sync/push"), 0);
  });

  it("reports a failed initial upload with its error and keeps the license", async () => {
    const result = await connect({ pushStatus: 500 });

    assert.equal(result.status, "sync-failed");
    assert.match(result.error, /500/);
    assert.ok(await readJson(home, "license-cache.json"));
    const lines = describeBootstrap("connect", result);
    assert.match(lines.at(-1), /omnodex sync/);
  });
});
