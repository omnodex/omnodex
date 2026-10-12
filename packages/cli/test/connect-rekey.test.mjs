/**
 * `omnodex connect` against a stream whose token or secret changed: a
 * rejected token goes back through sign-in with the secret kept, a rotated
 * token is collected, a stream with a registered secret never gets a new
 * one, and a token or secret passed as a flag is checked and saved.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { deriveStreamVerifier } from "@omnodex/sync-encryptor";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const SECRET = "case stream secret";

/** A cloud that knows `valid` tokens, answers `rotated` ones as rotated, and runs a device flow. */
async function startCloud({ valid = [], rotated = [], verifier = null, newToken = "omx_test_new" } = {}) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const auth = (req.headers.authorization ?? "").replace(/^Bearer /, "");
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
      seen.push(`${req.method} ${req.url}`);
      const json = (status, value) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(value)); };
      switch (req.url) {
        case "/api/v1/device/code":
          return json(200, { device_code: "dc", user_code: "ABCD-EFGH", verification_url: "http://dash/device", expires_in: 60, interval: 0 });
        case "/api/v1/device/token":
          return json(200, { api_token: newToken, customer_id: "cust_case" });
        case "/api/v1/stream/collect-token":
          if (!rotated.includes(body.old_token)) return json(401, { error: "not_collectable" });
          if (body.secret_verifier !== verifier) return json(409, { error: "secret_mismatch" });
          return json(200, { api_token: newToken, customer_id: "cust_case" });
        case "/api/v1/connect/claim":
          return json(201, { claim_token: "omx_claim_case", expires_at: new Date(Date.now() + 600_000).toISOString() });
      }
      if (!valid.includes(auth)) {
        return rotated.includes(auth) ? json(401, { error: "token_rotated" }) : json(401, { error: "invalid_token" });
      }
      if (req.url === "/api/v1/stream/verifier") {
        if (req.method === "GET") return json(200, { registered: !!verifier });
        if (!verifier) return json(200, { ok: true, status: "registered" });
        return body.secret_verifier === verifier ? json(200, { ok: true, status: "matched" }) : json(409, { error: "secret_mismatch" });
      }
      // License validation and anything else: unavailable, so connect stops before syncing.
      json(503, { error: "unavailable" });
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${server.address().port}`, seen, close: () => new Promise((r) => server.close(r)) };
}

async function setup(t, config) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-connect-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const home = path.join(root, ".omnodex");
  await fs.mkdir(home, { recursive: true });
  if (config) await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify(config));
  return { root, home };
}

async function connect({ root, home }, cloud, args = []) {
  const env = {
    ...process.env, HOME: root, USERPROFILE: root, OMNODEX_HOME: home, OMNODEX_SINGLE_ROOT: "1",
    OMNODEX_NO_UPDATE_CHECK: "1", OMNODEX_AUTO_SYNC: "0", OMNODEX_API_URL: cloud.url,
  };
  delete env.OMNODEX_API_TOKEN;
  delete env.OMNODEX_STREAM_SECRET;
  delete env.OMNODEX_SYNC_PASSPHRASE;
  const child = spawn(process.execPath, [CLI, "connect", ...args], { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const code = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error(`connect did not finish:\n${out}`)); }, 60_000);
    child.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  return { code, out };
}

const readConfig = async (home) => JSON.parse(await fs.readFile(path.join(home, "stream-config.json"), "utf8"));
const secretOf = (config) => config.stream_secret ?? config.passphrase;

test("a revoked token goes back through sign-in and keeps the stream secret", async (t) => {
  const cloud = await startCloud({ valid: ["omx_test_new"] });
  t.after(cloud.close);
  const ctx = await setup(t, { api_token: "omx_test_old", stream_secret: SECRET, api_url: cloud.url });

  const { code, out } = await connect(ctx, cloud);
  assert.equal(code, 0, out);
  assert.match(out, /token no longer works/);
  assert.ok(cloud.seen.includes("POST /api/v1/device/code"), out);
  const config = await readConfig(ctx.home);
  assert.equal(config.api_token, "omx_test_new");
  assert.equal(secretOf(config), SECRET);
});

test("a rotated token is collected with the stream secret", async (t) => {
  const cloud = await startCloud({ valid: ["omx_test_new"], rotated: ["omx_test_old"], verifier: await deriveStreamVerifier(SECRET) });
  t.after(cloud.close);
  const ctx = await setup(t, { api_token: "omx_test_old", stream_secret: SECRET, api_url: cloud.url });

  const { code, out } = await connect(ctx, cloud);
  assert.equal(code, 0, out);
  assert.match(out, /collected the new one/);
  assert.ok(!cloud.seen.includes("POST /api/v1/device/code"));
  assert.equal((await readConfig(ctx.home)).api_token, "omx_test_new");
});

test("a stream with a registered secret never gets a new one", async (t) => {
  const cloud = await startCloud({ valid: ["omx_test_case"], verifier: await deriveStreamVerifier(SECRET) });
  t.after(cloud.close);
  const ctx = await setup(t, null);

  const { code, out } = await connect(ctx, cloud, ["--token", "omx_test_case"]);
  assert.equal(code, 1, out);
  assert.match(out, /already has a stream secret/);
  assert.match(out, /omnodex connect --secret/);
  await assert.rejects(fs.readFile(path.join(ctx.home, "stream-config.json")));
});

test("a secret passed as a flag is checked: the wrong one is refused and not saved", async (t) => {
  const cloud = await startCloud({ valid: ["omx_test_case"], verifier: await deriveStreamVerifier(SECRET) });
  t.after(cloud.close);
  const ctx = await setup(t, null);

  const wrong = await connect(ctx, cloud, ["--token", "omx_test_case", "--secret", "not the secret"]);
  assert.equal(wrong.code, 1, wrong.out);
  assert.match(wrong.out, /not the one this stream uses/);

  const right = await connect(ctx, cloud, ["--token", "omx_test_case", "--secret", SECRET]);
  assert.equal(right.code, 0, right.out);
  assert.match(right.out, /saved the token and stream secret/);
  const config = await readConfig(ctx.home);
  assert.equal(config.api_token, "omx_test_case");
  assert.equal(secretOf(config), SECRET);
});

test("a new token passed after a rotate replaces the saved one", async (t) => {
  const cloud = await startCloud({ valid: ["omx_test_new"], verifier: await deriveStreamVerifier(SECRET) });
  t.after(cloud.close);
  const ctx = await setup(t, { api_token: "omx_test_old", stream_secret: SECRET, api_url: cloud.url });

  const { code, out } = await connect(ctx, cloud, ["--token", "omx_test_new"]);
  assert.equal(code, 0, out);
  assert.match(out, /saved the token to stream-config.json/);
  const config = await readConfig(ctx.home);
  assert.equal(config.api_token, "omx_test_new");
  assert.equal(secretOf(config), SECRET);
});

test("an invalid token passed as a flag is refused, not signed in again", async (t) => {
  const cloud = await startCloud({ valid: [] });
  t.after(cloud.close);
  const ctx = await setup(t, { api_token: "omx_test_old", stream_secret: SECRET, api_url: cloud.url });

  const { code, out } = await connect(ctx, cloud, ["--token", "omx_test_typo"]);
  assert.equal(code, 1, out);
  assert.match(out, /that token is not valid/);
  assert.ok(!cloud.seen.includes("POST /api/v1/device/code"));
  assert.equal((await readConfig(ctx.home)).api_token, "omx_test_old");
});
