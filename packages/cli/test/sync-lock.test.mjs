// `omnodex sync` while a background pass holds the sync lock: it waits for
// the pass and then syncs, or says a sync is running and exits cleanly,
// instead of failing on a locked traces.db.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const HOSTED = {
  customer_id: "cust_case",
  tier: "hosted",
  features: ["community_rules", "encrypted_sync", "hosted_dashboard"],
  ttl_seconds: 86400,
};

/** Local stand-in for the license and segment sync routes. */
async function startApi(t) {
  const seen = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      seen.push(`${req.method} ${req.url.replace(/segments\/.+/, "segments/:id")}`);
      res.writeHead(req.url.startsWith("/api/v1/sync/segments/") ? 201 : 200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(req.url === "/api/v1/sync/manifest" ? { commit_id: "commit_case_1" } : HOSTED));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { url: `http://127.0.0.1:${server.address().port}`, seen };
}

async function scratch(t, api) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-sync-lock-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const omnodexHome = path.join(home, ".omnodex");
  await fs.mkdir(omnodexHome, { recursive: true });
  await fs.writeFile(
    path.join(omnodexHome, "stream-config.json"),
    JSON.stringify({ api_token: "omx_test_case", passphrase: "case-passphrase", api_url: api.url }),
  );
  return { home, omnodexHome, lock: path.join(omnodexHome, "auto-sync.lock") };
}

/** Run the CLI without blocking this process, so the stub API can answer. */
function sync(env, waitMs, onStdout = () => {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "sync"], {
      cwd: env.home,
      env: {
        ...process.env,
        HOME: env.home,
        USERPROFILE: env.home,
        OMNODEX_HOME: env.omnodexHome,
        OMNODEX_SINGLE_ROOT: "1",
        OMNODEX_AUTO_SYNC: "0",
        OMNODEX_SYNC_LOCK_WAIT_MS: String(waitMs),
      },
    });
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; onStdout(stdout); });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("waits for a running background pass, then syncs", async (t) => {
  const api = await startApi(t);
  const env = await scratch(t, api);
  await fs.writeFile(env.lock, JSON.stringify({ pid: 1, at: new Date().toISOString() }));
  // The pass finishes once the CLI has said it is waiting for it.
  let released = false;
  const res = await sync(env, 30_000, (out) => {
    if (!released && out.includes("waiting")) {
      released = true;
      setTimeout(() => fs.unlink(env.lock).catch(() => {}), 500);
    }
  });
  assert.equal(res.code, 0, res.stderr);
  assert.match(res.stdout, /a background sync is running on this machine; waiting/);
  assert.match(res.stdout, /\[sync\] done\. commit=commit_case_1/);
  assert.ok(api.seen.includes("PUT /api/v1/sync/manifest"));
  // The manual sync released the lock it took.
  await assert.rejects(fs.stat(env.lock));
});

test("says a sync is running and exits cleanly when the pass outlasts the wait", async (t) => {
  const api = await startApi(t);
  const env = await scratch(t, api);
  await fs.writeFile(env.lock, JSON.stringify({ pid: 1, at: new Date().toISOString() }));

  const res = await sync(env, 1500);
  assert.equal(res.code, 1);
  assert.match(res.stderr, /a background sync is still running\. Try again/);
  assert.doesNotMatch(res.stderr, /database is locked|at .*\.js:\d+/);
  assert.ok(!api.seen.some((s) => s.includes("/sync/")), "nothing was uploaded");
  // The background pass's lock is left alone.
  await fs.stat(env.lock);
});

test("takes over a stale lock from a crashed sync without waiting", async (t) => {
  const api = await startApi(t);
  const env = await scratch(t, api);
  await fs.writeFile(env.lock, "{}");
  const old = new Date(Date.now() - 11 * 60 * 1000);
  await fs.utimes(env.lock, old, old);

  const res = await sync(env, 30_000);
  assert.equal(res.code, 0, res.stderr);
  assert.doesNotMatch(res.stdout, /waiting/);
  assert.match(res.stdout, /\[sync\] done\./);
});
