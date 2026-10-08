// `omnodex license` checks the account `omnodex connect` linked. It used to
// call the license client with no settings, so it saw only
// OMNODEX_API_TOKEN, reported the free tier on a connected machine, ignored
// --token, and kept its cache in ~/.omnodex rather than OMNODEX_HOME.

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

/** Local license endpoint; records the bearer token of each request. */
async function startApi(t) {
  const tokens = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      tokens.push(req.headers.authorization ?? "");
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(HOSTED));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { url: `http://127.0.0.1:${server.address().port}`, tokens };
}

async function scratch(t, api) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-license-cmd-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  // OMNODEX_HOME apart from HOME/.omnodex, to show which one the cache uses.
  const omnodexHome = path.join(home, "case-omnodex");
  await fs.mkdir(omnodexHome, { recursive: true });
  await fs.writeFile(
    path.join(omnodexHome, "stream-config.json"),
    JSON.stringify({ api_token: "omx_test_case", passphrase: "case-passphrase", api_url: api.url }),
  );
  return { home, omnodexHome };
}

/** Run the CLI without blocking the event loop, so the local API can answer. */
function run(env, args) {
  const childEnv = { ...process.env, HOME: env.home, USERPROFILE: env.home, OMNODEX_HOME: env.omnodexHome, OMNODEX_SINGLE_ROOT: "1" };
  delete childEnv.OMNODEX_API_TOKEN;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "license", ...args], { cwd: env.home, env: childEnv });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.on("close", (status) => resolve({ status, stdout }));
  });
}

test("uses the token connect saved, and caches in OMNODEX_HOME", async (t) => {
  const api = await startApi(t);
  const env = await scratch(t, api);
  const result = await run(env, []);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /\[license\] tier:\s+hosted/);
  assert.deepEqual(api.tokens, ["Bearer omx_test_case"]);
  const cache = JSON.parse(await fs.readFile(path.join(env.omnodexHome, "license-cache.json"), "utf8"));
  assert.equal(cache.response.tier, "hosted");
  await assert.rejects(fs.stat(path.join(env.home, ".omnodex", "license-cache.json")));

  // clear removes that same cache.
  assert.equal((await run(env, ["clear"])).status, 0);
  await assert.rejects(fs.stat(path.join(env.omnodexHome, "license-cache.json")));
});

test("--token wins over the saved token", async (t) => {
  const api = await startApi(t);
  const env = await scratch(t, api);
  const result = await run(env, ["--token", "omx_test_flag"]);
  assert.match(result.stdout, /tier:\s+hosted/);
  assert.deepEqual(api.tokens, ["Bearer omx_test_flag"]);
});
