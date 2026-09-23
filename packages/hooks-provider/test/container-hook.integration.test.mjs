// Integration tests for the container hook as a process: the environment
// gate, delivery to a local ingest server, the curl transport, and the
// single-file bundle running with no node_modules next to it.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { CLOUD_CONTAINER_MARKERS, makeCurlPoster } from "../dist/container-hook.js";
import { bytesToBase64, generateStreamKeyPair, openEvent } from "../../sync-encryptor/dist/hpke-event.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(here, "..");
const DIST_BIN = path.join(pkgDir, "dist", "bin", "container-hook.js");
const TOKEN = "oxi_" + "B".repeat(43);
const inContainer = CLOUD_CONTAINER_MARKERS.some((m) => fs.existsSync(m));

let server;
let port;
const received = [];

before(async () => {
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ url: req.url, auth: req.headers.authorization, body: JSON.parse(body) });
      res.writeHead(202, { "content-type": "application/json" });
      res.end('{"accepted":1}');
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(() => server.close());

async function makePlugin({ force }) {
  const pair = await generateStreamKeyPair();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-plugin-"));
  fs.mkdirSync(path.join(root, "scripts"));
  fs.writeFileSync(
    path.join(root, "ingest.json"),
    JSON.stringify({
      version: 1,
      api_base: `http://127.0.0.1:${port}`,
      ingest_token: TOKEN,
      source_id: "src_0123456789ab",
      public_key: bytesToBase64(pair.publicKey),
      key_id: pair.keyId,
      force,
    }),
  );
  return { pair, root, home: fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-home-")) };
}

// Async, so this process's test server can answer the hook while it runs.
function runHook(script, plugin, payload) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, CLAUDE_PLUGIN_ROOT: plugin.root, OMNODEX_HOME: plugin.home, HOME: plugin.home },
    });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.on("close", (status) => resolve({ status, stdout }));
    child.stdin.end(JSON.stringify(payload));
  });
}

const PRE = { session_id: "sess-int", cwd: "/home/case/repo", hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu_int", tool_input: { command: "ls" } };
const STOP = { session_id: "sess-int", hook_event_name: "Stop" };

test("outside a cloud container the hook exits at once and writes nothing", { skip: inContainer && "running inside a cloud container" }, async () => {
  const plugin = await makePlugin({ force: false });
  const before = received.length;
  for (const payload of [PRE, STOP]) {
    const r = await runHook(DIST_BIN, plugin, payload);
    assert.equal(r.status, 0);
    assert.equal(r.stdout, "");
  }
  assert.equal(fs.existsSync(path.join(plugin.home, "ingest")), false);
  assert.equal(received.length, before);
});

test("without ingest.json the hook does nothing, even when forced elsewhere", async () => {
  const plugin = await makePlugin({ force: true });
  fs.unlinkSync(path.join(plugin.root, "ingest.json"));
  const r = await runHook(DIST_BIN, plugin, PRE);
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
  assert.equal(fs.existsSync(path.join(plugin.home, "ingest")), false);
});

test("when capturing, events reach the ingest endpoint sealed on Stop", async () => {
  const plugin = await makePlugin({ force: true });
  const before = received.length;
  assert.equal((await runHook(DIST_BIN, plugin, PRE)).status, 0);
  assert.equal(received.length, before, "nothing sent mid-turn");
  const r = await runHook(DIST_BIN, plugin, STOP);
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
  assert.equal(received.length, before + 1);
  const req = received.at(-1);
  assert.equal(req.url, "/api/v1/ingest/events");
  assert.equal(req.auth, `Bearer ${TOKEN}`);
  const key = { keyId: plugin.pair.keyId, privateKey: plugin.pair.privateKey };
  const event = JSON.parse(new TextDecoder().decode(await openEvent(key, req.body.events[0])));
  assert.equal(event.tool_call_id, "tu_int");
  assert.equal(event.platform, "cowork");
});

test("the curl transport posts the body with the token header", async () => {
  const hasCurl = spawnSync("curl", ["--version"]).status === 0;
  if (!hasCurl) return;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-curl-"));
  const before = received.length;
  const r = await makeCurlPoster(work)(`http://127.0.0.1:${port}/api/v1/ingest/events`, TOKEN, '{"events":[{"x":1}]}');
  assert.deepEqual(r, { status: 202 });
  assert.equal(received.length, before + 1);
  assert.equal(received.at(-1).auth, `Bearer ${TOKEN}`);
  assert.deepEqual(received.at(-1).body, { events: [{ x: 1 }] });
  assert.deepEqual(fs.readdirSync(work), [], "the header file is removed");
});

test("the single-file bundle runs with no node_modules beside it", async () => {
  const plugin = await makePlugin({ force: true });
  const script = path.join(plugin.root, "scripts", "omnodex-hook.mjs");
  execFileSync(process.execPath, [path.join(pkgDir, "bundle.config.mjs"), "--out", script], { stdio: "ignore" });
  const before = received.length;
  assert.equal((await runHook(script, plugin, PRE)).status, 0);
  const r = await runHook(script, plugin, STOP);
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "");
  assert.equal(received.length, before + 1);
  assert.equal(received.at(-1).body.events.length, 1);
});
