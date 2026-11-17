// Process-level test: the hook command as an agent runs it. Environment in,
// payload on stdin, delivery to a local ingest server, exit code 0 always.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { bytesToBase64, generateStreamKeyPair } from "../../sync-encryptor/dist/hpke-event.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.resolve(here, "..", "dist", "bin", "sealed-hook.js");

let server;
let port;
const received = [];

before(async () => {
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ auth: req.headers.authorization, body: JSON.parse(body) });
      res.writeHead(202, { "content-type": "application/json" }).end("{}");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});

after(() => server.close());

function run(args, env, payload) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [BIN, ...args], { env: { PATH: process.env.PATH, ...env } });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.on("close", (status) => resolve({ status, stdout }));
    child.stdin.end(typeof payload === "string" ? payload : JSON.stringify(payload));
  });
}

async function hostEnv(extra) {
  const pair = await generateStreamKeyPair();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "omnodex-sealed-int-"));
  return {
    home,
    env: {
      HOME: home,
      OMNODEX_HOME: home,
      OMNODEX_INGEST_PUBLIC_KEY: bytesToBase64(pair.publicKey),
      OMNODEX_INGEST_SOURCE_ID: "src_0123456789ab",
      OMNODEX_INGEST_API_BASE: `http://127.0.0.1:${port}`,
      ...extra,
    },
  };
}

const PRE = { session_id: "i1", cwd: "/home/case/repo", hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "tu_i", tool_input: { command: "ls" } };

test("a Claude Code cloud session (CLAUDE_CODE_REMOTE) delivers without any token", async () => {
  const { env } = await hostEnv({ CLAUDE_CODE_REMOTE: "true" });
  const before = received.length;
  assert.equal((await run(["claude-code"], env, PRE)).status, 0);
  assert.equal(received.length, before);
  const stop = await run(["claude-code"], env, { session_id: "i1", hook_event_name: "Stop" });
  assert.equal(stop.status, 0);
  assert.equal(received.length, before + 1);
  assert.equal(received.at(-1).auth, undefined);
  assert.equal(received.at(-1).body.events.length, 1);
});

test("the same command on a laptop (no marker) sends nothing and exits 0", async () => {
  const { env, home } = await hostEnv({});
  const before = received.length;
  const r = await run(["claude-code"], env, { session_id: "i2", hook_event_name: "Stop" });
  assert.equal(r.status, 0);
  assert.equal(received.length, before);
  assert.equal(fs.existsSync(path.join(home, "ingest")), false);
});

test("a Copilot hook with no settings prints {} and exits 0", async () => {
  const r = await run(["copilot"], { OMNODEX_SEALED: "1" }, { hook_event_name: "SessionEnd", session_id: "i3" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "{}");
});

test("garbage on stdin still exits 0 with the agent's answer", async () => {
  const { env } = await hostEnv({ OMNODEX_SEALED: "1" });
  const r = await run(["cursor"], env, "}{ not json");
  assert.equal(r.status, 0);
  assert.equal(r.stdout, "{}");
});

test("the provider can come from the environment instead of the command line", async () => {
  const { env } = await hostEnv({ OMNODEX_SEALED: "1", OMNODEX_SEALED_PROVIDER: "claude-code" });
  const before = received.length;
  await run([], env, { session_id: "i4", hook_event_name: "Stop" });
  assert.equal(received.length, before);
  await run([], env, PRE);
  await run([], env, { session_id: "i1", hook_event_name: "Stop" });
  assert.equal(received.length, before + 1);
});
