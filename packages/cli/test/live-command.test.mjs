// `omnodex status` reports the live push gate, and `omnodex live resume`
// clears it. While the relay reports no dashboard watching, every pusher on
// the machine holds back; before these, the only sign was a JSON file under
// OMNODEX_HOME and the only fix was deleting it by hand.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const GATE = "live-push-state.json";

async function scratch(t, { credentials = true } = {}) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-live-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const omnodexHome = path.join(home, ".omnodex");
  await fs.mkdir(omnodexHome, { recursive: true });
  if (credentials) {
    await fs.writeFile(
      path.join(omnodexHome, "stream-config.json"),
      // Unroutable API: nothing here may reach the network.
      JSON.stringify({ api_token: "omx_test_case", passphrase: "case-passphrase", api_url: "http://127.0.0.1:9" }),
    );
  }
  return { home, omnodexHome };
}

function run(env, args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: env.home,
    env: {
      ...process.env,
      HOME: env.home,
      USERPROFILE: env.home,
      OMNODEX_HOME: env.omnodexHome,
    },
    encoding: "utf8",
    timeout: 60_000,
  });
}

async function pause(env, secondsLeft) {
  const state = { paused_until: Date.now() + secondsLeft * 1000, backoff_ms: 60_000 };
  await fs.writeFile(path.join(env.omnodexHome, GATE), JSON.stringify(state) + "\n");
  return state;
}

test("status reports a paused gate with the time it reopens", async (t) => {
  const env = await scratch(t);
  const state = await pause(env, 45);
  const result = run(env, ["status"]);
  assert.equal(result.status, 0, result.stderr);
  const line = result.stdout.split("\n").find((l) => l.startsWith("[status] live push:"));
  assert.ok(line, result.stdout);
  assert.match(line, new RegExp(`paused until ${new Date(state.paused_until).toISOString().replace(/[.]/g, "\\.")}`));
  assert.match(line, /back-off 60s/);
  assert.match(line, /omnodex live resume/);
});

test("status reports an open gate", async (t) => {
  const env = await scratch(t);
  const result = run(env, ["status"]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^\[status\] live push:\s+open$/m);
});

test("status says nothing about live push without cloud credentials", async (t) => {
  const env = await scratch(t, { credentials: false });
  await pause(env, 45);
  const result = run(env, ["status"]);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /live push/);
});

test("live resume clears a paused gate, and a second run says it is open", async (t) => {
  const env = await scratch(t);
  await pause(env, 45);

  const first = run(env, ["live", "resume"]);
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /\[live\] resumed/);
  await assert.rejects(fs.access(path.join(env.omnodexHome, GATE)));

  const second = run(env, ["live", "resume"]);
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /\[live\] already open/);

  const shown = run(env, ["live"]);
  assert.equal(shown.status, 0, shown.stderr);
  assert.match(shown.stdout, /: open$/m);
});

test("live with an unknown subcommand fails without touching the gate", async (t) => {
  const env = await scratch(t);
  await pause(env, 45);
  const result = run(env, ["live", "restart"]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown subcommand: restart/);
  await fs.access(path.join(env.omnodexHome, GATE));
});
