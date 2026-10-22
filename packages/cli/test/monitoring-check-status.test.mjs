/**
 * `omnodex status` runs the monitoring config check and reports each
 * platform; a hook entry removed by something other than Omnodex is
 * recorded with a HIGH finding.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { EventLog } from "@omnodex/event-log";
import { CAPTURE_CONTROL_SESSION_ID } from "@omnodex/shared";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

/** An isolated home; never the developer's real ~/.omnodex or agents. */
async function machine(t) {
  const root = realpathSync(await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-moncheck-")));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const home = path.join(root, "home");
  const omnodexHome = path.join(home, ".omnodex");
  const project = path.join(root, "project");
  await fs.mkdir(project, { recursive: true });
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    OMNODEX_HOME: omnodexHome,
    CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
    CODEX_HOME: path.join(home, ".codex"),
    WSL_DISTRO_NAME: "",
    OMNODEX_WSL_MOUNT_ROOT: path.join(root, "no-windows-mount"),
    // No update check: its detached child writes into HOME after the command exits.
    OMNODEX_NO_UPDATE_CHECK: "1",
  };
  return { root, home, omnodexHome, project, env };
}

function run(args, env, cwd) {
  const child = spawn(process.execPath, [CLI, ...args], { env, cwd, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.end();
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`omnodex ${args.join(" ")} did not finish:\n${out}`));
    }, 60000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, out });
    });
  });
}

async function controlEvents(omnodexHome) {
  const log = new EventLog({ root: path.join(omnodexHome, "event-log") });
  await log.init();
  try {
    return await log.readSession(CAPTURE_CONTROL_SESSION_ID);
  } finally {
    await log.close();
  }
}

test("status reports each platform, and a hook entry removed outside Omnodex raises a HIGH finding", async (t) => {
  const m = await machine(t);
  assert.equal((await run(["install", "--hooks", "codex", m.project, "--this-project", "--yes", "--no-connect"], m.env)).code, 0);

  const before = await run(["status", m.project], m.env, m.project);
  assert.equal(before.code, 0, before.out);
  assert.match(before.out, /\[status\] monitoring: +Codex ok/);

  // Something other than Omnodex empties the hook file.
  await fs.writeFile(path.join(m.project, ".codex", "hooks.json"), "{}\n");
  const after = await run(["status", m.project], m.env, m.project);
  assert.match(after.out, /\[status\] monitoring: +Codex 1 problem/);
  assert.match(after.out, /⚠ Codex hooks missing from .*hooks\.json/);
  assert.match(after.out, /run `omnodex install codex` in that project/);

  const events = await controlEvents(m.omnodexHome);
  const change = events.find((e) => e.event_type === "monitoring.unexplained_change");
  assert.ok(change, "unexplained change recorded");
  assert.equal(change.problem, "hooks_missing");
  const finding = events.find((e) => e.event_type === "risk.detected" && e.related_event_id === change.event_id);
  assert.equal(finding?.severity, "HIGH");

  // Reported once, not on every status.
  await run(["status", m.project], m.env, m.project);
  const again = await controlEvents(m.omnodexHome);
  assert.equal(again.filter((e) => e.event_type === "monitoring.unexplained_change").length, 1);
});

test("removing hooks with omnodex uninstall leaves nothing unexplained", async (t) => {
  const m = await machine(t);
  assert.equal((await run(["install", "--hooks", "codex", m.project, "--this-project", "--yes", "--no-connect"], m.env)).code, 0);
  await run(["status", m.project], m.env, m.project);
  assert.equal((await run(["uninstall", "codex", m.project, "--unattended"], m.env)).code, 0);
  const r = await run(["status", m.project], m.env, m.project);
  assert.doesNotMatch(r.out, /⚠/);
  const events = await controlEvents(m.omnodexHome);
  assert.ok(!events.some((e) => e.event_type === "monitoring.unexplained_change"));
});
