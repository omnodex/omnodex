/**
 * Monitoring markers: every change Omnodex makes to its own monitoring is
 * recorded, and removing it needs a person at a terminal or --unattended.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { EventLog, outboundEvents, startPause } from "@omnodex/event-log";
import { CAPTURE_CONTROL_SESSION_ID, monitoringChangeRows } from "@omnodex/shared";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

/** An isolated home; never the developer's real ~/.omnodex or agents. */
async function machine(t) {
  const root = realpathSync(await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-markers-")));
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
  };
  return { root, home, omnodexHome, project, env };
}

function run(args, env) {
  const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
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

/** Import the CLI modules with OMNODEX_HOME pointed at a scratch home. */
async function withHome(omnodexHome, fn) {
  const saved = process.env.OMNODEX_HOME;
  process.env.OMNODEX_HOME = omnodexHome;
  try {
    return await fn();
  } finally {
    if (saved === undefined) delete process.env.OMNODEX_HOME;
    else process.env.OMNODEX_HOME = saved;
  }
}

test("registry changes write install, update and uninstall markers; a same-version reinstall writes none", async (t) => {
  const m = await machine(t);
  const { addInstallation, removeInstallation } = await import("../dist/registry.js");
  const entry = {
    target: "codex", component: "plugin", scope: "user", settingsFile: "marketplace.json",
    installedAt: "2026-10-21T00:00:00.000Z", installedVersion: "0.9.0", usesLauncher: true, pluginVersion: "0.4.0",
  };
  await withHome(m.omnodexHome, async () => {
    await addInstallation(entry);
    await addInstallation(entry);
    await addInstallation({ ...entry, pluginVersion: "0.5.0" });
    await removeInstallation("codex", undefined, "plugin");
  });
  const rows = monitoringChangeRows(await controlEvents(m.omnodexHome));
  assert.deepEqual(rows.map((r) => [r.action, r.from, r.to]), [
    ["install", null, "0.4.0"],
    ["update", "0.4.0", "0.5.0"],
    ["uninstall", "0.5.0", null],
  ]);
  for (const r of rows) {
    assert.equal(r.target, "codex");
    assert.equal(r.component, "plugin");
    assert.equal(r.scope, "user");
    assert.ok(r.cli_version);
  }
});

test("leaving a project out, bringing it back and every-project recording write markers", async (t) => {
  const m = await machine(t);
  const { addExclusion, removeExclusion, setEverywhere } = await import("../dist/hook-scope.js");
  await setEverywhere(m.omnodexHome, "claude-code", true);
  await setEverywhere(m.omnodexHome, "claude-code", true);
  await addExclusion(m.omnodexHome, "claude-code", m.project);
  await removeExclusion(m.omnodexHome, "claude-code", m.project);
  await setEverywhere(m.omnodexHome, "claude-code", false);
  const rows = monitoringChangeRows(await controlEvents(m.omnodexHome));
  assert.deepEqual(rows.map((r) => r.action), ["everywhere_on", "exclude", "include", "everywhere_off"]);
  assert.ok(rows[1].project_path);
});

test("changing the enforcement mode writes a marker with both modes", async (t) => {
  const m = await machine(t);
  const { setMode } = await import("../dist/enforce-command.js");
  await setMode(m.omnodexHome, "shadow");
  await setMode(m.omnodexHome, "shadow");
  const rows = monitoringChangeRows(await controlEvents(m.omnodexHome));
  assert.deepEqual(rows.map((r) => [r.action, r.from, r.to]), [["enforce_mode", "monitor", "shadow"]]);
});

test("connecting a machine writes a marker; rotating its token does not", async (t) => {
  const m = await machine(t);
  const { updateStreamConfig } = await import("../dist/stream-config.js");
  await updateStreamConfig(m.omnodexHome, { api_token: "omx_test_first", passphrase: "secret" });
  await updateStreamConfig(m.omnodexHome, { api_token: "omx_test_rotated" });
  const rows = monitoringChangeRows(await controlEvents(m.omnodexHome));
  assert.deepEqual(rows.map((r) => r.action), ["connect"]);
});

test("monitoring markers still leave the machine during a sync pause", async (t) => {
  const m = await machine(t);
  const { recordMonitoringChange } = await import("../dist/monitoring-markers.js");
  const marker = await recordMonitoringChange({ action: "uninstall", target: "codex" }, m.omnodexHome);
  await startPause(m.omnodexHome, "sync", { untilMs: null, by: "cli" });
  const out = await outboundEvents([marker], m.omnodexHome);
  assert.equal(out.length, 1);
});

test("uninstall without a terminal is refused and changes nothing", async (t) => {
  const m = await machine(t);
  assert.equal((await run(["install", "--hooks", "codex", m.project, "--this-project", "--yes", "--no-connect"], m.env)).code, 0);
  const r = await run(["uninstall", "codex", m.project, "--confirm"], m.env);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /needs a person at an interactive terminal/);
  assert.match(await fs.readFile(path.join(m.project, ".codex", "hooks.json"), "utf8"), /codex-hook/);
  const rows = monitoringChangeRows(await controlEvents(m.omnodexHome));
  assert.ok(!rows.some((row) => row.action === "uninstall"), "no uninstall marker");
});

test("uninstall --unattended removes the hooks, marks the change unattended and raises a MEDIUM finding", async (t) => {
  const m = await machine(t);
  assert.equal((await run(["install", "--hooks", "codex", m.project, "--this-project", "--yes", "--no-connect"], m.env)).code, 0);
  const r = await run(["uninstall", "codex", m.project, "--unattended"], m.env);
  assert.equal(r.code, 0, r.out);

  const events = await controlEvents(m.omnodexHome);
  const rows = monitoringChangeRows(events);
  const install = rows.find((row) => row.action === "install");
  const removal = rows.find((row) => row.action === "uninstall");
  assert.ok(install, "install marker");
  assert.ok(removal, "uninstall marker");
  assert.equal(removal.actor, "unattended");
  assert.equal(removal.target, "codex");

  const finding = events.find((e) => e.event_type === "risk.detected");
  assert.ok(finding, "finding");
  assert.equal(finding.severity, "MEDIUM");
  assert.equal(finding.rule_id, "RULE_SELF_PROTECTION_UNATTENDED_REMOVAL");
  assert.equal(finding.related_event_id, removal.event_id);
  assert.match(finding.description, /--unattended/);
});
