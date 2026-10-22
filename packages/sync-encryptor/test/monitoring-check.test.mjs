// Validation: monitoring config check
//
// Each installation in installations.json is compared with the agent's real
// config. A change from working to broken that no monitoring.changed marker
// explains writes monitoring.unexplained_change and a HIGH finding, once.
// Benign cases stay quiet: a marker, a deleted project, and anything already
// broken on the first run (the baseline after an upgrade).
//
// Every machine is a scratch directory; nothing reads the real home.
//
// Run: node --test packages/sync-encryptor/test/monitoring-check.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { EventLog } from "@omnodex/event-log";
import { CAPTURE_CONTROL_SESSION_ID, SCHEMA_VERSION } from "@omnodex/shared";
import {
  checkMonitoringConfig,
  codexHooksOff,
  MONITORING_CHECK_INTERVAL_MS,
  UNEXPLAINED_CHANGE_RULE_ID,
} from "../dist/monitoring-check.js";
import { runAutoSync } from "../dist/auto-sync.js";

const T0 = Date.parse("2026-10-22T12:00:00.000Z");
const LATER = T0 + MONITORING_CHECK_INTERVAL_MS + 1000;
const HOOK = { type: "command", command: "node /h/.omnodex/bin/claude-hook-launcher.js", "omnodex-managed": true };

async function machine(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "omnodex-moncheck-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const userHome = path.join(root, "home");
  const omnodexHome = path.join(userHome, ".omnodex");
  const project = path.join(root, "project");
  await mkdir(omnodexHome, { recursive: true });
  await mkdir(project, { recursive: true });
  const env = { CLAUDE_CONFIG_DIR: path.join(userHome, ".claude"), CODEX_HOME: path.join(userHome, ".codex") };
  const check = (at, extra = {}) => checkMonitoringConfig(omnodexHome, { now: at, userHome, env, ...extra });
  return { root, userHome, omnodexHome, project, env, check };
}

async function put(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, typeof value === "string" ? value : JSON.stringify(value, null, 2));
}

async function register(m, entries) {
  await put(path.join(m.omnodexHome, "installations.json"), {
    version: 2,
    installations: entries.map((e) => ({ installedAt: "2026-10-01T00:00:00.000Z", installedVersion: "0.9.0", usesLauncher: true, ...e })),
  });
}

async function controlEvents(home) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  try {
    return await log.readSession(CAPTURE_CONTROL_SESSION_ID);
  } finally {
    await log.close();
  }
}

async function marker(home, target, at) {
  const log = new EventLog({ root: path.join(home, "event-log") });
  await log.init();
  try {
    await log.append({
      schema_version: SCHEMA_VERSION, event_id: randomUUID(), session_id: CAPTURE_CONTROL_SESSION_ID,
      occurred_at: new Date(at).toISOString(), recorded_at: new Date(at).toISOString(), interceptor: "analyzer",
      event_type: "monitoring.changed", action: "exclude", target, cli_version: "0.9.0", actor: "terminal",
    });
  } finally {
    await log.close();
  }
}

const claudeProjectHooks = (m) => path.join(m.project, ".claude", "settings.local.json");

async function claudeProject(m) {
  await register(m, [{ target: "claude-code", component: "hooks", scope: "project", projectPath: m.project, settingsFile: "settings.local.json" }]);
  await put(claudeProjectHooks(m), { hooks: { PreToolUse: [{ matcher: "*", hooks: [HOOK] }] } });
}

describe("monitoring config check", () => {
  it("records a hook entry removed with no marker once, as an unexplained change and a HIGH finding", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    const first = await m.check(T0);
    assert.equal(first.ran, true);
    assert.deepEqual(first.checks.map((c) => c.state), ["ok"]);
    assert.equal(first.written.length, 0);

    await put(claudeProjectHooks(m), { hooks: {} });
    const second = await m.check(LATER);
    assert.deepEqual(second.checks.map((c) => c.state), ["hooks_missing"]);
    const [change, finding] = second.written;
    assert.equal(change.event_type, "monitoring.unexplained_change");
    assert.equal(change.problem, "hooks_missing");
    assert.equal(change.target, "claude-code");
    assert.equal(change.file, claudeProjectHooks(m));
    assert.equal(finding.event_type, "risk.detected");
    assert.equal(finding.severity, "HIGH");
    assert.equal(finding.rule_id, UNEXPLAINED_CHANGE_RULE_ID);
    assert.equal(finding.related_event_id, change.event_id);

    const logged = await controlEvents(m.omnodexHome);
    assert.deepEqual(logged.map((e) => e.event_type), ["monitoring.unexplained_change", "risk.detected"]);

    const third = await m.check(LATER + MONITORING_CHECK_INTERVAL_MS + 1000);
    assert.equal(third.written.length, 0, "the same change is reported once");
  });

  it("writes nothing when a monitoring.changed marker since the last check explains the change", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    await m.check(T0);
    await put(claudeProjectHooks(m), { hooks: {} });
    await marker(m.omnodexHome, "claude-code", T0 + 60_000);
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["hooks_missing"]);
    assert.equal(r.written.length, 0);
  });

  it("a marker for another platform does not explain the change", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    await m.check(T0);
    await put(claudeProjectHooks(m), { hooks: {} });
    await marker(m.omnodexHome, "codex", T0 + 60_000);
    assert.equal((await m.check(LATER)).written.length, 2);
  });

  it("treats anything already broken on the first run as the baseline", async (t) => {
    const m = await machine(t);
    await register(m, [{ target: "claude-code", component: "hooks", scope: "project", projectPath: m.project, settingsFile: "settings.local.json" }]);
    const first = await m.check(T0);
    assert.deepEqual(first.checks.map((c) => c.state), ["hooks_missing"]);
    assert.equal(first.written.length, 0);
    assert.equal((await m.check(LATER)).written.length, 0);
  });

  it("an installation added after the first run counts as working from its install time", async (t) => {
    const m = await machine(t);
    await register(m, []);
    await m.check(T0);
    await register(m, [{
      target: "claude-code", component: "hooks", scope: "project", projectPath: m.project,
      settingsFile: "settings.local.json", installedAt: new Date(T0 + 60_000).toISOString(),
    }]);
    // Removed before the next check ever saw it working.
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["hooks_missing"]);
    assert.equal(r.written.length, 2);
  });

  it("a deleted project is gone, not tampered with", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    await m.check(T0);
    await rm(m.project, { recursive: true, force: true });
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["project_gone"]);
    assert.equal(r.written.length, 0);
  });

  it("runs at most every 15 minutes unless forced", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    assert.equal((await m.check(T0)).ran, true);
    assert.equal((await m.check(T0 + 60_000)).ran, false);
    assert.equal((await m.check(T0 + 60_000, { force: true })).ran, true);
  });

  it("Claude Code: disableAllHooks in the user settings switches the hooks off", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    await m.check(T0);
    await put(path.join(m.env.CLAUDE_CONFIG_DIR, "settings.json"), { disableAllHooks: true });
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["hooks_disabled"]);
    assert.equal(r.written[0].problem, "hooks_disabled");
  });

  it("Codex: project hooks removed, then hooks = false in config.toml", async (t) => {
    const m = await machine(t);
    const hooks = path.join(m.project, ".codex", "hooks.json");
    await register(m, [{ target: "codex", component: "hooks", scope: "project", projectPath: m.project, settingsFile: "hooks.json" }]);
    await put(hooks, { hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "node codex-hook-launcher.js" }] }] } });
    assert.deepEqual((await m.check(T0)).checks.map((c) => c.state), ["ok"]);
    await put(path.join(m.env.CODEX_HOME, "config.toml"), "[features]\nweb_search = true\nhooks = false\n");
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["hooks_disabled"]);
    assert.equal(r.written.length, 2);
  });

  it("Antigravity: enabled false on the Omnodex group, and the MCP entry removed", async (t) => {
    const m = await machine(t);
    const hooks = path.join(m.userHome, ".gemini", "config", "hooks.json");
    const mcp = path.join(m.project, ".agents", "mcp_config.json");
    await register(m, [
      { target: "antigravity", component: "hooks", scope: "user", settingsFile: hooks },
      { target: "antigravity", component: "mcp", scope: "project", projectPath: m.project, settingsFile: "mcp_config.json" },
    ]);
    const group = { Stop: [{ type: "command", command: "node antigravity-hook-launcher.js --user-scope Stop" }] };
    await put(hooks, { omnodex: group });
    await put(mcp, { mcpServers: { omnodex: { command: "node" }, github: {} } });
    assert.deepEqual((await m.check(T0)).checks.map((c) => c.state), ["ok", "ok"]);
    await put(hooks, { omnodex: { enabled: false, ...group } });
    await put(mcp, { mcpServers: { github: {} } });
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["hooks_disabled", "mcp_missing"]);
    assert.deepEqual(r.written.filter((e) => e.event_type === "monitoring.unexplained_change").map((e) => e.problem), ["hooks_disabled", "mcp_missing"]);
  });

  it("plugins: disabled in Claude Code's enabledPlugins, and a Codex plugin directory deleted", async (t) => {
    const m = await machine(t);
    const claudePlugin = path.join(m.omnodexHome, "plugins", "claude-marketplace", "omnodex-cowork");
    const codexPlugin = path.join(m.env.CODEX_HOME, "plugins", "omnodex-codex");
    await register(m, [
      { target: "claude-code", component: "plugin", scope: "user", settingsFile: "omnodex-cowork", pluginPath: claudePlugin },
      { target: "codex", component: "plugin", scope: "user", settingsFile: "omnodex-codex", pluginPath: codexPlugin },
    ]);
    await mkdir(claudePlugin, { recursive: true });
    await mkdir(codexPlugin, { recursive: true });
    await put(path.join(m.env.CLAUDE_CONFIG_DIR, "settings.json"), { enabledPlugins: { "omnodex-cowork@omnodex-local": true } });
    assert.deepEqual((await m.check(T0)).checks.map((c) => c.state), ["ok", "ok"]);
    await put(path.join(m.env.CLAUDE_CONFIG_DIR, "settings.json"), { enabledPlugins: { "omnodex-cowork@omnodex-local": false } });
    await rm(codexPlugin, { recursive: true, force: true });
    const r = await m.check(LATER);
    assert.deepEqual(r.checks.map((c) => c.state), ["plugin_disabled", "plugin_missing"]);
    assert.equal(r.written.length, 4);
  });

  it("an entry the registry no longer has is not checked", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    await m.check(T0);
    await put(claudeProjectHooks(m), { hooks: {} });
    await register(m, []);
    const r = await m.check(LATER);
    assert.equal(r.checks.length, 0);
    assert.equal(r.written.length, 0);
  });

  it("never throws on a damaged registry or config", async (t) => {
    const m = await machine(t);
    await put(path.join(m.omnodexHome, "installations.json"), "{not json");
    const r = await m.check(T0);
    assert.equal(r.ran, true);
    assert.equal(r.checks.length, 0);
    await claudeProject(m);
    await put(claudeProjectHooks(m), "{damaged");
    assert.deepEqual((await m.check(LATER)).checks.map((c) => c.state), ["hooks_missing"]);
  });

  it("pushes what it writes to the live relay", async (t) => {
    const m = await machine(t);
    await claudeProject(m);
    await m.check(T0);
    await put(claudeProjectHooks(m), { hooks: {} });
    const pushed = [];
    await m.check(LATER, { push: async (events) => pushed.push(...events) });
    assert.deepEqual(pushed.map((e) => e.event_type), ["monitoring.unexplained_change", "risk.detected"]);
  });
});

describe("codexHooksOff", () => {
  it("reads [features] hooks and the older codex_hooks, and the dotted form", () => {
    assert.equal(codexHooksOff("[features]\nhooks = false\n"), true);
    assert.equal(codexHooksOff("[features]\ncodex_hooks=false"), true);
    assert.equal(codexHooksOff("features.hooks = false\n"), true);
    assert.equal(codexHooksOff("[features]\nhooks = true\n"), false);
    assert.equal(codexHooksOff("[other]\nhooks = false\n"), false);
    assert.equal(codexHooksOff("[features]\n# hooks = false\n"), false);
  });
});

describe("background pass", () => {
  it("runAutoSync runs the config check", async (t) => {
    const m = await machine(t);
    let checked = null;
    await runAutoSync(m.omnodexHome, {
      refreshLicense: async () => undefined,
      submitUsage: async () => undefined,
      submitSignals: async () => undefined,
      checkMonitoring: async (home) => {
        checked = home;
      },
    });
    assert.equal(checked, m.omnodexHome);
  });

  it("the default check writes its state file", async (t) => {
    const m = await machine(t);
    await runAutoSync(m.omnodexHome, {
      refreshLicense: async () => undefined,
      submitUsage: async () => undefined,
      submitSignals: async () => undefined,
      pushFn: async () => true,
    });
    const state = JSON.parse(await readFile(path.join(m.omnodexHome, "monitoring-check.json"), "utf8"));
    assert.ok(state.last_run_at);
  });
});
