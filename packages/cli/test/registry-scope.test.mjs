/**
 * Tests for the installation registry's component and scope fields,
 * and for migrating version 1 registry files.
 */

import { test, beforeEach } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import {
  addInstallation,
  removeInstallation,
  listInstallations,
  findInstallations,
  findStaleInstallations,
} from "../dist/registry.js";

let tmpHome;

beforeEach(async () => {
  tmpHome = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-registry-"));
  process.env.OMNODEX_HOME = tmpHome;
});

const registryFile = () => path.join(tmpHome, "installations.json");

async function writeV1(installations) {
  await fs.writeFile(registryFile(), JSON.stringify({ version: 1, installations }, null, 2));
}

async function readFile() {
  return JSON.parse(await fs.readFile(registryFile(), "utf8"));
}

const now = "2026-10-15T00:00:00.000Z";

test("migration: version 1 hooks entries become project-scope hooks", async () => {
  await writeV1([
    { target: "claude-code", projectPath: "/tmp/p1", settingsFile: "settings.local.json", installedAt: now, installedVersion: "0.9.0", usesLauncher: true },
    { target: "codex", projectPath: "/tmp/p2", settingsFile: "hooks.json", installedAt: now, installedVersion: "0.9.0", usesLauncher: true },
  ]);
  const list = await listInstallations();
  assert.equal(list.length, 2);
  for (const entry of list) {
    assert.equal(entry.component, "hooks");
    assert.equal(entry.scope, "project");
  }
});

test("migration: a version 1 Antigravity MCP config entry becomes an mcp component", async () => {
  await writeV1([
    { target: "antigravity", projectPath: "/tmp/p1", settingsFile: "mcp_config.json", installedAt: now, installedVersion: "0.9.0", usesLauncher: true },
  ]);
  const [entry] = await listInstallations();
  assert.equal(entry.component, "mcp");
  assert.equal(entry.scope, "project");
});

test("migration: the next write saves version 2 and keeps every entry", async () => {
  await writeV1([
    { target: "codex", projectPath: "/tmp/p1", settingsFile: "hooks.json", installedAt: now, installedVersion: "0.9.0", usesLauncher: true },
  ]);
  await addInstallation({
    target: "claude-code", component: "hooks", scope: "project", projectPath: "/tmp/p2",
    settingsFile: "settings.local.json", installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
  });
  const file = await readFile();
  assert.equal(file.version, 2);
  assert.equal(file.installations.length, 2);
  const codex = file.installations.find((i) => i.target === "codex");
  assert.equal(codex.component, "hooks");
  assert.equal(codex.scope, "project");
});

test("unrecognized entries are preserved, not dropped", async () => {
  const odd = { target: "codex", component: "something-new", scope: "user", settingsFile: "x.json" };
  const garbage = { hello: "world" };
  await fs.writeFile(registryFile(), JSON.stringify({
    version: 3,
    installations: [
      odd,
      garbage,
      { target: "codex", projectPath: "/tmp/p1", settingsFile: "hooks.json", installedAt: now, installedVersion: "1.0.0", usesLauncher: true },
    ],
  }));

  const list = await listInstallations();
  assert.equal(list.length, 1, "only the readable entry is listed");

  await addInstallation({
    target: "claude-code", component: "hooks", scope: "project", projectPath: "/tmp/p2",
    settingsFile: "settings.local.json", installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
  });
  const file = await readFile();
  assert.deepEqual(file.unrecognized, [odd, garbage]);
  assert.equal(file.installations.length, 2);
});

test("user-scope entries need no project path and are replaced in place", async () => {
  const plugin = {
    target: "codex", component: "plugin", scope: "user", settingsFile: "marketplace.json",
    installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
    pluginPath: "/home/case/.omnodex/plugins/codex", pluginVersion: "0.2.0",
  };
  await addInstallation(plugin);
  await addInstallation({ ...plugin, pluginVersion: "0.3.0", pluginOverride: true });

  const plugins = await findInstallations({ component: "plugin" });
  assert.equal(plugins.length, 1);
  assert.equal(plugins[0].projectPath, undefined);
  assert.equal(plugins[0].pluginVersion, "0.3.0");
  assert.equal(plugins[0].pluginOverride, true);
});

test("a project entry without a project path is rejected", async () => {
  await assert.rejects(
    addInstallation({
      target: "codex", component: "hooks", scope: "project", settingsFile: "hooks.json",
      installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
    }),
  );
});

test("hooks and MCP for the same project are separate entries", async () => {
  const base = {
    target: "antigravity", scope: "project", projectPath: "/tmp/p1",
    installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
  };
  await addInstallation({ ...base, component: "hooks", settingsFile: "hooks.json" });
  await addInstallation({ ...base, component: "mcp", settingsFile: "mcp_config.json" });
  assert.equal((await listInstallations()).length, 2);

  // Removing hooks leaves the MCP entry.
  assert.equal(await removeInstallation("antigravity", "/tmp/p1", "hooks"), true);
  const left = await listInstallations();
  assert.equal(left.length, 1);
  assert.equal(left[0].component, "mcp");
});

test("removing a user-scope plugin does not touch project hooks", async () => {
  await addInstallation({
    target: "codex", component: "hooks", scope: "project", projectPath: "/tmp/p1",
    settingsFile: "hooks.json", installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
  });
  await addInstallation({
    target: "codex", component: "plugin", scope: "user", settingsFile: "marketplace.json",
    installedAt: now, installedVersion: "1.0.0", usesLauncher: true,
  });
  assert.equal(await removeInstallation("codex", undefined, "plugin"), true);
  const left = await listInstallations();
  assert.equal(left.length, 1);
  assert.equal(left[0].component, "hooks");
});

test("plugins are never reported as stale launchers", async () => {
  await addInstallation({
    target: "codex", component: "plugin", scope: "user", settingsFile: "marketplace.json",
    installedAt: now, installedVersion: "1.0.0", usesLauncher: false,
  });
  assert.deepEqual(await findStaleInstallations(), []);
});
