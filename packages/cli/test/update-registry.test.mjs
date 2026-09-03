/**
 * Tests for the update and registry modules (FS-012).
 *
 * Tests:
 *   1. compareSemver: correct ordering of version strings
 *   2. Registry CRUD: add, find, remove, list, stale detection
 *   3. Update cache: read/write cycle
 *   4. Launcher template: generation and currency check
 */

import { test, beforeEach } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// compareSemver (pure function, no I/O)
// ---------------------------------------------------------------------------

import { compareSemver } from "../dist/update.js";

test("compareSemver: equal versions", () => {
  assert.equal(compareSemver("1.2.3", "1.2.3"), 0);
});

test("compareSemver: strips leading v", () => {
  assert.equal(compareSemver("v1.2.3", "1.2.3"), 0);
});

test("compareSemver: major difference", () => {
  assert.equal(compareSemver("1.0.0", "2.0.0"), -1);
  assert.equal(compareSemver("2.0.0", "1.0.0"), 1);
});

test("compareSemver: minor difference", () => {
  assert.equal(compareSemver("1.1.0", "1.2.0"), -1);
  assert.equal(compareSemver("1.3.0", "1.2.0"), 1);
});

test("compareSemver: patch difference", () => {
  assert.equal(compareSemver("1.2.3", "1.2.4"), -1);
  assert.equal(compareSemver("1.2.5", "1.2.4"), 1);
});

test("compareSemver: missing parts treated as 0", () => {
  assert.equal(compareSemver("1.2", "1.2.0"), 0);
  assert.equal(compareSemver("1", "1.0.0"), 0);
});

// ---------------------------------------------------------------------------
// Registry (uses temp OMNODEX_HOME)
// ---------------------------------------------------------------------------

import {
  addInstallation,
  removeInstallation,
  listInstallations,
  findInstallations,
  findStaleInstallations,
  getInstalledVersion,
} from "../dist/registry.js";

let tmpHome;

beforeEach(async () => {
  tmpHome = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-test-"));
  process.env.OMNODEX_HOME = tmpHome;
});

test("registry: empty listing on fresh home", async () => {
  const list = await listInstallations();
  assert.deepEqual(list, []);
});

test("registry: add and list installation", async () => {
  const install = {
    target: "claude-code",
    projectPath: "/tmp/test-project",
    settingsFile: "settings.local.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: true,
    launcherPath: path.join(tmpHome, "bin", "claude-hook-launcher.js"),
  };
  await addInstallation(install);

  const list = await listInstallations();
  assert.equal(list.length, 1);
  assert.equal(list[0].target, "claude-code");
  assert.equal(list[0].projectPath, "/tmp/test-project");
  assert.equal(list[0].usesLauncher, true);
});

test("registry: add replaces same target+project (idempotent)", async () => {
  const base = {
    target: "codex",
    projectPath: "/tmp/project-a",
    settingsFile: "hooks.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: false,
  };
  await addInstallation(base);
  await addInstallation({ ...base, installedVersion: "1.1.0", usesLauncher: true });

  const list = await listInstallations();
  assert.equal(list.length, 1);
  assert.equal(list[0].installedVersion, "1.1.0");
  assert.equal(list[0].usesLauncher, true);
});

test("registry: find by target", async () => {
  await addInstallation({
    target: "claude-code",
    projectPath: "/tmp/p1",
    settingsFile: "settings.local.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: true,
  });
  await addInstallation({
    target: "codex",
    projectPath: "/tmp/p2",
    settingsFile: "hooks.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: true,
  });

  const claude = await findInstallations({ target: "claude-code" });
  assert.equal(claude.length, 1);
  assert.equal(claude[0].projectPath, "/tmp/p1");

  const codex = await findInstallations({ target: "codex" });
  assert.equal(codex.length, 1);
});

test("registry: remove installation", async () => {
  await addInstallation({
    target: "claude-code",
    projectPath: "/tmp/p1",
    settingsFile: "settings.local.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: true,
  });

  const removed = await removeInstallation("claude-code", "/tmp/p1");
  assert.equal(removed, true);

  const list = await listInstallations();
  assert.equal(list.length, 0);

  // Removing again returns false
  const again = await removeInstallation("claude-code", "/tmp/p1");
  assert.equal(again, false);
});

test("registry: findStaleInstallations returns only legacy entries", async () => {
  await addInstallation({
    target: "claude-code",
    projectPath: "/tmp/p1",
    settingsFile: "settings.local.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: true,
  });
  await addInstallation({
    target: "codex",
    projectPath: "/tmp/p2",
    settingsFile: "hooks.json",
    installedAt: new Date().toISOString(),
    installedVersion: "1.0.0",
    usesLauncher: false, // legacy
  });

  const stale = await findStaleInstallations();
  assert.equal(stale.length, 1);
  assert.equal(stale[0].target, "codex");
});

test("registry: getInstalledVersion returns a string", () => {
  const version = getInstalledVersion();
  assert.equal(typeof version, "string");
  // Should be either a valid semver or the dev fallback
  assert.ok(version.match(/^\d+\.\d+\.\d+/) || version === "0.0.0-dev");
});

// ---------------------------------------------------------------------------
// Launcher template
// ---------------------------------------------------------------------------

import { writeLauncher, launcherPath, isLauncherCurrent } from "../dist/launcher-template.js";

test("launcher: launcherPath returns expected location", () => {
  const p = launcherPath("claude-code");
  assert.ok(p.includes(".omnodex"));
  assert.ok(p.includes("bin"));
  assert.ok(p.endsWith("claude-hook-launcher.js"));
});

test("launcher: writeLauncher creates a file", async () => {
  const dest = await writeLauncher("claude-code");
  const stat = await fs.stat(dest);
  assert.ok(stat.isFile());
  assert.ok(stat.size > 100); // not empty

  const content = await fs.readFile(dest, "utf8");
  assert.ok(content.includes("#!/usr/bin/env node"));
  assert.ok(content.includes("claude-code"));
  assert.ok(content.includes("findShim"));
});

test("launcher: isLauncherCurrent returns true after fresh write", async () => {
  await writeLauncher("codex");
  const current = await isLauncherCurrent("codex");
  assert.equal(current, true);
});

test("launcher: isLauncherCurrent returns false for missing file", async () => {
  const current = await isLauncherCurrent("antigravity");
  assert.equal(current, false);
});

test("launcher: isLauncherCurrent returns false for modified file", async () => {
  const dest = await writeLauncher("antigravity");
  await fs.appendFile(dest, "\n// tampered\n");
  const current = await isLauncherCurrent("antigravity");
  assert.equal(current, false);
});

// ---------------------------------------------------------------------------
// Source install detection (detectInstallMethod, getSourceInstallInfo)
// ---------------------------------------------------------------------------

import { detectInstallMethod, getSourceInstallInfo } from "../dist/update.js";

test("detectInstallMethod: returns 'source' when run from the source tree", () => {
  const method = detectInstallMethod();
  assert.equal(method, "source");
});

test("getSourceInstallInfo: returns non-null when run from the source tree", () => {
  const info = getSourceInstallInfo();
  assert.notEqual(info, null);
  assert.notEqual(info, undefined);
});

test("getSourceInstallInfo: returns expected shape (branch, sha, dirty)", () => {
  const info = getSourceInstallInfo();
  assert.equal(typeof info.branch, "string", "branch should be a string");
  assert.ok(info.branch.length > 0, "branch should not be empty");
  assert.equal(typeof info.sha, "string", "sha should be a string");
  assert.ok(info.sha.length > 0, "sha should not be empty");
  assert.equal(typeof info.dirty, "boolean", "dirty should be a boolean");
});

test("getSourceInstallInfo: repoRoot ends with the omnodex repo directory", () => {
  const info = getSourceInstallInfo();
  assert.equal(typeof info.repoRoot, "string", "repoRoot should be a string");
  const normalized = info.repoRoot.replace(/\\/g, "/");
  assert.ok(
    normalized.endsWith("/omnodex") || normalized.endsWith("/omnodex/"),
    `repoRoot should end with the omnodex repo directory, got: ${info.repoRoot}`
  );
});

test("getSourceInstallInfo: sha is a short hex string", () => {
  const info = getSourceInstallInfo();
  assert.match(
    info.sha,
    /^[0-9a-f]{7,}$/,
    `sha should be a short hex string, got: ${info.sha}`
  );
});
