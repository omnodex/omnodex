// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
// A project-level Copilot hook file is kept out of git, and uninstall --mcp is
// a known option.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { addGitExclude, excludeFileFor, isTracked, removeGitExclude } from "../dist/git-exclude.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const REL = path.join(".github", "hooks", "omnodex.json");

function gitEnv(home) {
  return { ...process.env, HOME: home, USERPROFILE: home, GIT_CONFIG_GLOBAL: path.join(home, ".gitconfig"), GIT_CONFIG_NOSYSTEM: "1" };
}
function machine(t) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), "omnodex-gx-")));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const home = path.join(root, "home");
  const project = path.join(root, "proj");
  mkdirSync(home);
  mkdirSync(project);
  const env = { ...gitEnv(home), OMNODEX_HOME: path.join(home, ".omnodex"), OMNODEX_SINGLE_ROOT: "1", OMNODEX_NO_UPDATE_CHECK: "1", COPILOT_HOME: path.join(home, ".copilot"), OMNODEX_API_URL: "http://localhost:1" };
  const git = (...args) => spawnSync("git", args, { cwd: project, env, encoding: "utf8" });
  return { root, home, project, env, git };
}
function run(args, env, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env, cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, out }));
  });
}

test("the exclude file is the clone's own, and adding and removing the line is clean and repeatable", async (t) => {
  const m = machine(t);
  assert.equal(excludeFileFor(m.project), null, "outside a git repository there is nothing to exclude");
  assert.equal(await addGitExclude(m.project, REL), null);
  m.git("init", "-q");
  const file = excludeFileFor(m.project);
  assert.ok(file && file.replace(/\\/g, "/").endsWith("info/exclude"));
  assert.equal(await addGitExclude(m.project, REL), file);
  assert.equal(await addGitExclude(m.project, REL), file);
  const text = readFileSync(file, "utf8");
  assert.equal(text.split("/.github/hooks/omnodex.json").length - 1, 1, "added once");
  assert.equal(await removeGitExclude(m.project, REL), true);
  assert.equal(readFileSync(file, "utf8").includes("omnodex.json"), false);
  assert.equal(await removeGitExclude(m.project, REL), false);
});

test("install copilot in a project keeps its hook file out of git, and uninstall puts it back", async (t) => {
  const m = machine(t);
  m.git("init", "-q");
  const install = await run(["install", "copilot", m.project, "--this-project", "--no-connect", "--yes"], m.env, m.project);
  assert.equal(install.code, 0, install.out);
  const hooks = path.join(m.project, REL);
  assert.ok(existsSync(hooks), install.out);
  assert.match(install.out, /excluded from git/);
  assert.equal(m.git("status", "--porcelain", "--untracked-files=all").stdout.includes("omnodex.json"), false, "git does not see the file");
  assert.equal(m.git("check-ignore", "-q", REL).status, 0);
  const uninstall = await run(["uninstall", "copilot", m.project, "--confirm", "--unattended"], m.env, m.project);
  assert.equal(uninstall.code, 0, uninstall.out);
  assert.equal(existsSync(hooks), false);
  assert.equal(readFileSync(excludeFileFor(m.project), "utf8").includes("omnodex.json"), false);
});

test("a hook file that is already committed is reported, not hidden", async (t) => {
  const m = machine(t);
  m.git("init", "-q");
  mkdirSync(path.join(m.project, ".github", "hooks"), { recursive: true });
  writeFileSync(path.join(m.project, REL), "{}\n");
  m.git("add", "-A");
  assert.equal(isTracked(m.project, REL), true);
  const install = await run(["install", "copilot", m.project, "--this-project", "--no-connect", "--yes"], m.env, m.project);
  assert.match(install.out, /is committed in this repository/);
  assert.equal(readFileSync(excludeFileFor(m.project), "utf8").includes("omnodex.json"), false);
});

test("install in a folder that is not a git repository still works", async (t) => {
  const m = machine(t);
  const install = await run(["install", "copilot", m.project, "--this-project", "--no-connect", "--yes"], m.env, m.project);
  assert.equal(install.code, 0, install.out);
  assert.ok(existsSync(path.join(m.project, REL)));
});

test("uninstall --mcp is accepted and removes the MCP entry of Copilot, Cursor and OpenCode", async (t) => {
  const m = machine(t);
  const cursorMcp = path.join(m.home, ".cursor", "mcp.json");
  const entry = { omnodex: { command: "omnodex", args: ["mcp-proxy", "start"] } };
  mkdirSync(path.dirname(cursorMcp), { recursive: true });
  writeFileSync(cursorMcp, JSON.stringify({ mcpServers: entry }));
  mkdirSync(m.env.COPILOT_HOME, { recursive: true });
  writeFileSync(path.join(m.env.COPILOT_HOME, "mcp-config.json"), JSON.stringify({ mcpServers: entry }));
  for (const target of ["copilot", "cursor", "opencode"]) {
    const r = await run(["uninstall", target, "--mcp", "--confirm", "--unattended"], m.env, m.project);
    assert.doesNotMatch(r.out, /unknown option/i, `${target}: ${r.out}`);
    assert.equal(r.code, 0, `${target}: ${r.out}`);
  }
  assert.equal(JSON.parse(readFileSync(cursorMcp, "utf8")).mcpServers.omnodex, undefined);
  assert.equal(JSON.parse(readFileSync(path.join(m.env.COPILOT_HOME, "mcp-config.json"), "utf8")).mcpServers.omnodex, undefined);
});
