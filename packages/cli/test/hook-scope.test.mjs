/**
 * Hook scope: record every project (hooks in each agent's user-level file)
 * or only one, leave single projects out, and never record an event twice.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { promises as fs, existsSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  addExclusion,
  exclusionFor,
  readHookScope,
  removeExclusion,
  setEverywhere,
  userHooksFile,
} from "../dist/hook-scope.js";
import { generateLauncherSource } from "../dist/launcher-template.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

async function tempRoot(t) {
  // realpath: on macOS the temp dir is under /var, a symlink to /private/var.
  const root = realpathSync(await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-scope-")));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

/** An isolated home with two projects; never the developer's real ~/.omnodex or agents. */
async function machine(t) {
  const root = await tempRoot(t);
  const home = path.join(root, "home");
  const omnodexHome = path.join(home, ".omnodex");
  const project = path.join(root, "project");
  const other = path.join(root, "other");
  await fs.mkdir(project, { recursive: true });
  await fs.mkdir(other, { recursive: true });
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    OMNODEX_HOME: omnodexHome,
    CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
    CODEX_HOME: path.join(home, ".codex"),
    WSL_DISTRO_NAME: "",
    // /proc/version still says WSL on a WSL machine; point the Windows scan at nothing.
    OMNODEX_WSL_MOUNT_ROOT: path.join(root, "no-windows-mount"),
  };
  return { root, home, omnodexHome, project, other, env };
}

function run(args, env, { cwd } = {}) {
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

const readJson = async (file) => JSON.parse(await fs.readFile(file, "utf8"));

// ---------------------------------------------------------------------------
// The stored model
// ---------------------------------------------------------------------------

test("exclusions cover subfolders, can be removed from inside, and go when every-project recording stops", async (t) => {
  const m = await machine(t);
  await setEverywhere(m.omnodexHome, "codex", true);
  await addExclusion(m.omnodexHome, "codex", m.project);
  let scope = await readHookScope(m.omnodexHome);
  assert.deepEqual(scope.everywhere, ["codex"]);
  const stored = Object.keys(scope.excluded)[0];
  assert.equal(stored.toLowerCase(), m.project.toLowerCase());
  assert.equal(exclusionFor(scope, "codex", path.join(m.project, "src", "deep")), stored);
  assert.equal(exclusionFor(scope, "codex", `${m.project}-sibling`), null);
  assert.equal(exclusionFor(scope, "claude-code", m.project), null);

  // Installing in a subfolder of a left-out project records it again.
  assert.equal(await removeExclusion(m.omnodexHome, "codex", path.join(m.project, "src")), stored);
  assert.equal(exclusionFor(await readHookScope(m.omnodexHome), "codex", m.project), null);

  await addExclusion(m.omnodexHome, "codex", m.project);
  await setEverywhere(m.omnodexHome, "codex", false);
  scope = await readHookScope(m.omnodexHome);
  assert.deepEqual(scope, { version: 1, everywhere: [], excluded: {} });
});

test("userHooksFile names each agent's user-level file and honors CLAUDE_CONFIG_DIR and CODEX_HOME", () => {
  assert.equal(userHooksFile("claude-code", "/h", {}), path.join("/h", ".claude", "settings.json"));
  assert.equal(userHooksFile("claude-code", "/h", { CLAUDE_CONFIG_DIR: "/cc" }), path.join("/cc", "settings.json"));
  assert.equal(userHooksFile("codex", "/h", {}), path.join("/h", ".codex", "hooks.json"));
  assert.equal(userHooksFile("codex", "/h", { CODEX_HOME: "/c" }), path.join("/c", "hooks.json"));
  assert.equal(userHooksFile("antigravity", "/h", {}), path.join("/h", ".gemini", "config", "hooks.json"));
});

// ---------------------------------------------------------------------------
// install / uninstall / status
// ---------------------------------------------------------------------------

test("install --everywhere writes each agent's user-level file and keeps what else is there", async (t) => {
  const m = await machine(t);
  // Someone else's hooks and settings in the user-level files.
  await fs.mkdir(path.join(m.home, ".claude"), { recursive: true });
  await fs.writeFile(path.join(m.home, ".claude", "settings.json"), JSON.stringify({
    model: "opus",
    hooks: { Stop: [{ hooks: [{ type: "command", command: "say done" }] }] },
  }));
  await fs.mkdir(path.join(m.home, ".gemini", "config"), { recursive: true });
  await fs.writeFile(path.join(m.home, ".gemini", "config", "hooks.json"), JSON.stringify({ linter: { Stop: [] } }));

  for (const target of ["claude-code", "codex", "antigravity"]) {
    const r = await run(["install", "--hooks", target, m.project, "--everywhere", "--no-connect"], m.env);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /now records every project/);
  }

  const claude = await readJson(path.join(m.home, ".claude", "settings.json"));
  assert.equal(claude.model, "opus");
  assert.ok(claude.hooks.Stop.some((g) => g.hooks.some((h) => h.command === "say done")));
  const claudeCommand = claude.hooks.PreToolUse[0].hooks[0].command;
  assert.match(claudeCommand, /claude-hook-launcher\.js"? --user-scope$/);

  const codex = await readJson(path.join(m.home, ".codex", "hooks.json"));
  assert.match(codex.hooks.PostToolUse[0].hooks[0].command, /codex-hook-launcher\.js"? --user-scope$/);

  const agy = await readJson(path.join(m.home, ".gemini", "config", "hooks.json"));
  assert.deepEqual(agy.linter, { Stop: [] });
  assert.match(agy.omnodex.Stop[0].command, /antigravity-hook-launcher\.js"? --user-scope Stop$/);

  // Nothing written into the project.
  assert.ok(!existsSync(path.join(m.project, ".claude")));
  assert.ok(!existsSync(path.join(m.project, ".codex")));
  assert.ok(!existsSync(path.join(m.project, ".agents")));

  assert.deepEqual((await readHookScope(m.omnodexHome)).everywhere, ["antigravity", "claude-code", "codex"]);
  const registry = await readJson(path.join(m.omnodexHome, "installations.json"));
  assert.deepEqual(
    registry.installations.map((i) => `${i.target}:${i.scope}`).sort(),
    ["antigravity:user", "claude-code:user", "codex:user"],
  );
});

test("without a terminal or flags a one-agent install stays in the project; --yes records every project", async (t) => {
  const m = await machine(t);
  const plain = await run(["install", "--hooks", "codex", m.project, "--no-connect"], m.env);
  assert.equal(plain.code, 0, plain.out);
  assert.ok(existsSync(path.join(m.project, ".codex", "hooks.json")));
  assert.ok(!existsSync(path.join(m.home, ".codex", "hooks.json")));

  const yes = await run(["install", "--hooks", "codex", m.project, "--yes", "--no-connect"], m.env);
  assert.equal(yes.code, 0, yes.out);
  assert.ok(existsSync(path.join(m.home, ".codex", "hooks.json")));
  assert.match(yes.out, /this project also has its own Codex hooks; they step aside/);
});

test("--everywhere and --legacy-shim together are refused", async (t) => {
  const m = await machine(t);
  const r = await run(["install", "--hooks", "codex", m.project, "--everywhere", "--legacy-shim", "--no-connect"], m.env);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /cannot be combined with --legacy-shim/);
  assert.ok(!existsSync(path.join(m.home, ".codex", "hooks.json")));
});

test("uninstall in a project leaves it out, status says so, and install records it again", async (t) => {
  const m = await machine(t);
  assert.equal((await run(["install", "--hooks", "codex", m.project, "--everywhere", "--no-connect"], m.env)).code, 0);

  const out = await run(["uninstall", "codex", m.project, "--confirm"], m.env);
  assert.equal(out.code, 0, out.out);
  assert.match(out.out, /Codex no longer records/);
  assert.ok(existsSync(path.join(m.home, ".codex", "hooks.json")), "user-level hooks stay");
  assert.ok(exclusionFor(await readHookScope(m.omnodexHome), "codex", m.project));

  const again = await run(["uninstall", "codex", m.project, "--confirm"], m.env);
  assert.match(again.out, /already left out for Codex/);

  const here = await run(["status", m.project], m.env);
  assert.match(here.out, /Codex: records every project, but this project is left out/);
  const elsewhere = await run(["status", m.other], m.env);
  assert.match(elsewhere.out, /Codex: records every project\n/);
  const all = await run(["status", "--all"], m.env);
  assert.match(all.out, /Recording every project: Codex/);
  // Stored paths are lowercase on Windows.
  assert.match(all.out, new RegExp(`left out: ${m.project.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")} \\(Codex\\)`, "i"));

  // Without a flag, an agent that records every project keeps doing so.
  const back = await run(["install", "--hooks", "codex", m.project, "--no-connect"], m.env);
  assert.equal(back.code, 0, back.out);
  assert.match(back.out, /had been left out; Codex records it again/);
  assert.equal(exclusionFor(await readHookScope(m.omnodexHome), "codex", m.project), null);
  assert.ok(!existsSync(path.join(m.project, ".codex", "hooks.json")));
});

test("uninstall --everywhere removes only Omnodex's user-level hooks and stops every-project recording", async (t) => {
  const m = await machine(t);
  await fs.mkdir(path.join(m.home, ".codex"), { recursive: true });
  await fs.writeFile(path.join(m.home, ".codex", "hooks.json"), JSON.stringify({
    hooks: { Stop: [{ hooks: [{ type: "command", command: "notify" }] }] },
  }));
  assert.equal((await run(["install", "--hooks", "codex", m.project, "--everywhere", "--no-connect"], m.env)).code, 0);
  await run(["uninstall", "codex", m.other, "--confirm"], m.env);

  const r = await run(["uninstall", "codex", "--everywhere", "--confirm"], m.env);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /removed Codex every-project hooks/);
  const left = await readJson(path.join(m.home, ".codex", "hooks.json"));
  assert.deepEqual(left, { hooks: { Stop: [{ hooks: [{ type: "command", command: "notify" }] }] } });
  assert.deepEqual(await readHookScope(m.omnodexHome), { version: 1, everywhere: [], excluded: {} });
  const registry = await readJson(path.join(m.omnodexHome, "installations.json"));
  assert.deepEqual(registry.installations, []);
});

test("uninstall with no target and nothing in the project leaves the project out for every recording agent", async (t) => {
  const m = await machine(t);
  for (const target of ["claude-code", "codex"]) {
    assert.equal((await run(["install", "--hooks", target, m.project, "--everywhere", "--no-connect"], m.env)).code, 0);
  }
  const r = await run(["uninstall", m.other, "--confirm"], m.env);
  assert.equal(r.code, 0, r.out);
  const scope = await readHookScope(m.omnodexHome);
  assert.deepEqual(Object.values(scope.excluded), [["claude-code", "codex"]]);
  assert.ok(exclusionFor(scope, "claude-code", m.other) && exclusionFor(scope, "codex", m.other));
});

// ---------------------------------------------------------------------------
// The launcher decides what is recorded
// ---------------------------------------------------------------------------

/**
 * A launcher for `platform` in a scratch home, with a fake shim that writes
 * the arguments and stdin it received to a file, so each run shows whether
 * the event would have been recorded and what the shim was given.
 */
async function launcherRig(t, platform) {
  const m = await machine(t);
  const launcher = path.join(m.root, "launcher.cjs");
  await fs.writeFile(launcher, generateLauncherSource(platform));
  const shim = path.join(m.root, "fake-shim.cjs");
  const record = path.join(m.root, "recorded.json");
  await fs.writeFile(shim, `
const fs = require("node:fs");
const stdin = fs.readFileSync(0, "utf8");
fs.writeFileSync(${JSON.stringify(record)}, JSON.stringify({ argv: process.argv.slice(2), stdin }));
`);
  const env = { ...m.env, OMNODEX_SHIM_PATH: shim };
  const fire = async (args, payload, { cwd = m.other } = {}) => {
    await fs.rm(record, { force: true });
    const r = spawnSync(process.execPath, [launcher, ...args], {
      env,
      cwd,
      input: JSON.stringify(payload),
      encoding: "utf8",
    });
    assert.equal(r.status, 0, r.stderr);
    return existsSync(record) ? readJson(record) : null;
  };
  return { ...m, fire };
}

test("launcher: with no scope file every hook records, as before", async (t) => {
  const r = await launcherRig(t, "codex");
  const got = await r.fire([], { cwd: r.project });
  assert.deepEqual(got.argv, []);
  assert.deepEqual(JSON.parse(got.stdin), { cwd: r.project });
});

test("launcher: project hooks step aside when the platform records every project; user-level hooks record once", async (t) => {
  const r = await launcherRig(t, "claude-code");
  await setEverywhere(r.omnodexHome, "claude-code", true);
  assert.equal(await r.fire([], { cwd: r.project }), null, "project hook steps aside");
  const got = await r.fire(["--user-scope"], { cwd: r.project });
  assert.deepEqual(got.argv, [], "the marker is not passed to the shim");

  // Another platform's every-project recording does not affect this one.
  const codex = await launcherRig(t, "codex");
  await setEverywhere(codex.omnodexHome, "claude-code", true);
  assert.notEqual(await codex.fire([], { cwd: codex.project }), null);
});

test("launcher: a left-out project is not recorded; others are, with stdin passed through intact", async (t) => {
  const r = await launcherRig(t, "codex");
  await setEverywhere(r.omnodexHome, "codex", true);
  await addExclusion(r.omnodexHome, "codex", r.project);

  assert.equal(await r.fire(["--user-scope"], { cwd: path.join(r.project, "sub") }), null);
  const payload = { cwd: r.other, session_id: "s1", note: "ünïcode" };
  const got = await r.fire(["--user-scope"], payload);
  assert.deepEqual(JSON.parse(got.stdin), payload);
});

test("launcher: Antigravity's project comes from workspacePaths, and the event name still reaches the shim", async (t) => {
  const r = await launcherRig(t, "antigravity");
  await setEverywhere(r.omnodexHome, "antigravity", true);
  await addExclusion(r.omnodexHome, "antigravity", r.project);
  assert.equal(await r.fire(["--user-scope", "Stop"], { workspacePaths: [r.project] }), null);
  const got = await r.fire(["--user-scope", "Stop"], { workspacePaths: [r.other] });
  assert.deepEqual(got.argv, ["Stop"]);
});

test("launcher: without a payload project the working directory decides", async (t) => {
  const r = await launcherRig(t, "claude-code");
  await setEverywhere(r.omnodexHome, "claude-code", true);
  await addExclusion(r.omnodexHome, "claude-code", r.project);
  assert.equal(await r.fire(["--user-scope"], {}, { cwd: r.project }), null);
  assert.notEqual(await r.fire(["--user-scope"], {}, { cwd: r.other }), null);
});

test("in the home folder, the user-level files are not mistaken for project hooks", async (t) => {
  const m = await machine(t);
  for (const target of ["claude-code", "codex"]) {
    assert.equal((await run(["install", "--hooks", target, m.project, "--everywhere", "--no-connect"], m.env)).code, 0);
  }
  const status = await run(["status", m.home], m.env);
  assert.doesNotMatch(status.out, /installed\n/);
  const r = await run(["uninstall", m.home, "--confirm"], m.env);
  assert.equal(r.code, 0, r.out);
  assert.doesNotMatch(r.out, /remove this project's hooks/);
  assert.ok((await fs.readFile(path.join(m.home, ".claude", "settings.json"), "utf8")).includes("--user-scope"));
  assert.ok((await fs.readFile(path.join(m.home, ".codex", "hooks.json"), "utf8")).includes("--user-scope"));
});
