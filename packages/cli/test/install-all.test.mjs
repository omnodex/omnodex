/**
 * `omnodex install` with no target: detect every supported agent surface,
 * show the plan, confirm once, install each, and report per surface.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs, existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { detectSurfaces, detectWsl, findOnPath, isWsl, wslNote } from "../dist/surfaces.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

async function tempRoot(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-install-all-"));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

async function fakeCommand(dir, name) {
  await fs.mkdir(dir, { recursive: true });
  const file = path.join(dir, name);
  await fs.writeFile(file, "#!/bin/sh\n");
  await fs.chmod(file, 0o755);
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

test("detectSurfaces finds surfaces by command on PATH, home directory or macOS app", async (t) => {
  const root = await tempRoot(t);
  const home = path.join(root, "home");
  const bin = path.join(root, "bin");
  const apps = path.join(root, "Applications");
  // PATH lookup uses the real platform's separator and extensions.
  await fakeCommand(bin, process.platform === "win32" ? "claude.cmd" : "claude");
  await fs.mkdir(path.join(home, ".codex"), { recursive: true });
  await fs.mkdir(path.join(apps, "Antigravity.app"), { recursive: true });

  const env = { PATH: bin, PATHEXT: ".EXE;.CMD" };
  assert.deepEqual(detectSurfaces({ home, platform: process.platform, env, applicationsDir: apps }).slice(0, 2), [
    { surface: "claude-code", evidence: "claude on PATH" },
    { surface: "codex", evidence: "~/.codex" },
  ]);
  // App bundles count only on macOS.
  assert.deepEqual(detectSurfaces({ home, platform: "darwin", env: { PATH: "" }, applicationsDir: apps }), [
    { surface: "codex", evidence: "~/.codex" },
    { surface: "antigravity", evidence: "Antigravity.app" },
  ]);
  assert.deepEqual(detectSurfaces({ home, platform: "linux", env: { PATH: "" }, applicationsDir: apps }), [
    { surface: "codex", evidence: "~/.codex" },
  ]);
});

test("detectSurfaces ignores a bare ~/.gemini, which Gemini CLI also creates", async (t) => {
  const root = await tempRoot(t);
  const home = path.join(root, "home");
  await fs.mkdir(path.join(home, ".gemini"), { recursive: true });
  assert.deepEqual(detectSurfaces({ home, platform: "linux", env: { PATH: "" } }), []);

  await fs.mkdir(path.join(home, ".gemini", "config"), { recursive: true });
  assert.deepEqual(detectSurfaces({ home, platform: "linux", env: { PATH: "" } }), [
    { surface: "antigravity", evidence: "~/.gemini/config" },
  ]);
});

test("findOnPath honors PATHEXT on Windows", async (t) => {
  const root = await tempRoot(t);
  await fs.writeFile(path.join(root, "codex.CMD"), "");
  assert.equal(findOnPath("codex", { platform: "win32", env: { PATH: root, PATHEXT: ".EXE;.CMD" } }), path.join(root, "codex.CMD"));
  assert.equal(findOnPath("codex", { platform: "linux", env: { PATH: root } }), null);
});

// ---------------------------------------------------------------------------
// WSL
// ---------------------------------------------------------------------------

test("isWsl reads WSL_DISTRO_NAME or /proc/version, and only on Linux", () => {
  assert.equal(isWsl({ platform: "linux", env: { WSL_DISTRO_NAME: "Ubuntu" }, procVersion: null, mountRoot: "/mnt" }), true);
  assert.equal(isWsl({ platform: "linux", env: {}, procVersion: "Linux version 5.15.167.4-microsoft-standard-WSL2", mountRoot: "/mnt" }), true);
  assert.equal(isWsl({ platform: "linux", env: {}, procVersion: "Linux version 6.8.0-generic", mountRoot: "/mnt" }), false);
  assert.equal(isWsl({ platform: "darwin", env: { WSL_DISTRO_NAME: "x" }, procVersion: null, mountRoot: "/mnt" }), false);
});

// WSL detection runs only on Linux and works on POSIX paths, which a Windows
// runner's scratch directory is not.
const posixOnly = { skip: process.platform === "win32" && "WSL paths are POSIX" };

test("under WSL, Windows-side surfaces produce a PowerShell note and a Windows project path", posixOnly, async (t) => {
  const root = await tempRoot(t);
  const mountRoot = path.join(root, "mnt");
  await fs.mkdir(path.join(mountRoot, "c", "Users", "case", ".codex"), { recursive: true });
  await fs.mkdir(path.join(mountRoot, "c", "Users", "case", ".claude"), { recursive: true });
  await fs.mkdir(path.join(mountRoot, "c", "Users", "Public", ".codex"), { recursive: true });
  const probe = { platform: "linux", env: { WSL_DISTRO_NAME: "Ubuntu" }, procVersion: null, mountRoot };

  const onWindowsDrive = detectWsl(probe, path.join(mountRoot, "c", "Users", "case", "repo"));
  assert.deepEqual(onWindowsDrive.windowsSurfaces, ["claude-code", "codex"]);
  assert.equal(onWindowsDrive.windowsProjectPath, "C:\\Users\\case\\repo");
  const note = wslNote(onWindowsDrive).join("\n");
  assert.match(note, /Native Windows also has Claude Code, Codex/);
  assert.match(note, /cd "C:\\Users\\case\\repo"; npm i -g omnodex; omnodex install/);
  assert.match(note, /use each project folder from one host only/);

  const inLinuxHome = detectWsl(probe, "/home/case/repo");
  assert.equal(inLinuxHome.windowsProjectPath, null);
  assert.match(wslNote(inLinuxHome).join("\n"), /from the Windows project folder/);
  assert.doesNotMatch(wslNote(inLinuxHome).join("\n"), /one host only/);
});

test("no WSL note outside WSL or when Windows has no surfaces", posixOnly, async (t) => {
  const root = await tempRoot(t);
  const mountRoot = path.join(root, "mnt");
  await fs.mkdir(path.join(mountRoot, "c", "Users", "case"), { recursive: true });
  assert.equal(detectWsl({ platform: "darwin", env: {}, procVersion: null, mountRoot }, "/x"), null);
  const info = detectWsl({ platform: "linux", env: { WSL_DISTRO_NAME: "Ubuntu" }, procVersion: null, mountRoot }, "/x");
  assert.deepEqual(wslNote(info), []);
});

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

function run(args, env, { stdin = "" } = {}) {
  const child = spawn(process.execPath, [CLI, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.end(stdin);
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

/** A machine with Claude Code and Codex (by home directory) and no agents on PATH. */
async function machine(t) {
  const root = await tempRoot(t);
  const home = path.join(root, "home");
  const project = path.join(root, "project");
  const emptyBin = path.join(root, "empty-bin");
  await fs.mkdir(path.join(home, ".claude"), { recursive: true });
  await fs.mkdir(path.join(home, ".codex"), { recursive: true });
  await fs.mkdir(project, { recursive: true });
  await fs.mkdir(emptyBin, { recursive: true });
  // An isolated home and PATH: never the developer's real ~/.omnodex or agents.
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    OMNODEX_HOME: path.join(home, ".omnodex"),
    CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
    CODEX_HOME: path.join(home, ".codex"),
    PATH: emptyBin,
    OMNODEX_APPLICATIONS_DIR: path.join(root, "Applications"),
    WSL_DISTRO_NAME: "",
  };
  return { root, home, project, env };
}

test("without a terminal and without --yes, it shows the plan and installs nothing", async (t) => {
  const m = await machine(t);
  const result = await run(["install", m.project], m.env);
  assert.equal(result.code, 1, result.out);
  assert.match(result.out, /Claude Code\s+\(found: ~\/\.claude\)/);
  assert.match(result.out, /Codex\s+\(found: ~\/\.codex\)/);
  assert.match(result.out, /Re-run with --yes/);
  assert.doesNotMatch(result.out, /Antigravity/);
  assert.ok(!existsSync(path.join(m.project, ".claude", "settings.local.json")));
  assert.ok(!existsSync(path.join(m.project, ".codex", "hooks.json")));
});

test("with --yes it records every project on every detected surface, and a rerun changes nothing", async (t) => {
  const m = await machine(t);
  const first = await run(["install", m.project, "--yes"], m.env);
  assert.equal(first.code, 0, first.out);
  assert.match(first.out, /to record every project:/);
  assert.match(first.out, /Claude Code\s+installed/);
  assert.match(first.out, /Codex\s+installed/);
  assert.ok(existsSync(path.join(m.home, ".claude", "settings.json")));
  assert.ok(existsSync(path.join(m.home, ".codex", "hooks.json")));
  assert.ok(!existsSync(path.join(m.project, ".claude", "settings.local.json")));
  assert.ok(!existsSync(path.join(m.project, ".codex", "hooks.json")));
  // One sign-in notice for the whole install, not one per surface.
  assert.equal(first.out.match(/skipped the dashboard sign-in/g)?.length ?? 0, 1, first.out);

  const registry = JSON.parse(await fs.readFile(path.join(m.home, ".omnodex", "installations.json"), "utf8"));
  assert.deepEqual(registry.installations.map((i) => i.target).sort(), ["claude-code", "codex"]);

  const again = await run(["install", m.project, "--yes"], m.env);
  assert.equal(again.code, 0, again.out);
  assert.match(again.out, /Claude Code\s+already set up, nothing changed/);
  assert.match(again.out, /nothing to change; Omnodex is already set up here/);
});

test("--this-project writes project hooks, in the current directory when no project is given", async (t) => {
  const m = await machine(t);
  const child = spawn(process.execPath, [CLI, "install", "-y", "--this-project"], { env: m.env, cwd: m.project, stdio: ["pipe", "pipe", "pipe"] });
  child.stdin.end();
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const code = await new Promise((resolve) => child.on("exit", resolve));
  assert.equal(code, 0, out);
  assert.ok(existsSync(path.join(m.project, ".codex", "hooks.json")));
});

test("one surface failing does not stop the others", async (t) => {
  const m = await machine(t);
  // A directory where Claude Code's settings file should be makes its install fail.
  await fs.mkdir(path.join(m.home, ".claude", "settings.json"), { recursive: true });
  const result = await run(["install", m.project, "--yes"], m.env);
  assert.equal(result.code, 1, result.out);
  assert.match(result.out, /Claude Code\s+failed:/);
  assert.match(result.out, /Codex\s+installed/);
  assert.ok(existsSync(path.join(m.home, ".codex", "hooks.json")));
});

test("with no supported surface on the host it says so and exits non-zero", async (t) => {
  const m = await machine(t);
  await fs.rm(path.join(m.home, ".claude"), { recursive: true });
  await fs.rm(path.join(m.home, ".codex"), { recursive: true });
  const result = await run(["install", m.project, "--yes"], m.env);
  assert.equal(result.code, 1, result.out);
  assert.match(result.out, /no supported agent surfaces found/);
});

test("an unknown name that is not a folder is still an unknown target", async (t) => {
  const m = await machine(t);
  const result = await run(["install", "codx"], m.env);
  assert.equal(result.code, 1, result.out);
  assert.match(result.out, /unknown target 'codx'/);
});
