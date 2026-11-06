/**
 * The platform registry: Copilot, Cursor and OpenCode are recognized in the
 * shared plumbing (targets, hook scope, launcher, labels, detection) while
 * their providers are still to come, and an install for one reports that
 * clearly instead of half-working.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { promises as fs, existsSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { addExclusion, readHookScope, setEverywhere, userHooksFile, writeHookScope } from "../dist/hook-scope.js";
import { LAUNCHER_PLATFORMS, generateLauncherSource, launcherHomeRelativePath } from "../dist/launcher-template.js";
import {
  PLATFORMS,
  PLATFORM_AVAILABLE,
  PLATFORM_LABELS,
  availablePlatforms,
  isPlatform,
  notYetSupported,
} from "../dist/platforms.js";
import { SURFACES, SURFACE_LABELS, detectSurfaces } from "../dist/surfaces.js";
import { interceptorLabel, interceptorTone, runtimeLabel } from "../dist/dashboard-model/labels.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");
const NEW_PLATFORMS = ["copilot", "cursor", "opencode"];

async function machine(t) {
  const root = realpathSync(await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-platforms-")));
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
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
    OMNODEX_NO_UPDATE_CHECK: "1",
    CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
    CODEX_HOME: path.join(home, ".codex"),
    WSL_DISTRO_NAME: "",
    OMNODEX_WSL_MOUNT_ROOT: path.join(root, "no-windows-mount"),
  };
  return { root, home, omnodexHome, project, other, env };
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

test("the registry lists all six platforms; only the shipped three are available", () => {
  assert.deepEqual([...PLATFORMS], ["claude-code", "codex", "antigravity", "copilot", "cursor", "opencode"]);
  assert.deepEqual(availablePlatforms(), ["claude-code", "codex", "antigravity"]);
  for (const p of NEW_PLATFORMS) {
    assert.equal(isPlatform(p), true);
    assert.equal(PLATFORM_AVAILABLE[p], false);
    assert.ok(PLATFORM_LABELS[p]);
    assert.equal(SURFACE_LABELS[p], PLATFORM_LABELS[p]);
  }
  assert.equal(isPlatform("agy"), false);
  assert.match(notYetSupported("cursor"), /Cursor support is not available yet/);
});

test("loops over every platform skip the ones whose provider has not shipped", () => {
  assert.deepEqual(LAUNCHER_PLATFORMS, availablePlatforms());
  assert.deepEqual(SURFACES, availablePlatforms());
});

test("detection ignores the new agents until their providers ship", async (t) => {
  const m = await machine(t);
  const bin = path.join(m.root, "bin");
  await fs.mkdir(bin);
  for (const cmd of ["copilot", "cursor-agent", "opencode"]) await fs.writeFile(path.join(bin, cmd), "#!/bin/sh\n", { mode: 0o755 });
  await fs.mkdir(path.join(m.home, ".cursor"), { recursive: true });
  const found = detectSurfaces({ home: m.home, platform: "linux", env: { PATH: bin } });
  assert.deepEqual(found, []);
});

test("each new platform has a user-level hooks file, and the agent's own folder variable moves it", () => {
  const home = path.join(os.tmpdir(), "case-home");
  assert.equal(userHooksFile("copilot", home, {}), path.join(home, ".copilot", "hooks", "omnodex.json"));
  assert.equal(userHooksFile("copilot", home, { COPILOT_HOME: path.join(home, "cp") }), path.join(home, "cp", "hooks", "omnodex.json"));
  assert.equal(userHooksFile("cursor", home, {}), path.join(home, ".cursor", "hooks.json"));
  assert.equal(userHooksFile("opencode", home, {}), path.join(home, ".config", "opencode", "plugins", "omnodex.js"));
  assert.equal(
    userHooksFile("opencode", home, { XDG_CONFIG_HOME: path.join(home, "xdg") }),
    path.join(home, "xdg", "opencode", "plugins", "omnodex.js"),
  );
});

test("hook scope stores and exclusions apply to the new platforms", async (t) => {
  const m = await machine(t);
  for (const p of NEW_PLATFORMS) await setEverywhere(m.omnodexHome, p, true);
  await addExclusion(m.omnodexHome, "cursor", m.project);
  const scope = await readHookScope(m.omnodexHome);
  assert.deepEqual(scope.everywhere, ["copilot", "cursor", "opencode"]);
  assert.deepEqual(Object.values(scope.excluded), [["cursor"]]);

  // A name that is not a platform is still dropped when the file is read.
  await writeHookScope(m.omnodexHome, { version: 1, everywhere: ["cursor", "vim"], excluded: {} });
  assert.deepEqual((await readHookScope(m.omnodexHome)).everywhere, ["cursor"]);
});

test("each new platform gets its own launcher naming its provider package", () => {
  for (const [platform, pkg, file] of [
    ["copilot", "copilot-provider", "copilot-hook-launcher.js"],
    ["cursor", "cursor-provider", "cursor-hook-launcher.js"],
    ["opencode", "opencode-provider", "opencode-plugin-launcher.js"],
  ]) {
    const source = generateLauncherSource(platform);
    assert.match(source, new RegExp(`PLATFORM = "${platform}"`));
    assert.match(source, new RegExp(`PACKAGE_NAME = "${pkg}"`));
    assert.equal(launcherHomeRelativePath(platform), `.omnodex/bin/${file}`);
  }
});

/** A launcher in a scratch home with a fake shim that records whether it ran. */
async function launcherRig(t, platform) {
  const m = await machine(t);
  const launcher = path.join(m.root, "launcher.cjs");
  await fs.writeFile(launcher, generateLauncherSource(platform));
  const shim = path.join(m.root, "fake-shim.cjs");
  const record = path.join(m.root, "recorded.json");
  await fs.writeFile(shim, `require("node:fs").writeFileSync(${JSON.stringify(record)}, "ran");`);
  const env = { ...m.env, OMNODEX_SHIM_PATH: shim };
  const fire = (payload) => {
    if (existsSync(record)) spawnSync(process.execPath, ["-e", `require("node:fs").rmSync(${JSON.stringify(record)})`]);
    const r = spawnSync(process.execPath, [launcher, "--user-scope"], { env, cwd: m.other, input: JSON.stringify(payload), encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return existsSync(record);
  };
  return { ...m, fire };
}

test("launcher: the project comes from cwd for Copilot and OpenCode, and the first workspace root for Cursor", async (t) => {
  for (const [platform, inside, outside] of [
    ["copilot", (r) => ({ cwd: r.project }), (r) => ({ cwd: r.other })],
    ["opencode", (r) => ({ cwd: r.project }), (r) => ({ cwd: r.other })],
    ["cursor", (r) => ({ workspace_roots: [r.project, r.other] }), (r) => ({ workspace_roots: [r.other, r.project] })],
  ]) {
    const r = await launcherRig(t, platform);
    await setEverywhere(r.omnodexHome, platform, true);
    await addExclusion(r.omnodexHome, platform, r.project);
    assert.equal(r.fire(inside(r)), false, `${platform}: a left-out project is not recorded`);
    assert.equal(r.fire(outside(r)), true, `${platform}: other projects are recorded`);
  }
});

test("the dashboard names the new sources", () => {
  assert.equal(interceptorLabel("copilot-hook"), "Copilot");
  assert.equal(interceptorLabel("cursor-hook"), "Cursor");
  assert.equal(interceptorLabel("opencode-plugin"), "OpenCode");
  for (const kind of ["copilot-hook", "cursor-hook", "opencode-plugin"]) assert.notEqual(interceptorTone(kind), "slate");
  assert.equal(runtimeLabel({ interceptor: "cursor-hook", platform: "cursor", mcp_client_name: null }), "Cursor");
  assert.equal(runtimeLabel({ interceptor: "mcp-proxy", platform: "opencode", mcp_client_name: null }), "OpenCode via MCP Proxy");
});

test("install and uninstall name the new targets but report them as not available yet", async (t) => {
  const m = await machine(t);
  for (const target of NEW_PLATFORMS) {
    const install = await run(["install", target, m.project, "--no-connect", "--yes"], m.env);
    assert.equal(install.code, 1, install.out);
    assert.match(install.out, /not available yet/);
  }
  const uninstall = await run(["uninstall", "opencode", m.project, "--confirm"], m.env);
  assert.equal(uninstall.code, 1, uninstall.out);
  assert.match(uninstall.out, /not available yet/);
  // Nothing was written for any of them.
  assert.equal(existsSync(userHooksFile("cursor", m.home, m.env)), false);
  assert.equal(existsSync(path.join(m.omnodexHome, "bin")), false);
});

test("an unknown target lists every valid one", async (t) => {
  const m = await machine(t);
  const r = await run(["install", "emacs"], m.env);
  assert.equal(r.code, 1);
  for (const p of ["claude-code", "codex", "antigravity", "copilot", "cursor", "opencode"]) assert.match(r.out, new RegExp(p));
});
