// Hook commands that name paths this machine does not have, as when a
// project hooks file written on another machine arrives through a shared
// repo or a synced folder.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { findMissingHookPaths, hookCommandPaths } from "../dist/hook-paths.js";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const HOME = "/home/case";

/** An Antigravity hooks file whose commands are the given strings. */
function antigravityFile(command) {
  return JSON.stringify({
    omnodex: {
      PostToolUse: [{ matcher: "*", hooks: [{ type: "command", command: `${command} PostToolUse`, timeout: 30 }] }],
      Stop: [{ type: "command", command: `${command} Stop`, timeout: 30 }],
    },
  });
}

const existsOnly = (paths) => async (p) => paths.includes(p);

test("hookCommandPaths reads the env prefix, launcher and node binary", () => {
  assert.deepEqual(
    hookCommandPaths("OMNODEX_HOME=/Users/case/.omnodex /usr/local/bin/node /Users/case/.omnodex/bin/antigravity-hook-launcher.js Stop", HOME),
    [
      { kind: "omnodex-home", path: "/Users/case/.omnodex" },
      { kind: "node", path: "/usr/local/bin/node" },
      { kind: "launcher", path: "/Users/case/.omnodex/bin/antigravity-hook-launcher.js" },
    ],
  );
});

test("hookCommandPaths expands $HOME and keeps quoted paths with spaces whole", () => {
  assert.deepEqual(hookCommandPaths('node "$HOME/.omnodex/bin/codex-hook-launcher.js"', HOME), [
    { kind: "launcher", path: "/home/case/.omnodex/bin/codex-hook-launcher.js" },
  ]);
  assert.deepEqual(
    hookCommandPaths("OMNODEX_HOME='/home/case/my home/.omnodex' node '/home/case/my home/shim.js' Stop", HOME),
    [
      { kind: "omnodex-home", path: "/home/case/my home/.omnodex" },
      { kind: "launcher", path: "/home/case/my home/shim.js" },
    ],
  );
});

test("hookCommandPaths reads cmd.exe syntax", () => {
  assert.deepEqual(
    hookCommandPaths('set "OMNODEX_HOME=C:\\Users\\case\\.omnodex" && node "C:\\Users\\case\\.omnodex\\bin\\antigravity-hook-launcher.js" Stop', HOME),
    [
      { kind: "omnodex-home", path: "C:\\Users\\case\\.omnodex" },
      { kind: "launcher", path: "C:\\Users\\case\\.omnodex\\bin\\antigravity-hook-launcher.js" },
    ],
  );
});

test("hookCommandPaths leaves out bare node and relative paths", () => {
  assert.deepEqual(hookCommandPaths("node ./bin/launch-proxy.js --platform antigravity", HOME), []);
});

test("findMissingHookPaths reports another machine's paths, once each", async () => {
  const content = antigravityFile(
    "OMNODEX_HOME=/Users/case/.omnodex node /Users/case/.omnodex/bin/antigravity-hook-launcher.js",
  );
  const missing = await findMissingHookPaths(content, { home: HOME, exists: existsOnly([]) });
  assert.deepEqual(missing, [
    { kind: "omnodex-home", path: "/Users/case/.omnodex" },
    { kind: "launcher", path: "/Users/case/.omnodex/bin/antigravity-hook-launcher.js" },
  ]);
});

test("findMissingHookPaths is empty when every path resolves", async () => {
  const content = antigravityFile('node "$HOME/.omnodex/bin/antigravity-hook-launcher.js"');
  const missing = await findMissingHookPaths(content, {
    home: HOME,
    exists: existsOnly(["/home/case/.omnodex/bin/antigravity-hook-launcher.js"]),
  });
  assert.deepEqual(missing, []);
});

test("findMissingHookPaths ignores other tools' hooks and files that are not JSON", async () => {
  const content = JSON.stringify({
    hooks: { PostToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "node /opt/other/audit.js" }] }] },
  });
  assert.deepEqual(await findMissingHookPaths(content, { home: HOME, exists: existsOnly([]) }), []);
  assert.deepEqual(await findMissingHookPaths("not json", { home: HOME, exists: existsOnly([]) }), []);
});

test("status warns about an Antigravity hooks file written on another machine", async (t) => {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-hook-paths-"));
  t.after(() => fs.rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const projectPath = path.join(home, "repo");
  await fs.mkdir(path.join(projectPath, ".agents"), { recursive: true });
  const elsewhere = "/nonexistent-omnodex-test/case/.omnodex";
  await fs.writeFile(
    path.join(projectPath, ".agents", "hooks.json"),
    antigravityFile(`OMNODEX_HOME=${elsewhere} node ${elsewhere}/bin/antigravity-hook-launcher.js`),
  );
  const result = spawnSync(process.execPath, [CLI, "status", projectPath], {
    cwd: projectPath,
    env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: path.join(home, ".omnodex") },
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Antigravity: installed/);
  assert.match(result.stdout, /names paths this machine does not have/);
  assert.ok(result.stdout.includes(`${elsewhere}/bin/antigravity-hook-launcher.js`), result.stdout);
  assert.match(result.stdout, /omnodex install antigravity --this-project/);
});
