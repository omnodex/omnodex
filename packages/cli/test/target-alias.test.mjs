/**
 * `agy` is Antigravity's CLI launcher name. The CLI accepts it wherever it
 * takes a target and stores only the canonical `antigravity`.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalTarget, platformFromTarget } from "../dist/connect.js";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

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
    }, 30000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, out });
    });
  });
}

test("canonicalTarget resolves agy and leaves other names alone", () => {
  assert.equal(canonicalTarget("agy"), "antigravity");
  assert.equal(canonicalTarget("antigravity"), "antigravity");
  assert.equal(canonicalTarget("codex"), "codex");
  assert.equal(canonicalTarget("something-else"), "something-else");
  assert.equal(platformFromTarget("agy"), platformFromTarget("antigravity"));
});

async function installWith(target) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-alias-"));
  const home = path.join(root, "home");
  const project = path.join(root, "project");
  await fs.mkdir(project, { recursive: true });
  // An isolated home: never the developer's real ~/.omnodex.
  const env = { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: path.join(home, ".omnodex") };
  const result = await run(["install", target, project, "--no-connect"], env);
  const hooks = await fs.readFile(path.join(project, ".agents", "hooks.json"), "utf8");
  const registry = JSON.parse(await fs.readFile(path.join(home, ".omnodex", "installations.json"), "utf8"));
  return { root, home, project, env, result, hooks, registry };
}

test("install agy and install antigravity write the same hooks and registry entry", async (t) => {
  const viaAlias = await installWith("agy");
  const viaName = await installWith("antigravity");
  t.after(() => Promise.all([viaAlias, viaName].map((r) => fs.rm(r.root, { recursive: true, force: true }))));

  assert.equal(viaAlias.result.code, 0, viaAlias.result.out);
  assert.equal(viaName.result.code, 0, viaName.result.out);

  // Same hook file once each run's own scratch root is factored out. The
  // hooks file is JSON, so on Windows the root appears with escaped backslashes.
  const strip = (r) => [JSON.stringify(r.root).slice(1, -1), r.root].reduce((s, p) => s.split(p).join("<root>"), r.hooks);
  assert.equal(strip(viaAlias), strip(viaName));

  const [aliasEntry] = viaAlias.registry.installations;
  const [nameEntry] = viaName.registry.installations;
  assert.equal(aliasEntry.target, "antigravity");
  for (const key of ["target", "component", "scope", "settingsFile", "usesLauncher"]) {
    assert.equal(aliasEntry[key], nameEntry[key], key);
  }
});

test("uninstall agy removes Antigravity hooks", async (t) => {
  const installed = await installWith("agy");
  t.after(() => fs.rm(installed.root, { recursive: true, force: true }));

  const result = await run(["uninstall", "agy", installed.project, "--confirm"], installed.env);
  assert.equal(result.code, 0, result.out);
  assert.match(result.out, /removed Antigravity hooks/);
  const registry = JSON.parse(await fs.readFile(path.join(installed.home, ".omnodex", "installations.json"), "utf8"));
  assert.deepEqual(registry.installations, []);
});
