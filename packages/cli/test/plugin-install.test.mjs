/**
 * Agent plugins installed by the CLI: choose and verify the bundle, unpack
 * it where the agent looks, register it with the agent's CLI, and remove it.
 *
 * A local HTTP server stands in for downloads.omnodex.com, and small
 * scripts named codex and claude stand in for the agents' CLIs, recording
 * how they were called. Nothing here touches the network or real agents.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { promises as fs, existsSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { extractZip, readZip, resolveBundle } from "../dist/plugins.js";
import { bundle, downloadsServer, makeZip, sha } from "./plugin-fixtures.mjs";

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

/** Stand-ins for the agents' CLIs that log their arguments. */
async function fakeHosts(dir, log) {
  await fs.mkdir(dir, { recursive: true });
  const script = path.join(dir, "fake-host.cjs");
  await fs.writeFile(script, `
const fs = require("node:fs");
const name = process.env.FAKE_HOST_NAME || require("node:path").basename(process.argv[1]).replace(/\\.cjs$/, "");
fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify([name, ...process.argv.slice(2)]) + "\\n");
process.exit(Number(process.env["FAKE_" + name.toUpperCase() + "_EXIT"] || 0));
`);
  for (const name of ["codex", "claude"]) {
    if (process.platform === "win32") {
      await fs.writeFile(path.join(dir, `${name}.cmd`), `@set FAKE_HOST_NAME=${name}\r\n@node "${script}" %*\r\n`);
    } else {
      const file = path.join(dir, name);
      await fs.writeFile(file, `#!/bin/sh\nFAKE_HOST_NAME=${name} exec node "${script}" "$@"\n`);
      await fs.chmod(file, 0o755);
    }
  }
}

async function machine(t, published) {
  const root = realpathSync(await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-plugin-")));
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const home = path.join(root, "home");
  const project = path.join(root, "project");
  const bin = path.join(root, "bin");
  const log = path.join(root, "hosts.log");
  await fs.mkdir(project, { recursive: true });
  await fakeHosts(bin, log);
  const site = await downloadsServer(t, published);
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    OMNODEX_HOME: path.join(home, ".omnodex"),
    CLAUDE_CONFIG_DIR: path.join(home, ".claude"),
    CODEX_HOME: path.join(home, ".codex"),
    OMNODEX_DOWNLOADS_URL: site.url,
    OMNODEX_NO_UPDATE_CHECK: "1",
    PATH: [bin, path.dirname(process.execPath)].join(path.delimiter),
    WSL_DISTRO_NAME: "",
    // /proc/version still says WSL on a WSL machine; point the Windows scan at nothing.
    OMNODEX_WSL_MOUNT_ROOT: path.join(root, "no-windows-mount"),
  };
  const hostCalls = async () => (existsSync(log) ? (await fs.readFile(log, "utf8")).trim().split("\n").map((l) => JSON.parse(l)) : []);
  return { root, home, project, env, site, hostCalls, omnodexHome: env.OMNODEX_HOME };
}

function run(args, env) {
  const child = spawn(process.execPath, [CLI, ...args], { env, cwd: os.tmpdir(), stdio: ["pipe", "pipe", "pipe"] });
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
// Bundles
// ---------------------------------------------------------------------------

test("readZip reads stored archives and extractZip refuses entries outside the folder", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-zip-"));
  t.after(() => fs.rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const ok = makeZip({ "a/b.txt": "hi", "c.json": "{}" });
  assert.deepEqual(readZip(ok).map((e) => [e.name, e.data.toString()]), [["a/b.txt", "hi"], ["c.json", "{}"]]);
  await extractZip(ok, path.join(root, "out"));
  assert.equal(await fs.readFile(path.join(root, "out", "a", "b.txt"), "utf8"), "hi");

  await assert.rejects(extractZip(makeZip({ "../evil.txt": "x" }), path.join(root, "bad")), /outside/);
  assert.ok(!existsSync(path.join(root, "evil.txt")));
});

test("resolveBundle downloads the pin, checks it, caches it, and refuses a mismatch", async (t) => {
  const good = bundle("codex", "1.0.0");
  const m = await machine(t, { codex: { "1.0.0": good } });
  const cacheDir = path.join(m.root, "cache");
  const pins = { cowork: { version: "1.0.0", sha256: "0".repeat(64), size: 0 }, codex: { version: "1.0.0", sha256: sha(good), size: good.length }, antigravity: { version: "1.0.0", sha256: "0".repeat(64), size: 0 } };

  const first = await resolveBundle({ target: "codex", baseUrl: m.site.url, cacheDir, pins });
  assert.equal(first.version, "1.0.0");
  assert.equal(first.override, false);
  const downloads = m.site.requests.length;
  const again = await resolveBundle({ target: "codex", baseUrl: m.site.url, cacheDir, pins });
  assert.equal(m.site.requests.length, downloads, "the cached copy is used");
  assert.ok(again.source.startsWith(cacheDir));

  m.site.files.set("/plugins/codex/1.0.0/omnodex-codex.plugin", Buffer.from("tampered"));
  await fs.rm(cacheDir, { recursive: true });
  await assert.rejects(resolveBundle({ target: "codex", baseUrl: m.site.url, cacheDir, pins }), /checksum mismatch/);
  assert.ok(!existsSync(path.join(cacheDir, "codex-1.0.0.plugin")), "a bad download is not cached");
});

test("resolveBundle: --plugin-version uses that version's published checksum; latest follows latest.json", async (t) => {
  const v1 = bundle("codex", "1.0.0");
  const v2 = bundle("codex", "2.0.0");
  const m = await machine(t, { codex: { "1.0.0": v1, "2.0.0": v2 } });
  const pins = { codex: { version: "1.0.0", sha256: sha(v1), size: 0 } };
  const cacheDir = path.join(m.root, "cache");
  const chosen = await resolveBundle({ target: "codex", version: "2.0.0", baseUrl: m.site.url, cacheDir, pins });
  assert.equal(chosen.sha256, sha(v2));
  assert.equal(chosen.override, true);
  const latest = await resolveBundle({ target: "codex", version: "latest", baseUrl: m.site.url, cacheDir, pins });
  assert.equal(latest.version, "2.0.0");
  await assert.rejects(resolveBundle({ target: "codex", version: "9.9.9", baseUrl: m.site.url, cacheDir, pins }), /no published checksum for codex 9\.9\.9/);
});

test("resolveBundle --from accepts the pin, a published checksum or --sha256, and refuses anything else", async (t) => {
  const v1 = bundle("codex", "1.0.0");
  const v2 = bundle("codex", "2.0.0");
  const mine = bundle("codex", "3.0.0-local");
  const m = await machine(t, { codex: { "1.0.0": v1, "2.0.0": v2 } });
  const pins = { codex: { version: "1.0.0", sha256: sha(v1), size: 0 } };
  const req = { target: "codex", baseUrl: m.site.url, cacheDir: path.join(m.root, "cache"), pins };
  const file = async (name, bytes) => {
    const p = path.join(m.root, name);
    await fs.writeFile(p, bytes);
    return p;
  };

  assert.equal((await resolveBundle({ ...req, from: await file("v1.plugin", v1) })).override, false);
  const published = await resolveBundle({ ...req, from: await file("v2.plugin", v2) });
  assert.deepEqual([published.version, published.override], ["2.0.0", true]);

  const local = await file("mine.plugin", mine);
  await assert.rejects(resolveBundle({ ...req, from: local }), new RegExp(`matches neither .* pass --sha256 ${sha(mine)}`));
  const trusted = await resolveBundle({ ...req, from: local, sha256: sha(mine) });
  assert.deepEqual([trusted.version, trusted.override], ["3.0.0-local", true]);
  await assert.rejects(resolveBundle({ ...req, from: local, sha256: "a".repeat(64) }), /not the a+ given with --sha256/);

  // Offline: only the pin or --sha256 can vouch for a file.
  const offline = { ...req, baseUrl: "http://127.0.0.1:9" };
  assert.equal((await resolveBundle({ ...offline, from: await file("v1b.plugin", v1) })).version, "1.0.0");
  await assert.rejects(resolveBundle({ ...offline, from: await file("v2b.plugin", v2) }), /matches neither/);
});

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

test("install codex --plugin unpacks the plugin, keeps the personal marketplace, and runs codex plugin add once per install", async (t) => {
  const m = await machine(t, { codex: { "9.9.9": bundle("codex", "9.9.9") } });
  // An existing personal marketplace with its own name and another plugin.
  await fs.mkdir(path.join(m.home, ".agents", "plugins"), { recursive: true });
  await fs.writeFile(path.join(m.home, ".agents", "plugins", "marketplace.json"), JSON.stringify({
    name: "local-testing",
    plugins: [{ name: "other", source: { source: "local", path: "./other" } }],
  }));

  for (let i = 0; i < 2; i++) {
    const r = await run(["install", "codex", m.project, "--plugin", "--plugin-version", "9.9.9", "--no-connect"], m.env);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /Codex plugin omnodex-codex 9\.9\.9 \(this CLI pins /);
  }
  const dir = path.join(m.home, ".codex", "plugins", "omnodex-codex");
  assert.ok(existsSync(path.join(dir, ".codex-plugin", "plugin.json")));
  const market = await readJson(path.join(m.home, ".agents", "plugins", "marketplace.json"));
  assert.equal(market.name, "local-testing");
  assert.deepEqual(market.plugins.map((p) => p.name), ["other", "omnodex-codex"], "no duplicate entry");
  assert.equal(market.plugins[1].source.path, "./.codex/plugins/omnodex-codex");
  assert.deepEqual(await m.hostCalls(), [
    ["codex", "plugin", "add", "omnodex-codex@local-testing"],
    ["codex", "plugin", "add", "omnodex-codex@local-testing"],
  ]);
  // --plugin alone writes no hooks.
  assert.ok(!existsSync(path.join(m.project, ".codex")));
  assert.ok(!existsSync(path.join(m.home, ".codex", "hooks.json")));

  const registry = await readJson(path.join(m.omnodexHome, "installations.json"));
  const entry = registry.installations.find((i) => i.component === "plugin");
  assert.deepEqual([entry.target, entry.scope, entry.pluginVersion, entry.pluginOverride], ["codex", "user", "9.9.9", true]);

  const status = await run(["status", m.project], m.env);
  assert.match(status.out, /Codex plugin: omnodex-codex 9\.9\.9 \(chosen version, not this CLI's pin\), for every project/);
});

test("a failed download leaves the hooks installed, exits non-zero, and says how to retry", async (t) => {
  const m = await machine(t, { codex: {} });
  const r = await run(["install", "codex", m.project, "--this-project", "--plugin-version", "1.2.3", "--no-connect"], m.env);
  assert.equal(r.code, 1, r.out);
  assert.ok(existsSync(path.join(m.project, ".codex", "hooks.json")), "hooks installed");
  assert.match(r.out, /Codex plugin not installed: no published checksum for codex 1\.2\.3/);
  assert.match(r.out, /the hooks above are installed and record without it/);
  assert.match(r.out, /retry with `omnodex install codex --plugin`/);
  assert.deepEqual(await m.hostCalls(), []);
});

test("install claude-code --plugin builds a local marketplace and installs it for the user; a manual MCP entry is flagged", async (t) => {
  const m = await machine(t, { cowork: { "4.0.0": bundle("cowork", "4.0.0") } });
  await fs.mkdir(m.home, { recursive: true });
  await fs.writeFile(path.join(m.home, ".claude.json"), JSON.stringify({ mcpServers: { omnodex: { command: "node" } } }));
  const r = await run(["install", "claude-code", m.project, "--plugin", "--plugin-version", "4.0.0", "--no-connect"], m.env);
  assert.equal(r.code, 0, r.out);
  const marketplace = path.join(m.omnodexHome, "plugins", "claude-marketplace");
  assert.ok(existsSync(path.join(marketplace, "omnodex-cowork", ".claude-plugin", "plugin.json")));
  const manifest = await readJson(path.join(marketplace, ".claude-plugin", "marketplace.json"));
  assert.deepEqual(manifest.plugins.map((p) => [p.name, p.source, p.version]), [["omnodex-cowork", "./omnodex-cowork", "4.0.0"]]);
  assert.deepEqual(await m.hostCalls(), [
    ["claude", "plugin", "marketplace", "add", marketplace],
    ["claude", "plugin", "install", "omnodex-cowork@omnodex-local", "--scope", "user"],
  ]);
  assert.match(r.out, /WARNING: Claude Code also has a manual `omnodex` MCP server/);
});

test("install antigravity --plugin unpacks into ~/.gemini/config/plugins and runs the bundle's configure step", async (t) => {
  const configure = `require("node:fs").writeFileSync(require("node:path").join(__dirname, "..", "configured"), "yes");\n`;
  const m = await machine(t, { antigravity: { "5.0.0": bundle("antigravity", "5.0.0", { "bin/configure.js": configure }) } });
  const r = await run(["install", "antigravity", m.project, "--plugin", "--plugin-version", "5.0.0", "--no-connect"], m.env);
  assert.equal(r.code, 0, r.out);
  const dir = path.join(m.home, ".gemini", "config", "plugins", "omnodex-antigravity");
  assert.equal(await fs.readFile(path.join(dir, "configured"), "utf8"), "yes");
  assert.match(r.out, /configured the plugin's paths for this host/);
});

test("uninstall leaves the plugin unless --plugin is given, which removes only Omnodex's marketplace entry", async (t) => {
  const m = await machine(t, { codex: { "9.9.9": bundle("codex", "9.9.9") } });
  await fs.mkdir(path.join(m.home, ".agents", "plugins"), { recursive: true });
  await fs.writeFile(path.join(m.home, ".agents", "plugins", "marketplace.json"), JSON.stringify({
    name: "local-testing",
    plugins: [{ name: "other" }],
  }));
  const install = await run(["install", "codex", m.project, "--this-project", "--plugin-version", "9.9.9", "--no-connect"], m.env);
  assert.equal(install.code, 0, install.out);

  const hooksOnly = await run(["uninstall", "codex", m.project, "--confirm", "--unattended"], m.env);
  assert.equal(hooksOnly.code, 0, hooksOnly.out);
  assert.match(hooksOnly.out, /the Codex plugin stays installed for every project; `omnodex uninstall codex --plugin` removes it/);
  const dir = path.join(m.home, ".codex", "plugins", "omnodex-codex");
  assert.ok(existsSync(dir));

  const r = await run(["uninstall", "codex", "--plugin", "--confirm", "--unattended"], m.env);
  assert.equal(r.code, 0, r.out);
  assert.ok(!existsSync(dir));
  const market = await readJson(path.join(m.home, ".agents", "plugins", "marketplace.json"));
  assert.deepEqual(market.plugins, [{ name: "other" }]);
  assert.deepEqual((await m.hostCalls()).at(-1), ["codex", "plugin", "remove", "omnodex-codex@local-testing"]);
  const registry = await readJson(path.join(m.omnodexHome, "installations.json"));
  assert.equal(registry.installations.filter((i) => i.component === "plugin").length, 0);

  const nothing = await run(["uninstall", "codex", "--plugin", "--confirm", "--unattended"], m.env);
  assert.match(nothing.out, /no Omnodex plugin installed for Codex/);
});

test("install with no target refuses --from, and an explicit plugin version without a target", async (t) => {
  const m = await machine(t, {});
  const from = await run(["install", m.project, "--from", "x.plugin", "--yes"], m.env);
  assert.equal(from.code, 1);
  assert.match(from.out, /--from and --sha256 install one plugin/);
  const version = await run(["install", m.project, "--plugin-version", "1.0.0", "--yes"], m.env);
  assert.equal(version.code, 1);
  assert.match(version.out, /each plugin has its own version numbers/);
});
