/**
 * `omnodex update` brings installed agent plugins to the versions the new
 * release pins. Runs in-process with a scratch home, a local server for
 * downloads.omnodex.com, and a PATH with no agent CLIs on it.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs, existsSync, realpathSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { refreshPlugins } from "../dist/plugin-refresh.js";
import { addInstallation, findInstallations } from "../dist/registry.js";
import { bundle, downloadsServer, sha } from "./plugin-fixtures.mjs";

const pinsFor = (versions) => {
  const pins = {};
  for (const [platform, bytes] of Object.entries(versions)) {
    pins[platform] = { version: JSON.parse(manifestOf(bytes)).version, sha256: sha(bytes), size: bytes.length };
  }
  return pins;
};
// The fixtures are stored zips: the manifest JSON is readable in the bytes.
const manifestOf = (bytes) => /\{"name":"omnodex-[a-z]+","version":"[^"]+"\}/.exec(bytes.toString("latin1"))[0];

/** Scratch home with the process environment pointed at it for the test. */
async function machine(t, published) {
  const root = realpathSync(await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-refresh-")));
  const home = path.join(root, "home");
  const emptyBin = path.join(root, "bin");
  await fs.mkdir(emptyBin, { recursive: true });
  const saved = { ...process.env };
  Object.assign(process.env, {
    HOME: home,
    USERPROFILE: home,
    OMNODEX_HOME: path.join(home, ".omnodex"),
    CODEX_HOME: path.join(home, ".codex"),
    PATH: emptyBin,
  });
  t.after(async () => {
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
    await fs.rm(root, { recursive: true, force: true });
  });
  const site = await downloadsServer(t, published);
  return { root, home, site };
}

/** Records an installed plugin as `omnodex install --plugin` would. */
async function installed(target, version, dir, { override = false } = {}) {
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, "marker"), version);
  await addInstallation({
    target,
    component: "plugin",
    scope: "user",
    settingsFile: `omnodex-${target}`,
    installedAt: "2026-10-01T00:00:00.000Z",
    installedVersion: "0.0.0",
    usesLauncher: false,
    pluginPath: dir,
    pluginVersion: version,
    pluginOverride: override,
  });
}

const quiet = () => {};
const codexDir = (m) => path.join(m.home, ".codex", "plugins", "omnodex-codex");
const agyDir = (m) => path.join(m.home, ".gemini", "config", "plugins", "omnodex-antigravity");
const registryVersion = async (target) => (await findInstallations({ target, component: "plugin" }))[0]?.pluginVersion;

test("refresh replaces an older plugin with the pinned version and records it", async (t) => {
  const v2 = bundle("codex", "2.0.0");
  const m = await machine(t, { codex: { "1.0.0": bundle("codex", "1.0.0"), "2.0.0": v2 } });
  await installed("codex", "1.0.0", codexDir(m));

  const [outcome] = await refreshPlugins({ pins: pinsFor({ codex: v2 }), baseUrl: m.site.url, log: quiet });
  assert.equal(outcome.result, "updated");
  assert.match(outcome.message, /Codex: updated omnodex-codex 1\.0\.0 -> 2\.0\.0/);
  assert.match(outcome.message, /ChatGPT Desktop/, "without the codex CLI, says what to do in the app");
  const manifest = JSON.parse(await fs.readFile(path.join(codexDir(m), ".codex-plugin", "plugin.json"), "utf8"));
  assert.equal(manifest.version, "2.0.0");
  assert.ok(!existsSync(path.join(codexDir(m), "marker")), "the old copy was replaced");
  assert.equal(await registryVersion("codex"), "2.0.0");
});

test("an already current plugin is left alone and nothing is downloaded", async (t) => {
  const v1 = bundle("codex", "1.0.0");
  const m = await machine(t, { codex: { "1.0.0": v1 } });
  await installed("codex", "1.0.0", codexDir(m));
  const [outcome] = await refreshPlugins({ pins: pinsFor({ codex: v1 }), baseUrl: m.site.url, log: quiet });
  assert.equal(outcome.result, "current");
  assert.deepEqual(m.site.requests, []);
  assert.ok(existsSync(path.join(codexDir(m), "marker")));
});

test("a missing installed copy is reinstalled", async (t) => {
  const v1 = bundle("codex", "1.0.0");
  const m = await machine(t, { codex: { "1.0.0": v1 } });
  await installed("codex", "1.0.0", codexDir(m));
  await fs.rm(codexDir(m), { recursive: true });
  const [outcome] = await refreshPlugins({ pins: pinsFor({ codex: v1 }), baseUrl: m.site.url, log: quiet });
  assert.equal(outcome.result, "reinstalled");
  assert.ok(existsSync(path.join(codexDir(m), ".codex-plugin", "plugin.json")));
});

test("one plugin failing does not stop the others", async (t) => {
  const codex2 = bundle("codex", "2.0.0");
  const agy2 = bundle("antigravity", "2.0.0");
  // Antigravity 2.0.0 is pinned but not published.
  const m = await machine(t, { codex: { "2.0.0": codex2 }, antigravity: {} });
  await installed("antigravity", "1.0.0", agyDir(m));
  await installed("codex", "1.0.0", codexDir(m));
  const outcomes = await refreshPlugins({ pins: pinsFor({ codex: codex2, antigravity: agy2 }), baseUrl: m.site.url, log: quiet });
  const byTarget = Object.fromEntries(outcomes.map((o) => [o.target, o]));
  assert.equal(byTarget.antigravity.result, "failed");
  assert.match(byTarget.antigravity.message, /not updated: .*HTTP 404.*retry with `omnodex update --refresh-plugins`/);
  assert.equal(byTarget.codex.result, "updated");
  assert.equal(await registryVersion("antigravity"), "1.0.0", "a failed plugin keeps its record");
});

test("a version the user chose is kept until the CLI pins a newer one", async (t) => {
  const v2 = bundle("codex", "2.0.0");
  const v4 = bundle("codex", "4.0.0");
  const m = await machine(t, { codex: { "2.0.0": v2, "4.0.0": v4 } });
  await installed("codex", "3.0.0", codexDir(m), { override: true });

  const [kept] = await refreshPlugins({ pins: pinsFor({ codex: v2 }), baseUrl: m.site.url, log: quiet });
  assert.equal(kept.result, "kept");
  assert.match(kept.message, /kept omnodex-codex 3\.0\.0, the version you chose \(this CLI pins 2\.0\.0\)/);

  const [newer] = await refreshPlugins({ pins: pinsFor({ codex: v4 }), baseUrl: m.site.url, log: quiet });
  assert.equal(newer.result, "updated");
  const [entry] = await findInstallations({ target: "codex", component: "plugin" });
  assert.deepEqual([entry.pluginVersion, entry.pluginOverride], ["4.0.0", false]);
});

test("--check reports what would change and changes nothing", async (t) => {
  const v2 = bundle("codex", "2.0.0");
  const m = await machine(t, { codex: { "2.0.0": v2 } });
  await installed("codex", "1.0.0", codexDir(m));
  const lines = [];
  const [outcome] = await refreshPlugins({ check: true, pins: pinsFor({ codex: v2 }), baseUrl: m.site.url, log: (l) => lines.push(l) });
  assert.match(outcome.message, /would update omnodex-codex 1\.0\.0 -> 2\.0\.0/);
  assert.deepEqual(lines, [`  ${outcome.message}`]);
  assert.deepEqual(m.site.requests, []);
  assert.equal(await registryVersion("codex"), "1.0.0");
});
