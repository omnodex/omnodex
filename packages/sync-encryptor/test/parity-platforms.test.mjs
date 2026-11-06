// Monitoring knows the new platforms: the heartbeat names them and the config
// check recognizes their hook files and notices when the Omnodex entry goes.
//
// Run: node --test packages/sync-encryptor/test/parity-platforms.test.mjs

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { buildHeartbeat } from "../dist/monitoring-heartbeat.js";
import { checkMonitoringConfig, MONITORING_CHECK_INTERVAL_MS } from "../dist/monitoring-check.js";

const T0 = Date.parse("2026-11-06T12:00:00.000Z");
const LATER = T0 + MONITORING_CHECK_INTERVAL_MS + 1000;

async function put(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, typeof value === "string" ? value : JSON.stringify(value, null, 2));
}

async function machine(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "omnodex-parity-mon-"));
  t.after(() => rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const userHome = path.join(root, "home");
  const omnodexHome = path.join(userHome, ".omnodex");
  const project = path.join(root, "project");
  await mkdir(omnodexHome, { recursive: true });
  await mkdir(project, { recursive: true });
  return { root, userHome, omnodexHome, project, check: (at) => checkMonitoringConfig(omnodexHome, { now: at, userHome, env: {} }) };
}

const register = (m, entries) =>
  put(path.join(m.omnodexHome, "installations.json"), {
    version: 2,
    installations: entries.map((e) => ({ installedAt: "2026-10-01T00:00:00.000Z", installedVersion: "0.9.0", usesLauncher: true, component: "hooks", ...e })),
  });

describe("heartbeat", () => {
  it("reports the new platforms by name", async (t) => {
    const m = await machine(t);
    await put(path.join(m.omnodexHome, "monitoring-check.json"), {
      first_run_at: new Date(T0).toISOString(),
      last_run_at: new Date(T0).toISOString(),
      slots: { "copilot|hooks|user|": "ok", "cursor|hooks|user|": "hooks_missing", "opencode|hooks|user|": "ok" },
    });
    const h = await buildHeartbeat(m.omnodexHome);
    assert.deepEqual(h.platforms.map((p) => [p.platform, p.hooks]), [["copilot", "ok"], ["cursor", "missing"], ["opencode", "ok"]]);
  });
});

describe("config check", () => {
  const cases = [
    { target: "copilot", file: (m) => path.join(m.userHome, ".copilot", "hooks", "omnodex.json"), ours: { hooks: { preToolUse: [{ command: "node copilot-hook-launcher.js" }] } } },
    { target: "cursor", file: (m) => path.join(m.userHome, ".cursor", "hooks.json"), ours: { hooks: { preToolUse: [{ command: "node cursor-hook-launcher.js" }] } } },
    { target: "opencode", file: (m) => path.join(m.userHome, ".config", "opencode", "plugins", "omnodex.js"), ours: "// omnodex-managed\nexport const Omnodex = async () => ({});\n" },
  ];
  for (const c of cases) {
    it(`${c.target}: a user-level file with our entry is ok, and losing it is reported once`, async (t) => {
      const m = await machine(t);
      const file = c.file(m);
      await put(file, c.ours);
      await register(m, [{ target: c.target, scope: "user", settingsFile: file }]);
      const first = await m.check(T0);
      assert.deepEqual(first.checks.map((x) => x.state), ["ok"]);
      await put(file, typeof c.ours === "string" ? "// something else\n" : { hooks: {} });
      const second = await m.check(LATER);
      assert.deepEqual(second.checks.map((x) => x.state), ["hooks_missing"]);
      assert.equal(second.written.length, 2);
    });
  }

  it("project hook files are looked up where each platform keeps them", async (t) => {
    const m = await machine(t);
    await put(path.join(m.project, ".github", "hooks", "omnodex.json"), { hooks: { preToolUse: [{ command: "node copilot-hook-launcher.js" }] } });
    await put(path.join(m.project, ".cursor", "hooks.json"), { hooks: { preToolUse: [{ command: "node cursor-hook-launcher.js" }] } });
    await put(path.join(m.project, ".opencode", "plugins", "omnodex.js"), "// omnodex-managed\n");
    await register(m, ["copilot", "cursor", "opencode"].map((target) => ({ target, scope: "project", projectPath: m.project, settingsFile: "unused" })));
    const r = await m.check(T0);
    assert.deepEqual(r.checks.map((x) => [x.target, x.state]).sort(), [["copilot", "ok"], ["cursor", "ok"], ["opencode", "ok"]]);
  });
});
