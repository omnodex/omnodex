/**
 * Tests for how the generated hook launcher finds and runs its shim.
 *
 * Each test writes the launcher into a temp dir and runs it with a controlled
 * PATH and HOME, so nothing touches the real ~/.omnodex.
 *
 * Tests:
 *   1. npm package layout reached through a symlinked global bin (Unix)
 *   2. npm package layout beside a Windows-style wrapper on PATH
 *   3. Launcher arguments are forwarded to the shim
 *   4. Resolve-only mode reports a missing shim without running anything
 *   5. shim_paths in omnodex-config.json wins over PATH
 *   6. refreshStaleLaunchers rewrites outdated launchers only
 *   7. ensureLauncherResolves pins the CLI's own shim only when nothing resolves
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs, readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { generateLauncherSource, ensureLauncherResolves } from "../dist/launcher-template.js";

const NODE_DIR = path.dirname(process.execPath);

// A fake shim that records its argv and stdin next to itself.
const RECORDING_SHIM = `
const fs = require("node:fs");
let input = "";
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", () => {
  fs.writeFileSync(__filename + ".ran.json", JSON.stringify({ args: process.argv.slice(2), input }));
});
`;

async function makeTemp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "omnodex-launcher-"));
}

async function writeFile(p, content, mode = 0o755) {
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, content, { mode });
}

async function writeLauncherFile(dir, platform) {
  const p = path.join(dir, `${platform}-launcher.js`);
  await writeFile(p, generateLauncherSource(platform));
  return p;
}

function runLauncher(launcher, { pathDirs, home, args = [], input = "", env = {} }) {
  return spawnSync(process.execPath, [launcher, ...args], {
    input,
    encoding: "utf8",
    env: {
      PATH: [...pathDirs, NODE_DIR, "/usr/bin", "/bin"].join(path.delimiter),
      HOME: home,
      USERPROFILE: home,
      OMNODEX_HOME: path.join(home, ".omnodex"),
      ...env,
    },
  });
}

async function readRecord(shim) {
  return JSON.parse(await fs.readFile(shim + ".ran.json", "utf8"));
}

test("launcher: finds the shim in the npm package through a symlinked global bin", { skip: process.platform === "win32" }, async () => {
  const tmp = await makeTemp();
  try {
    const pkgBin = path.join(tmp, "prefix", "lib", "node_modules", "omnodex", "bin");
    const shim = path.join(pkgBin, "claude-hook-shim.js");
    await writeFile(path.join(pkgBin, "omnodex"), "#!/usr/bin/env node\n");
    await writeFile(shim, RECORDING_SHIM);
    const globalBin = path.join(tmp, "prefix", "bin");
    await fs.mkdir(globalBin, { recursive: true });
    await fs.symlink(path.join(pkgBin, "omnodex"), path.join(globalBin, "omnodex"));

    const launcher = await writeLauncherFile(tmp, "claude-code");
    const result = runLauncher(launcher, {
      pathDirs: [globalBin],
      home: path.join(tmp, "home"),
      input: '{"hook_event_name":"PreToolUse"}',
    });

    assert.equal(result.status, 0, result.stderr);
    const record = await readRecord(shim);
    assert.equal(record.input, '{"hook_event_name":"PreToolUse"}');
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("launcher: finds the shim in node_modules/omnodex beside a wrapper on PATH", async () => {
  const tmp = await makeTemp();
  try {
    // Windows npm layout: <prefix>\omnodex(.cmd) and <prefix>\node_modules\omnodex
    const prefix = path.join(tmp, "prefix");
    await writeFile(path.join(prefix, "omnodex"), "#!/bin/sh\n");
    const shim = path.join(prefix, "node_modules", "omnodex", "bin", "codex-hook-shim.js");
    await writeFile(shim, RECORDING_SHIM);

    const launcher = await writeLauncherFile(tmp, "codex");
    const result = runLauncher(launcher, {
      pathDirs: [prefix],
      home: path.join(tmp, "home"),
      env: { OMNODEX_LAUNCHER_RESOLVE_ONLY: "1" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), shim);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("launcher: forwards its arguments to the shim", async () => {
  const tmp = await makeTemp();
  try {
    const prefix = path.join(tmp, "prefix");
    await writeFile(path.join(prefix, "omnodex"), "#!/bin/sh\n");
    const shim = path.join(prefix, "node_modules", "omnodex", "bin", "antigravity-hook-shim.js");
    await writeFile(shim, RECORDING_SHIM);

    const launcher = await writeLauncherFile(tmp, "antigravity");
    const result = runLauncher(launcher, {
      pathDirs: [prefix],
      home: path.join(tmp, "home"),
      args: ["PreToolUse"],
      input: "{}",
    });

    assert.equal(result.status, 0, result.stderr);
    const record = await readRecord(shim);
    assert.deepEqual(record.args, ["PreToolUse"]);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("launcher: resolve-only mode exits 1 when no shim can be found", async () => {
  const tmp = await makeTemp();
  try {
    const home = path.join(tmp, "home");
    const launcher = await writeLauncherFile(tmp, "claude-code");
    const result = runLauncher(launcher, {
      pathDirs: [path.join(tmp, "empty")],
      home,
      env: { OMNODEX_LAUNCHER_RESOLVE_ONLY: "1" },
    });

    assert.equal(result.status, 1);
    assert.equal(result.stdout, "");
    // Resolve-only is a check, not a failed hook call, so nothing is logged
    await assert.rejects(fs.access(path.join(home, ".omnodex", "launcher.log")));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("launcher: shim_paths in omnodex-config.json takes priority over PATH", async () => {
  const tmp = await makeTemp();
  try {
    const prefix = path.join(tmp, "prefix");
    await writeFile(path.join(prefix, "omnodex"), "#!/bin/sh\n");
    await writeFile(path.join(prefix, "node_modules", "omnodex", "bin", "claude-hook-shim.js"), RECORDING_SHIM);
    const devShim = path.join(tmp, "dev", "claude-hook-shim.js");
    await writeFile(devShim, RECORDING_SHIM);

    const home = path.join(tmp, "home");
    await writeFile(
      path.join(home, ".omnodex", "omnodex-config.json"),
      JSON.stringify({ shim_paths: { "claude-code": devShim } }),
      0o644,
    );

    const launcher = await writeLauncherFile(tmp, "claude-code");
    const result = runLauncher(launcher, {
      pathDirs: [prefix],
      home,
      env: { OMNODEX_LAUNCHER_RESOLVE_ONLY: "1" },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), devShim);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("refreshStaleLaunchers: rewrites outdated launchers and skips missing ones", async () => {
  const tmp = await makeTemp();
  try {
    const home = path.join(tmp, "home");
    const binDir = path.join(home, ".omnodex", "bin");
    await writeFile(path.join(binDir, "claude-hook-launcher.js"), "// written by an older version\n");
    await writeFile(path.join(binDir, "codex-hook-launcher.js"), generateLauncherSource("codex"));

    const moduleUrl = new URL("../dist/launcher-template.js", import.meta.url).href;
    const script =
      `import(${JSON.stringify(moduleUrl)}).then(async (m) => ` +
      `console.log(JSON.stringify(await m.refreshStaleLaunchers())))`;
    const result = spawnSync(process.execPath, ["-e", script], {
      encoding: "utf8",
      env: { ...process.env, HOME: home, USERPROFILE: home },
    });

    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), ["claude-code"]);
    assert.equal(
      await fs.readFile(path.join(binDir, "claude-hook-launcher.js"), "utf8"),
      generateLauncherSource("claude-code"),
    );
    await assert.rejects(fs.access(path.join(binDir, "antigravity-hook-launcher.js")));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

// A resolver that behaves like a launcher which only knows shim_paths.
function configResolver(omnodexHome) {
  return (platform) => {
    try {
      const raw = readFileSync(path.join(omnodexHome, "omnodex-config.json"), "utf8");
      return JSON.parse(raw).shim_paths?.[platform] ?? null;
    } catch {
      return null;
    }
  };
}

test("ensureLauncherResolves: leaves config alone when the launcher already finds a shim", async () => {
  const tmp = await makeTemp();
  try {
    const home = path.join(tmp, ".omnodex");
    const ownShim = path.join(tmp, "own", "claude-hook-shim.js");
    await writeFile(ownShim, RECORDING_SHIM);

    const check = await ensureLauncherResolves("claude-code", home, [ownShim], () => "/usr/lib/node_modules/omnodex/bin/claude-hook-shim.js");

    assert.deepEqual(check, { status: "resolved", shim: "/usr/lib/node_modules/omnodex/bin/claude-hook-shim.js" });
    await assert.rejects(fs.access(path.join(home, "omnodex-config.json")));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("ensureLauncherResolves: pins the first existing candidate and keeps other config", async () => {
  const tmp = await makeTemp();
  try {
    const home = path.join(tmp, ".omnodex");
    const configPath = path.join(home, "omnodex-config.json");
    await writeFile(configPath, JSON.stringify({ shim_paths: { codex: "/keep/codex-hook-shim.js" }, other: 1 }), 0o644);
    const ownShim = path.join(tmp, "own", "claude-hook-shim.js");
    await writeFile(ownShim, RECORDING_SHIM);

    const check = await ensureLauncherResolves(
      "claude-code",
      home,
      [path.join(tmp, "missing", "claude-hook-shim.js"), ownShim],
      configResolver(home),
    );

    assert.deepEqual(check, { status: "pinned", shim: ownShim, configPath });
    const config = JSON.parse(await fs.readFile(configPath, "utf8"));
    assert.deepEqual(config, {
      shim_paths: { codex: "/keep/codex-hook-shim.js", "claude-code": ownShim },
      other: 1,
    });
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("ensureLauncherResolves: reports unresolved without writing when no candidate exists", async () => {
  const tmp = await makeTemp();
  try {
    const home = path.join(tmp, ".omnodex");
    const check = await ensureLauncherResolves("codex", home, [path.join(tmp, "missing.js")], () => null);

    assert.equal(check.status, "unresolved");
    await assert.rejects(fs.access(path.join(home, "omnodex-config.json")));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test("ensureLauncherResolves: does not overwrite an unreadable config", async () => {
  const tmp = await makeTemp();
  try {
    const home = path.join(tmp, ".omnodex");
    const configPath = path.join(home, "omnodex-config.json");
    await writeFile(configPath, "{ not json", 0o644);
    const ownShim = path.join(tmp, "own", "codex-hook-shim.js");
    await writeFile(ownShim, RECORDING_SHIM);

    const check = await ensureLauncherResolves("codex", home, [ownShim], () => null);

    assert.equal(check.status, "unresolved");
    assert.equal(await fs.readFile(configPath, "utf8"), "{ not json");
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});
