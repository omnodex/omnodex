// OMNODEX_SINGLE_ROOT=1 keeps a run inside OMNODEX_HOME. Without it the
// default home is always added as a second root, so a test pointed at a
// scratch or copied home also read and wrote the developer's real event log.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { EventLog } from "../../event-log/dist/index.js";
import { resolveRoots, singleRootRequested } from "../dist/config.js";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));

async function mkTmp(t, label) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), `omnodex-${label}-`));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

/** Write one finished session into a root's event log. */
async function seedRoot(root, sessionId) {
  const log = new EventLog({ root: path.join(root, "event-log") });
  await log.init();
  const at = "2026-09-18T12:00:00.000Z";
  const base = { schema_version: 1, session_id: sessionId, occurred_at: at, recorded_at: at, interceptor: "claude-code-hook" };
  await log.appendMany([
    { ...base, event_id: `${sessionId}-start`, event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: [] },
    { ...base, event_id: `${sessionId}-end`, event_type: "session.ended" },
  ]);
  await log.close();
}

/** Every file under dir with its contents, for a before/after comparison. */
async function snapshot(dir) {
  const out = {};
  for (const entry of await fs.readdir(dir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const full = path.join(entry.parentPath ?? entry.path, entry.name);
    out[path.relative(dir, full)] = await fs.readFile(full, "utf8");
  }
  return out;
}

/** Runs body with HOME, OMNODEX_HOME and OMNODEX_SINGLE_ROOT set, then restores them. */
async function withEnv(env, body) {
  const keys = ["HOME", "USERPROFILE", "OMNODEX_HOME", "OMNODEX_SINGLE_ROOT"];
  const prev = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  for (const k of keys) {
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    return await body();
  } finally {
    for (const k of keys) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
  }
}

test("singleRootRequested accepts 1, true and yes", async () => {
  for (const [value, expected] of [["1", true], ["true", true], ["YES", true], ["0", false], ["", false], [undefined, false]]) {
    await withEnv({ OMNODEX_SINGLE_ROOT: value }, async () => {
      assert.equal(singleRootRequested(), expected, `OMNODEX_SINGLE_ROOT=${value}`);
    });
  }
});

test("MUST_NOT include the default home with OMNODEX_SINGLE_ROOT=1", async (t) => {
  const fakeHome = await mkTmp(t, "home");
  const scratch = await mkTmp(t, "scratch");
  const resolved = await withEnv(
    { HOME: fakeHome, USERPROFILE: fakeHome, OMNODEX_HOME: scratch, OMNODEX_SINGLE_ROOT: "1" },
    () => resolveRoots(),
  );
  assert.deepEqual(resolved.all, [path.resolve(scratch)]);
  assert.equal(resolved.primary, path.resolve(scratch));
});

test("MUST include the default home without OMNODEX_SINGLE_ROOT", async (t) => {
  const fakeHome = await mkTmp(t, "home");
  const scratch = await mkTmp(t, "scratch");
  const resolved = await withEnv(
    { HOME: fakeHome, USERPROFILE: fakeHome, OMNODEX_HOME: scratch },
    () => resolveRoots(),
  );
  assert.deepEqual(resolved.all, [path.resolve(scratch), path.resolve(fakeHome, ".omnodex")]);
});

test("OMNODEX_SINGLE_ROOT keeps roots named explicitly in config and --roots", async (t) => {
  const fakeHome = await mkTmp(t, "home");
  const scratch = await mkTmp(t, "scratch");
  const fromConfig = await mkTmp(t, "config-root");
  const fromFlag = await mkTmp(t, "flag-root");
  await fs.writeFile(path.join(scratch, "config.json"), JSON.stringify({ dashboard: { roots: [fromConfig] } }));
  const resolved = await withEnv(
    { HOME: fakeHome, USERPROFILE: fakeHome, OMNODEX_HOME: scratch, OMNODEX_SINGLE_ROOT: "1" },
    () => resolveRoots([fromFlag]),
  );
  assert.deepEqual(resolved.all, [scratch, fromConfig, fromFlag].map((p) => path.resolve(p)));
});

test("detect with OMNODEX_SINGLE_ROOT=1 neither scans nor changes the default home", async (t) => {
  const fakeHome = await mkTmp(t, "home");
  const defaultHome = path.join(fakeHome, ".omnodex");
  const scratch = await mkTmp(t, "scratch");
  await seedRoot(defaultHome, "case-default-session");
  await seedRoot(scratch, "case-scratch-session");
  const before = await snapshot(defaultHome);

  const result = spawnSync(process.execPath, [CLI, "detect"], {
    env: { ...process.env, HOME: fakeHome, USERPROFILE: fakeHome, OMNODEX_HOME: scratch, OMNODEX_SINGLE_ROOT: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr);
  // The roots line comes first, so a reader sees what the run will touch.
  assert.match(result.stdout, new RegExp(`^\\[detect\\] roots: ${path.resolve(scratch).replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")}$`, "m"));
  assert.match(result.stdout, /case-scratch-session/);
  assert.doesNotMatch(result.stdout, /case-default-session/);
  assert.deepEqual(await snapshot(defaultHome), before);
});
