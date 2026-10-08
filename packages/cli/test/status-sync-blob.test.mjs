// `omnodex status` shows the last sync blob's size against the cloud's 50 MB
// limit, warns from 80% with what to do, and says plainly when a push was
// refused for size, which otherwise only shows in the background sync's state.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const MB = 1024 * 1024;

async function scratch(t, autoSyncState) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-status-blob-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const omnodexHome = path.join(home, ".omnodex");
  await fs.mkdir(omnodexHome, { recursive: true });
  await fs.writeFile(path.join(omnodexHome, "auto-sync-state.json"), JSON.stringify({
    last_attempt_at: "2026-10-08T09:00:00.000Z",
    last_success_at: "2026-10-08T09:00:00.000Z",
    last_blob_id: "blob_case_1",
    ...autoSyncState,
  }));
  return { home, omnodexHome };
}

function status(env) {
  const res = spawnSync(process.execPath, [CLI, "status"], {
    cwd: env.home,
    env: { ...process.env, HOME: env.home, USERPROFILE: env.home, OMNODEX_HOME: env.omnodexHome, OMNODEX_SINGLE_ROOT: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
  return res.stdout.split("\n").find((l) => l.includes("sync blob:")) ?? "";
}

test("shows the blob's size against the limit", async (t) => {
  const env = await scratch(t, { last_blob_bytes: 12.5 * MB });
  const line = status(env);
  assert.match(line, /12\.5 MB of 50 MB \(25%\)$/);
});

test("warns from 80%, with where to make room", async (t) => {
  const env = await scratch(t, { last_blob_bytes: 41 * MB });
  const line = status(env);
  assert.match(line, /41\.0 MB of 50 MB \(82%\), close to the limit/);
  assert.ok(line.includes(path.join(env.omnodexHome, "event-log", "sessions")), line);
});

test("says when a push was refused for size", async (t) => {
  const env = await scratch(t, { last_blob_bytes: 49 * MB, blob_too_large_bytes: 52 * MB, last_error: "sync push refused" });
  const line = status(env);
  assert.match(line, /52\.0 MB, over the 50 MB limit: sync is failing/);
});

test("says nothing before the first sync", async (t) => {
  const env = await scratch(t, {});
  assert.equal(status(env), "");
});
