// `omnodex status` shows the latest project settings file that sealed capture
// ignored on this host.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));

async function scratch(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-status-ingest-"));
  t.after(() => fs.rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const omnodexHome = path.join(home, ".omnodex");
  await fs.mkdir(path.join(omnodexHome, "ingest"), { recursive: true });
  return { home, omnodexHome };
}

function status(env) {
  return spawnSync(process.execPath, [CLI, "status"], {
    cwd: env.home,
    env: { ...process.env, HOME: env.home, USERPROFILE: env.home, OMNODEX_HOME: env.omnodexHome, OMNODEX_SINGLE_ROOT: "1", OMNODEX_NO_UPDATE_CHECK: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
}

test("shows the latest ignored settings warning", async (t) => {
  const env = await scratch(t);
  await fs.writeFile(
    path.join(env.omnodexHome, "ingest", "warnings.log"),
    "2026-10-08T09:00:00.000Z older warning\n2026-10-09T09:00:00.000Z newer warning\n",
  );
  const result = status(env);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\[status\] ingest: +warning \(2026-10-09T09:00:00\.000Z\): newer warning/);
  assert.doesNotMatch(result.stdout, /older warning/);
});

test("says nothing when there has been no warning", async (t) => {
  const env = await scratch(t);
  const result = status(env);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /\[status\] ingest:/);
});
