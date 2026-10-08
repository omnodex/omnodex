// `omnodex status` shows advanced (Pro) rule usage waiting to be sent, and
// any counts dropped for being older than 7 days, so a machine that was
// offline can see what was not billed.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));

async function scratch(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-status-usage-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const omnodexHome = path.join(home, ".omnodex");
  await fs.mkdir(omnodexHome, { recursive: true });
  return { home, omnodexHome };
}

function status(env) {
  return spawnSync(process.execPath, [CLI, "status"], {
    cwd: env.home,
    env: { ...process.env, HOME: env.home, USERPROFILE: env.home, OMNODEX_HOME: env.omnodexHome, OMNODEX_SINGLE_ROOT: "1" },
    encoding: "utf8",
    timeout: 60_000,
  });
}

test("reports waiting and dropped advanced usage", async (t) => {
  const env = await scratch(t);
  await fs.writeFile(path.join(env.omnodexHome, "advanced-usage.json"), JSON.stringify({
    version: 1,
    pending: { "2026-10-08": { evaluated: 7, findings: 1 } },
    in_flight: { batch_id: "case", days: { "2026-10-08": { evaluated: 5, findings: 0 } } },
    last_submitted_at: "2026-10-08T09:00:00.000Z",
    last_error: "HTTP 503",
    dropped: { evaluated: 40, days: 2, last_at: "2026-10-08T09:00:00.000Z" },
  }));
  const result = status(env);
  assert.equal(result.status, 0, result.stderr);
  const line = result.stdout.split("\n").find((l) => l.startsWith("[status] pro usage:"));
  assert.ok(line, result.stdout);
  assert.match(line, /12 advanced rule checks waiting to send/);
  assert.match(line, /last sent 2026-10-08T09:00:00\.000Z/);
  assert.match(line, /last error: HTTP 503/);
  assert.match(line, /40 checks over 2 day\(s\) dropped/);
});

test("says nothing on a machine that has never counted", async (t) => {
  const env = await scratch(t);
  const result = status(env);
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /pro usage/);
});
