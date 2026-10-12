// The sync passphrase is now called the stream secret. The config file
// carries it under both names so an older version on the same machine still
// reads it, and the old flag and environment variable keep working.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { readStreamConfig, resolveCredentials, writeStreamConfig } from "../dist/stream-config.js";

async function tempHome(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-secret-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

function withEnv(t, vars) {
  const prev = {};
  for (const [k, v] of Object.entries(vars)) {
    prev[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  t.after(() => {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });
}

test("written under both names, read from either", async (t) => {
  const home = await tempHome(t);
  await writeStreamConfig(home, { api_token: "omx_test_case", passphrase: "case-secret" });
  const raw = JSON.parse(await fs.readFile(path.join(home, "stream-config.json"), "utf8"));
  assert.equal(raw.stream_secret, "case-secret");
  assert.equal(raw.passphrase, "case-secret");

  await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_test_case", stream_secret: "new-name" }));
  assert.equal((await readStreamConfig(home)).passphrase, "new-name");
  await fs.writeFile(path.join(home, "stream-config.json"), JSON.stringify({ api_token: "omx_test_case", passphrase: "old-name" }));
  assert.equal((await readStreamConfig(home)).passphrase, "old-name");
});

test("OMNODEX_STREAM_SECRET wins over the older variable", async (t) => {
  const home = await tempHome(t);
  withEnv(t, { OMNODEX_STREAM_SECRET: "from-new", OMNODEX_SYNC_PASSPHRASE: "from-old", OMNODEX_API_TOKEN: "omx_test_case" });
  assert.equal((await resolveCredentials(home)).passphrase, "from-new");
  withEnv(t, { OMNODEX_STREAM_SECRET: undefined });
  const creds = await resolveCredentials(home);
  assert.equal(creds.passphrase, "from-old");
  assert.equal(creds.passphraseSource, "env");
});
