/**
 * The session start check of .claude/settings.local.json reports a password
 * saved inside an approved command: in a connection string, after a password
 * flag, or in a password variable. Placeholders stay quiet.
 */

import { describe, test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { inspectSettingsLocal } from "../dist/settings-secret-check.js";

const PW = "Rk7vQ2mXp9";
const approved = (command) => JSON.stringify({ permissions: { allow: [`Bash(${command})`] } }, null, 2);

let root;
beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "omnodex-settings-pw-"));
  await mkdir(path.join(root, ".claude"), { recursive: true });
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
});

async function typesFor(command) {
  await writeFile(path.join(root, ".claude", "settings.local.json"), approved(command));
  const report = await inspectSettingsLocal(root);
  return report ? report.types : [];
}

describe("settings.local.json check: passwords", () => {
  // [description, saved command, expected types]
  const MUST_FIRE = [
    ["a postgres URL", `psql postgres://app:${PW}@db.internal:5432/orders:*`, ["connection-string"]],
    ["a redis URL with no user", `redis-cli -u redis://:${PW}@cache:6379:*`, ["connection-string"]],
    ["a mongodb+srv URL", `mongosh mongodb+srv://admin:${PW}@cluster0.example.net/test:*`, ["connection-string"]],
    ["mysql -p", `mysql -u root -p${PW} shop:*`, ["password"]],
    ["sshpass -p", `sshpass -p ${PW} ssh deploy@host uptime:*`, ["password"]],
    ["a PGPASSWORD prefix", `PGPASSWORD=${PW} psql -h db -U app orders:*`, ["password"]],
  ];
  for (const [desc, command, expected] of MUST_FIRE) {
    test(`reports ${desc}`, async () => {
      assert.deepEqual(await typesFor(command), expected);
    });
  }

  const MUST_NOT_FIRE = [
    ["a placeholder URL", "psql postgres://user:password@localhost/db:*"],
    ["a variable in a URL", "psql postgres://app:${DB_PASS}@db/orders:*"],
    ["mysql -p with a variable", 'mysql -u root -p\\"$DB_PASS\\" shop:*'],
    ["mkdir -p", "mkdir -p src/lib:*"],
    ["a URL with no password", "psql postgres://app@db.internal:5432/orders:*"],
  ];
  for (const [desc, command] of MUST_NOT_FIRE) {
    test(`is quiet for ${desc}`, async () => {
      assert.deepEqual(await typesFor(command), []);
    });
  }

  test("the report never holds the password", async () => {
    await writeFile(path.join(root, ".claude", "settings.local.json"), approved(`mysql -u root -p${PW} shop:*`));
    const report = await inspectSettingsLocal(root);
    assert.ok(!JSON.stringify(report).includes(PW));
  });
});
