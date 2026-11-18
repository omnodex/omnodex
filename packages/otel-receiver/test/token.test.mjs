import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import { ensureToken, readStoredToken, resolveToken } from "../dist/index.js";
import { scratchHome } from "./helpers.mjs";

test("a token is created once, kept, and replaced only on rotate", async (t) => {
  const home = await scratchHome(t);
  assert.equal(await readStoredToken(home), undefined);
  const first = await ensureToken(home);
  assert.equal(first.created, true);
  assert.match(first.token, /^omxotel_[A-Za-z0-9_-]{43}$/);
  const again = await ensureToken(home);
  assert.deepEqual(again, { token: first.token, created: false });
  const rotated = await ensureToken(home, { rotate: true });
  assert.equal(rotated.created, true);
  assert.notEqual(rotated.token, first.token);
  assert.equal(await readStoredToken(home), rotated.token);
});

test("the token file is private to the user", { skip: process.platform === "win32" }, async (t) => {
  const home = await scratchHome(t);
  await ensureToken(home);
  const stat = await fs.stat(path.join(home, "otel-receiver.json"));
  assert.equal(stat.mode & 0o777, 0o600);
});

test("the environment's token wins over the stored one", async (t) => {
  const home = await scratchHome(t);
  const { token } = await ensureToken(home);
  assert.equal(await resolveToken(home, {}), token);
  assert.equal(await resolveToken(home, { OMNODEX_OTEL_TOKEN: "from-env" }), "from-env");
  assert.equal(await resolveToken(path.join(home, "nowhere"), {}), undefined);
});

test("an unreadable token file means no token, not a crash", async (t) => {
  const home = await scratchHome(t);
  await fs.writeFile(path.join(home, "otel-receiver.json"), "{ broken");
  assert.equal(await readStoredToken(home), undefined);
});
