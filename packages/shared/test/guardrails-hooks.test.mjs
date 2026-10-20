/**
 * The guardrails sidecar: which Omnodex homes sharing a hooks file are in
 * guardrails.
 *
 * Run: node --test packages/shared/test/guardrails-hooks.test.mjs
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  guardrailsHomeId,
  guardrailsSidecarPath,
  homeInGuardrails,
  readGuardrailsHomes,
  setGuardrailsHome,
  syncGuardrailsHome,
} from "../dist/guardrails-hooks.js";

async function fresh(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-guardrails-hooks-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

async function makeHome(dir, name, mode) {
  const home = path.join(dir, name);
  await mkdir(home, { recursive: true });
  if (mode) await writeFile(path.join(home, "omnodex-config.json"), JSON.stringify({ enforcement: { mode } }));
  return home;
}

test("the sidecar sits next to the hooks file it describes", () => {
  assert.equal(
    guardrailsSidecarPath(path.join("/home/case/repo/.claude", "settings.local.json")),
    path.join("/home/case/repo/.claude", "settings.local.omnodex-guardrails.json"),
  );
  assert.equal(
    guardrailsSidecarPath(path.join("/home/case/repo/.agents", "hooks.json")),
    path.join("/home/case/repo/.agents", "hooks.omnodex-guardrails.json"),
  );
});

test("a home id is stable, differs by home and host, and names no path", () => {
  const id = guardrailsHomeId("/home/case/.omnodex", "desk");
  assert.match(id, /^[0-9a-f]{16}$/);
  assert.equal(guardrailsHomeId("/home/case/.omnodex", "desk"), id);
  assert.notEqual(guardrailsHomeId("/home/case/.omnodex", "laptop"), id);
  assert.notEqual(guardrailsHomeId("/home/case/other", "desk"), id);
  assert.equal(guardrailsHomeId("/home/case/.omnodex", "DESK"), id, "host names compare without case");
});

test("two homes sharing a hooks file: the file needs guardrails until both leave", async (t) => {
  const dir = await fresh(t);
  const hooks = path.join(dir, "settings.local.json");
  const a = path.join(dir, "home-a");
  const b = path.join(dir, "home-b");

  assert.equal((await setGuardrailsHome(hooks, a, true)).length, 1);
  assert.equal((await setGuardrailsHome(hooks, b, true)).length, 2);
  assert.equal((await setGuardrailsHome(hooks, b, true)).length, 2, "listing twice keeps one entry");

  assert.deepEqual(await setGuardrailsHome(hooks, a, false), [guardrailsHomeId(b)]);
  assert.ok(existsSync(guardrailsSidecarPath(hooks)));

  assert.deepEqual(await setGuardrailsHome(hooks, b, false), []);
  assert.equal(existsSync(guardrailsSidecarPath(hooks)), false, "removed once nothing is listed");
});

test("unlisting a home that is not listed writes nothing", async (t) => {
  const dir = await fresh(t);
  const hooks = path.join(dir, "settings.local.json");
  assert.deepEqual(await setGuardrailsHome(hooks, path.join(dir, "home"), false), []);
  assert.equal(existsSync(guardrailsSidecarPath(hooks)), false);
});

test("a missing or malformed sidecar lists no homes", async (t) => {
  const dir = await fresh(t);
  const hooks = path.join(dir, "hooks.json");
  assert.deepEqual(await readGuardrailsHomes(hooks), []);
  await writeFile(guardrailsSidecarPath(hooks), "{not json");
  assert.deepEqual(await readGuardrailsHomes(hooks), []);
  await writeFile(guardrailsSidecarPath(hooks), JSON.stringify({ version: 1, homes: ["abc", 3, null] }));
  assert.deepEqual(await readGuardrailsHomes(hooks), ["abc"]);
});

test("syncGuardrailsHome follows the home's mode and reports other homes", async (t) => {
  const dir = await fresh(t);
  const hooks = path.join(dir, "settings.local.json");
  const guarded = await makeHome(dir, "guarded", "guardrails");
  const shadow = await makeHome(dir, "shadow", "shadow");

  assert.equal(homeInGuardrails(guarded), true);
  assert.equal(homeInGuardrails(shadow), false);
  assert.equal(homeInGuardrails(path.join(dir, "missing")), false);

  assert.equal(await syncGuardrailsHome(hooks, shadow), false);
  assert.equal(await syncGuardrailsHome(hooks, guarded), true);
  assert.equal(await syncGuardrailsHome(hooks, shadow), true, "another home still needs it");

  await writeFile(path.join(guarded, "omnodex-config.json"), JSON.stringify({ enforcement: { mode: "monitor" } }));
  assert.equal(await syncGuardrailsHome(hooks, guarded), false);
  const raw = existsSync(guardrailsSidecarPath(hooks)) ? await readFile(guardrailsSidecarPath(hooks), "utf8") : null;
  assert.equal(raw, null);
});
