// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
// omnodex update runs npm without the shell option Node deprecates.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const updateJs = path.join(here, "..", "dist", "update.js");
const updateSrc = path.join(here, "..", "src", "update.ts");

test("spawnNpm runs npm, and Node raises no deprecation about it", () => {
  const script = `import(${JSON.stringify("file://" + updateJs.replace(/\\/g, "/"))}).then((m) => {
    const r = m.spawnNpm(["--version"], { encoding: "utf8" });
    process.stdout.write(String(r.status) + ":" + String(r.stdout).trim());
  });`;
  const r = spawnSync(process.execPath, ["--throw-deprecation", "-e", script], { encoding: "utf8", env: { ...process.env, OMNODEX_NO_UPDATE_CHECK: "1" } });
  assert.equal(r.status, 0, r.stderr);
  assert.doesNotMatch(r.stderr, /DEP0190/);
  assert.match(r.stdout, /^0:\d+\.\d+\.\d+/);
});

test("spawnNpm refuses an argument that is not a plain word on Windows, where the command line is built as text", () => {
  const script = `import(${JSON.stringify("file://" + updateJs.replace(/\\/g, "/"))}).then((m) => {
    try { m.spawnNpm(["install", "x & calc"], { encoding: "utf8" }); process.stdout.write("ran"); }
    catch (e) { process.stdout.write("refused"); }
  });`;
  const r = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", env: { ...process.env, OMNODEX_NO_UPDATE_CHECK: "1" } });
  if (process.platform === "win32") assert.equal(r.stdout, "refused");
});

test("no source file spawns with a shell and an argument list", () => {
  assert.doesNotMatch(readFileSync(updateSrc, "utf8"), /shell:\s*true/);
});

test("the update lines are ASCII, so a legacy code page cannot garble them", () => {
  assert.doesNotMatch(readFileSync(updateSrc, "utf8").split("\n").filter((l) => /console\.|available:/.test(l)).join("\n"), /[^\x00-\x7F]/);
});
