// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir, access } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { OpenCodeInterceptor, PLUGIN_MARKER } from "../dist/index.js";

async function project(t) {
  const d = await mkdtemp(path.join(os.tmpdir(), "omnodex-opencode-int-"));
  t.after(() => rm(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  return d;
}
const make = (projectPath, extra = {}) =>
  new OpenCodeInterceptor({ projectPath, shimPath: "/h/.omnodex/bin/opencode-plugin-launcher.js", omnodexHome: "/h/.omnodex", ...extra });
const exists = (file) => access(file).then(() => true, () => false);

test("install writes the marked plugin into the project's .opencode/plugins/omnodex.js", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  assert.equal(i.hooksFilePath(), path.join(dir, ".opencode", "plugins", "omnodex.js"));
  await i.install();
  const src = await readFile(i.hooksFilePath(), "utf8");
  assert.ok(src.includes(PLUGIN_MARKER));
  assert.match(src, /opencode-plugin-launcher\.js/);
  assert.match(src, /"userScope": false/);
});

test("a reinstall replaces the plugin; the user-scope marker is carried", async (t) => {
  const dir = await project(t);
  const file = path.join(dir, "u", "omnodex.js");
  const i = make(dir, { hooksPath: file, launcherArgs: ["--user-scope"] });
  await i.install();
  await i.install();
  assert.match(await readFile(file, "utf8"), /"userScope": true/);
});

test("uninstall removes the plugin, and leaves a file Omnodex did not write", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  await i.install();
  await i.uninstall();
  assert.equal(await exists(i.hooksFilePath()), false);
  await mkdir(path.dirname(i.hooksFilePath()), { recursive: true });
  await writeFile(i.hooksFilePath(), "export const Mine = async () => ({});\n");
  await i.uninstall();
  assert.equal(await readFile(i.hooksFilePath(), "utf8"), "export const Mine = async () => ({});\n");
  await make(await project(t)).uninstall();
});

test("install refuses to overwrite a plugin file Omnodex did not write", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  await mkdir(path.dirname(i.hooksFilePath()), { recursive: true });
  await writeFile(i.hooksFilePath(), "export const Mine = async () => ({});\n");
  await assert.rejects(i.install(), /not an Omnodex plugin/);
  assert.equal(await readFile(i.hooksFilePath(), "utf8"), "export const Mine = async () => ({});\n");
});
