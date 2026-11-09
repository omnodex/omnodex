// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
// Installing the Cursor hooks file: version 1, Omnodex's own entries, and no
// harm to anyone else's hooks.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir, access } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { CURSOR_EVENT_NAMES, CursorInterceptor } from "../dist/index.js";

async function project(t) {
  const d = await mkdtemp(path.join(os.tmpdir(), "omnodex-cursor-int-"));
  t.after(() => rm(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  return d;
}
const make = (projectPath, extra = {}) =>
  new CursorInterceptor({ projectPath, shimPath: "/h/.omnodex/bin/cursor-hook-launcher.js", omnodexHome: "/h/.omnodex", platform: "linux", ...extra });
const readHooks = async (file) => JSON.parse(await readFile(file, "utf8"));
const exists = (file) => access(file).then(() => true, () => false);

test("install writes version 1 and one command per event, into the project's .cursor/hooks.json", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  assert.equal(i.hooksFilePath(), path.join(dir, ".cursor", "hooks.json"));
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.equal(file.version, 1);
  assert.deepEqual(Object.keys(file.hooks), [...CURSOR_EVENT_NAMES]);
  for (const [name, entries] of Object.entries(file.hooks)) {
    assert.equal(entries.length, 1, name);
    assert.match(entries[0].command, /^OMNODEX_HOME=\/h\/\.omnodex node \/h\/\.omnodex\/bin\/cursor-hook-launcher\.js$/);
    assert.ok(entries[0].timeout > 0);
  }
  for (const name of ["preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"]) assert.ok(file.hooks[name], name);
  assert.equal(file.hooks.afterShellExecution, undefined, "the after-hooks would record a call twice");
  assert.equal(file.hooks.stop, undefined);
});

test("on Windows the command carries no inline environment", async (t) => {
  const dir = await project(t);
  const i = make(dir, { platform: "win32", shimPath: "C:\\Users\\case\\.omnodex\\bin\\cursor-hook-launcher.js" });
  await i.install();
  assert.equal((await readHooks(i.hooksFilePath())).hooks.preToolUse[0].command, "node C:\\Users\\case\\.omnodex\\bin\\cursor-hook-launcher.js");
});

test("a reinstall replaces our entries and keeps anyone else's", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  await mkdir(path.dirname(i.hooksFilePath()), { recursive: true });
  await writeFile(i.hooksFilePath(), JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "./mine.sh" }], stop: [{ command: "./stop.sh" }] } }));
  await i.install();
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.equal(file.hooks.preToolUse.length, 2);
  assert.equal(file.hooks.preToolUse[0].command, "./mine.sh");
  assert.deepEqual(file.hooks.stop, [{ command: "./stop.sh" }]);
});

test("uninstall removes only our entries, and deletes the file when nothing else is left", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  await i.install();
  await i.uninstall();
  assert.equal(await exists(i.hooksFilePath()), false);

  await mkdir(path.dirname(i.hooksFilePath()), { recursive: true });
  await writeFile(i.hooksFilePath(), JSON.stringify({ version: 1, hooks: { preToolUse: [{ command: "./theirs.sh" }] } }));
  await i.install();
  await i.uninstall();
  assert.deepEqual((await readHooks(i.hooksFilePath())).hooks, { preToolUse: [{ command: "./theirs.sh" }] });
  await make(await project(t)).uninstall();
});

test("the user-scope marker follows the launcher, and sessionEnd gets a short timeout", async (t) => {
  const dir = await project(t);
  const i = make(dir, { hooksPath: path.join(dir, "u", "hooks.json"), launcherArgs: ["--user-scope"], timeoutSeconds: 60 });
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.match(file.hooks.sessionStart[0].command, /cursor-hook-launcher\.js --user-scope$/);
  assert.equal(file.hooks.sessionEnd[0].timeout, 10);
  assert.equal(file.hooks.preToolUse[0].timeout, 60);
});

test("paths with spaces and quotes stay one argument", async (t) => {
  const dir = await project(t);
  const i = make(dir, { shimPath: "/Users/o'neil/my dir/cursor-hook-shim.js", omnodexHome: "/Users/o'neil/.omnodex" });
  await i.install();
  const entry = (await readHooks(i.hooksFilePath())).hooks.preToolUse[0];
  assert.match(entry.command, /'\/Users\/o'\\''neil\/my dir\/cursor-hook-shim\.js'/);
  assert.match(entry.command, /OMNODEX_HOME='\/Users\/o'\\''neil\/\.omnodex'/);
});
