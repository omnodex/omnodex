// Installing the Copilot hooks file: PascalCase events, Omnodex's own file,
// and no harm to anyone else's hooks.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir, access } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { COPILOT_EVENT_NAMES, CopilotInterceptor } from "../dist/index.js";

async function project(t) {
  const d = await mkdtemp(path.join(os.tmpdir(), "omnodex-copilot-int-"));
  t.after(() => rm(d, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  return d;
}
const make = (projectPath, extra = {}) =>
  new CopilotInterceptor({ projectPath, shimPath: "/h/.omnodex/bin/copilot-hook-launcher.js", omnodexHome: "/h/.omnodex", ...extra });
const readHooks = async (file) => JSON.parse(await readFile(file, "utf8"));
const exists = (file) => access(file).then(() => true, () => false);

test("install writes version 1 and a PascalCase entry for each event, into the project's own file", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  assert.equal(i.hooksFilePath(), path.join(dir, ".github", "hooks", "omnodex.json"));
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.equal(file.version, 1);
  assert.deepEqual(Object.keys(file.hooks), [...COPILOT_EVENT_NAMES]);
  for (const [name, entries] of Object.entries(file.hooks)) {
    assert.equal(entries.length, 1, name);
    assert.equal(entries[0].type, "command");
    assert.match(entries[0].bash, /copilot-hook-launcher\.js/);
    assert.match(entries[0].powershell, /copilot-hook-launcher\.js/);
    assert.match(entries[0].bash, /OMNODEX_HOME=/);
    assert.match(entries[0].powershell, /\$env:OMNODEX_HOME=/);
    assert.ok(entries[0].timeoutSec > 0);
  }
  assert.ok(file.hooks.PreToolUse && file.hooks.PostToolUseFailure && file.hooks.PermissionRequest);
  assert.equal(file.hooks.Stop, undefined, "the end of a turn is not recorded");
});

test("a reinstall replaces our entries and keeps anyone else's", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  await mkdir(path.dirname(i.hooksFilePath()), { recursive: true });
  await writeFile(i.hooksFilePath(), JSON.stringify({ version: 1, hooks: { preToolUse: [{ type: "command", bash: "./mine.sh" }], PreToolUse: [{ type: "command", bash: "./theirs.sh" }] } }));
  await i.install();
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.equal(file.hooks.PreToolUse.length, 2);
  assert.equal(file.hooks.PreToolUse[0].bash, "./theirs.sh");
  assert.deepEqual(file.hooks.preToolUse, [{ type: "command", bash: "./mine.sh" }]);
});

test("uninstall removes only our entries, and deletes the file when nothing else is left", async (t) => {
  const dir = await project(t);
  const i = make(dir);
  await i.install();
  await i.uninstall();
  assert.equal(await exists(i.hooksFilePath()), false);

  await mkdir(path.dirname(i.hooksFilePath()), { recursive: true });
  await writeFile(i.hooksFilePath(), JSON.stringify({ version: 1, hooks: { PreToolUse: [{ type: "command", bash: "./theirs.sh" }] } }));
  await i.install();
  await i.uninstall();
  assert.deepEqual((await readHooks(i.hooksFilePath())).hooks, { PreToolUse: [{ type: "command", bash: "./theirs.sh" }] });
  // Uninstalling where nothing was installed is harmless.
  await make(await project(t)).uninstall();
});

test("the home-relative form is one command that works in bash and PowerShell, with the user-scope marker", async (t) => {
  const dir = await project(t);
  const i = make(dir, { hooksPath: path.join(dir, "u", "omnodex.json"), homeRelativeShimPath: ".omnodex/bin/copilot-hook-launcher.js", launcherArgs: ["--user-scope"] });
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.equal(file.hooks.SessionStart[0].command, 'node "$HOME/.omnodex/bin/copilot-hook-launcher.js" --user-scope');
  assert.equal(file.hooks.SessionStart[0].bash, undefined);
});

test("SessionEnd gets a short timeout", async (t) => {
  const dir = await project(t);
  const i = make(dir, { timeoutSeconds: 60 });
  await i.install();
  const file = await readHooks(i.hooksFilePath());
  assert.equal(file.hooks.SessionEnd[0].timeoutSec, 10);
  assert.equal(file.hooks.PreToolUse[0].timeoutSec, 60);
});

test("paths with spaces and quotes stay one argument in each shell", async (t) => {
  const dir = await project(t);
  const i = make(dir, { shimPath: "/Users/o'neil/my dir/copilot-hook-shim.js", omnodexHome: "/Users/o'neil/.omnodex" });
  await i.install();
  const entry = (await readHooks(i.hooksFilePath())).hooks.PreToolUse[0];
  assert.match(entry.bash, /'\/Users\/o'\\''neil\/my dir\/copilot-hook-shim\.js'/);
  assert.match(entry.powershell, /'\/Users\/o''neil\/my dir\/copilot-hook-shim\.js'/);
});
