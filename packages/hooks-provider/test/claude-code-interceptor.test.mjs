// Unit tests for the ClaudeCodeInterceptor. Verifies install/uninstall
// is idempotent, preserves unknown settings fields, and leaves non
// Omnodex hook handlers alone.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { ClaudeCodeInterceptor } from "../dist/claude-code-interceptor.js";

async function fresh(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-interceptor-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function makeInterceptor(projectPath) {
  return new ClaudeCodeInterceptor({
    projectPath,
    shimPath: "/opt/omnodex/shim.js",
    omnodexHome: path.join(projectPath, ".omnodex-home"),
    settingsFile: "settings.local.json",
  });
}

test("install writes the five hook events with async=true", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();

  const raw = await readFile(interceptor.settingsFilePath(), "utf8");
  const settings = JSON.parse(raw);

  for (const eventName of [
    "SessionStart",
    "SessionEnd",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
  ]) {
    assert.ok(settings.hooks[eventName], `expected ${eventName} group`);
    const [group] = settings.hooks[eventName];
    assert.equal(group.matcher, "*");
    const [handler] = group.hooks;
    assert.equal(handler.type, "command");
    assert.equal(handler.async, true);
    assert.equal(handler["omnodex-managed"], true);
    assert.match(handler.command, /OMNODEX_HOME=/);
    assert.match(handler.command, /claude-hook-shim|shim\.js/);
  }
});

test("install is idempotent", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  await interceptor.install();
  const settings = JSON.parse(
    await readFile(interceptor.settingsFilePath(), "utf8"),
  );
  // Each event should still have exactly one matcher group with one handler.
  for (const groups of Object.values(settings.hooks)) {
    assert.equal(groups.length, 1);
    assert.equal(groups[0].hooks.length, 1);
  }
});

test("uninstall leaves foreign handlers intact", async (t) => {
  const projectPath = await fresh(t);
  const settingsDir = path.join(projectPath, ".claude");
  await mkdir(settingsDir, { recursive: true });
  const settingsPath = path.join(settingsDir, "settings.local.json");
  await writeFile(
    settingsPath,
    JSON.stringify(
      {
        someUserField: "keep-me",
        hooks: {
          PreToolUse: [
            {
              matcher: "Bash",
              hooks: [
                {
                  type: "command",
                  command: "echo user hook",
                  async: true,
                },
              ],
            },
          ],
        },
      },
      null,
      2,
    ),
  );

  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  await interceptor.uninstall();

  const after = JSON.parse(await readFile(settingsPath, "utf8"));
  assert.equal(after.someUserField, "keep-me");
  // The user's own PreToolUse handler must still be there.
  assert.ok(after.hooks.PreToolUse);
  assert.equal(after.hooks.PreToolUse[0].matcher, "Bash");
  assert.equal(after.hooks.PreToolUse[0].hooks[0].command, "echo user hook");
  // No Omnodex-tagged handlers should remain anywhere.
  const flat = JSON.stringify(after);
  assert.equal(flat.includes("omnodex-managed"), false);
});
