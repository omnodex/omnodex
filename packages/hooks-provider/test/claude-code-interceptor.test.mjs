// Unit tests for the ClaudeCodeInterceptor. Verifies install/uninstall
// is idempotent, preserves unknown settings fields, and leaves non
// Omnodex hook handlers alone.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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

test("homeRelativeShimPath writes a host-neutral command with no env prefix", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath: "/home/case/.omnodex/bin/claude-hook-launcher.js",
    omnodexHome: "/home/case/.omnodex",
    homeRelativeShimPath: ".omnodex/bin/claude-hook-launcher.js",
    debug: true,
  });
  await interceptor.install();
  const settings = JSON.parse(
    await readFile(interceptor.settingsFilePath(), "utf8"),
  );
  for (const groups of Object.values(settings.hooks)) {
    assert.equal(
      groups[0].hooks[0].command,
      'node "$HOME/.omnodex/bin/claude-hook-launcher.js"',
    );
  }
});

test("host-neutral command resolves the launcher under the running shell's HOME", { skip: process.platform === "win32" }, async (t) => {
  const home = await fresh(t);
  const binDir = path.join(home, ".omnodex", "bin");
  await mkdir(binDir, { recursive: true });
  const marker = path.join(home, "ran");
  await writeFile(
    path.join(binDir, "claude-hook-launcher.js"),
    `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ok");\n`,
  );

  const projectPath = await fresh(t);
  const interceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath: path.join(binDir, "claude-hook-launcher.js"),
    omnodexHome: path.join(home, ".omnodex"),
    homeRelativeShimPath: ".omnodex/bin/claude-hook-launcher.js",
  });
  await interceptor.install();
  const settings = JSON.parse(
    await readFile(interceptor.settingsFilePath(), "utf8"),
  );
  const command = settings.hooks.PreToolUse[0].hooks[0].command;

  const result = spawnSync("sh", ["-c", command], {
    env: { ...process.env, HOME: home },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(await readFile(marker, "utf8"), "ok");
});

// Claude Code drops keys it does not know when it rewrites a settings file,
// so installed handlers can lose the omnodex-managed tag. Detection must
// still find them by their command, and must not claim foreign hooks.

async function writeHandlers(projectPath, handlers) {
  const settingsDir = path.join(projectPath, ".claude");
  await mkdir(settingsDir, { recursive: true });
  const settingsPath = path.join(settingsDir, "settings.local.json");
  const hooks = {};
  for (const [eventName, handler] of handlers) {
    hooks[eventName] = [{ matcher: "*", hooks: [handler] }];
  }
  await writeFile(settingsPath, JSON.stringify({ hooks }, null, 2));
  return settingsPath;
}

function untagged(command) {
  // Key order as Claude Code writes it back, with the tag gone.
  return { type: "command", command, timeout: 30, async: true };
}

const MUST_FIRE = [
  ["launcher command", 'node "$HOME/.omnodex/bin/claude-hook-launcher.js"'],
  ["Windows launcher path", 'node "C:\\Users\\case\\.omnodex\\bin\\claude-hook-launcher.js"'],
  [
    "legacy shim command",
    "OMNODEX_HOME=/home/case/.omnodex /usr/bin/node /home/case/omnodex/packages/hooks-provider/dist/bin/claude-hook-shim.js",
  ],
  ["legacy shim command, quoted", "OMNODEX_HOME='/home/case/my dir' node '/home/case/my dir/claude-hook-shim.js'"],
];

const MUST_NOT_FIRE = [
  ["user echo hook", "echo user hook"],
  ["similar file name", 'node "$HOME/bin/my-claude-hook-launcher.js"'],
  ["launcher name as a prefix", 'node "$HOME/.omnodex/bin/claude-hook-launcher.js.bak"'],
  ["other platform's launcher", 'node "$HOME/.omnodex/bin/codex-hook-launcher.js"'],
];

for (const [label, command] of MUST_FIRE) {
  test(`MUST_FIRE: isInstalled finds an untagged handler (${label})`, async (t) => {
    const projectPath = await fresh(t);
    await writeHandlers(projectPath, [
      ["PreToolUse", untagged(command)],
    ]);
    assert.equal(await makeInterceptor(projectPath).isInstalled(), true);
  });
}

test("MUST_FIRE: isInstalled finds its own command with the tag stripped", async (t) => {
  // A custom shim path matches neither file name; the exact command does.
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  const settingsPath = interceptor.settingsFilePath();
  const settings = JSON.parse(await readFile(settingsPath, "utf8"));
  for (const groups of Object.values(settings.hooks)) {
    for (const handler of groups[0].hooks) delete handler["omnodex-managed"];
  }
  await writeFile(settingsPath, JSON.stringify(settings, null, 2));
  assert.equal(await interceptor.isInstalled(), true);
});

for (const [label, command] of MUST_NOT_FIRE) {
  test(`MUST_NOT_FIRE: isInstalled ignores a foreign handler (${label})`, async (t) => {
    const projectPath = await fresh(t);
    const settingsPath = await writeHandlers(projectPath, [
      ["PreToolUse", untagged(command)],
    ]);
    const interceptor = makeInterceptor(projectPath);
    assert.equal(await interceptor.isInstalled(), false);

    // Install and uninstall leave the foreign handler alone too.
    await interceptor.install();
    await interceptor.uninstall();
    const after = JSON.parse(await readFile(settingsPath, "utf8"));
    assert.deepEqual(after.hooks.PreToolUse, [
      { matcher: "*", hooks: [untagged(command)] },
    ]);
  });
}

test("install replaces untagged Omnodex handlers instead of duplicating them", async (t) => {
  const projectPath = await fresh(t);
  const launcher = 'node "$HOME/.omnodex/bin/claude-hook-launcher.js"';
  await writeHandlers(projectPath, [
    ["PreToolUse", untagged(launcher)],
    ["SessionStart", untagged(launcher)],
  ]);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  const settings = JSON.parse(await readFile(interceptor.settingsFilePath(), "utf8"));
  for (const groups of Object.values(settings.hooks)) {
    assert.equal(groups.length, 1);
    assert.equal(groups[0].hooks.length, 1);
    assert.equal(groups[0].hooks[0]["omnodex-managed"], true);
  }
});

test("uninstall removes untagged Omnodex handlers and keeps foreign ones", async (t) => {
  const projectPath = await fresh(t);
  const settingsPath = await writeHandlers(projectPath, [
    ["PreToolUse", untagged('node "$HOME/.omnodex/bin/claude-hook-launcher.js"')],
    ["PostToolUse", untagged("echo user hook")],
  ]);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.uninstall();
  const after = JSON.parse(await readFile(settingsPath, "utf8"));
  assert.equal(after.hooks.PreToolUse, undefined);
  assert.equal(after.hooks.PostToolUse[0].hooks[0].command, "echo user hook");
  assert.equal(await interceptor.isInstalled(), false);
});
