// Unit tests for CodexInterceptor: install/uninstall idempotency,
// preservation of existing hooks, and surgical removal.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { CodexInterceptor } from "../dist/codex-interceptor.js";

async function fresh(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-codex-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function makeInterceptor(projectPath) {
  return new CodexInterceptor({
    projectPath,
    shimPath: "/opt/omnodex/codex-shim.js",
    omnodexHome: path.join(projectPath, ".omnodex-home"),
  });
}

test("install writes the four hook events", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();

  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const hooks = JSON.parse(raw);

  for (const eventName of ["SessionStart", "PreToolUse", "PostToolUse", "Stop"]) {
    assert.ok(hooks.hooks[eventName], `expected ${eventName} group`);
    const [group] = hooks.hooks[eventName];
    assert.equal(group.matcher, "*");
    const [handler] = group.hooks;
    assert.equal(handler.type, "command");
    assert.equal(handler["omnodex-managed"], true);
    assert.match(handler.command, /OMNODEX_HOME=/);
    assert.match(handler.command, /codex-shim/);
  }
});

test("install does NOT write async:true (not in Codex spec)", async (t) => {
  const projectPath = await fresh(t);
  await makeInterceptor(projectPath).install();
  const raw = await readFile(
    path.join(projectPath, ".codex", "hooks.json"),
    "utf8",
  );
  const hooks = JSON.parse(raw);
  const handler = hooks.hooks.PreToolUse[0].hooks[0];
  assert.equal(handler.async, undefined);
});

test("install is idempotent", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  await interceptor.install();

  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const hooks = JSON.parse(raw);
  // Should have exactly one group per event, not duplicates.
  assert.equal(hooks.hooks.PreToolUse.length, 1);
  assert.equal(hooks.hooks.PreToolUse[0].hooks.length, 1);
});

test("install preserves existing non-Omnodex hooks", async (t) => {
  const projectPath = await fresh(t);
  const codexDir = path.join(projectPath, ".codex");
  await mkdir(codexDir, { recursive: true });

  const existing = {
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [{ type: "command", command: "python3 /team/policy.py" }],
        },
      ],
    },
  };
  await writeFile(
    path.join(codexDir, "hooks.json"),
    JSON.stringify(existing, null, 2),
  );

  await makeInterceptor(projectPath).install();

  const raw = await readFile(path.join(codexDir, "hooks.json"), "utf8");
  const hooks = JSON.parse(raw);
  const preToolGroups = hooks.hooks.PreToolUse;
  // Should have the original team hook group plus the Omnodex group.
  assert.equal(preToolGroups.length, 2);
  const teamGroup = preToolGroups.find(
    (g) => g.hooks[0].command === "python3 /team/policy.py",
  );
  assert.ok(teamGroup, "original team hook must be preserved");
});

test("uninstall removes only Omnodex-managed handlers", async (t) => {
  const projectPath = await fresh(t);
  const codexDir = path.join(projectPath, ".codex");
  await mkdir(codexDir, { recursive: true });

  const existing = {
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [{ type: "command", command: "python3 /team/policy.py" }],
        },
      ],
    },
  };
  await writeFile(
    path.join(codexDir, "hooks.json"),
    JSON.stringify(existing, null, 2),
  );

  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  await interceptor.uninstall();

  const raw = await readFile(path.join(codexDir, "hooks.json"), "utf8");
  const hooks = JSON.parse(raw);
  // After uninstall the original team hook is still there.
  assert.ok(hooks.hooks.PreToolUse);
  const allHandlers = hooks.hooks.PreToolUse.flatMap((g) => g.hooks);
  const omnodexHandlers = allHandlers.filter((h) => h["omnodex-managed"]);
  assert.equal(omnodexHandlers.length, 0, "no Omnodex handlers should remain");
  assert.equal(allHandlers.length, 1, "team handler must survive");
});

test("uninstall on empty file is a no-op", async (t) => {
  const projectPath = await fresh(t);
  // No .codex/hooks.json exists yet.
  await makeInterceptor(projectPath).uninstall();
  // Should not throw.
});

test("debug flag adds OMNODEX_DEBUG=1 to shim command", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new CodexInterceptor({
    projectPath,
    shimPath: "/opt/shim.js",
    omnodexHome: "/tmp/home",
    debug: true,
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const hooks = JSON.parse(raw);
  const cmd = hooks.hooks.PreToolUse[0].hooks[0].command;
  assert.match(cmd, /OMNODEX_DEBUG=1/);
});

test("hooksFilePath returns .codex/hooks.json inside projectPath", (t) => {
  const interceptor = new CodexInterceptor({
    projectPath: "/home/case/myrepo",
    shimPath: "/opt/shim.js",
    omnodexHome: "/tmp/home",
  });
  assert.equal(
    interceptor.hooksFilePath(),
    "/home/case/myrepo/.codex/hooks.json",
  );
});

test("Windows platform uses cmd.exe set syntax", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new CodexInterceptor({
    projectPath,
    shimPath: "C:\\Users\\case\\shim.js",
    omnodexHome: "C:\\Users\\case\\.omnodex",
    platform: "win32",
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const hooks = JSON.parse(raw);
  const cmd = hooks.hooks.PreToolUse[0].hooks[0].command;
  // Must use set "VAR=value" && ... syntax, not POSIX VAR=value prefix.
  assert.match(cmd, /^set "OMNODEX_HOME=/);
  assert.match(cmd, / && /);
  // Must NOT use single-quote shell quoting.
  assert.ok(!cmd.includes("'"), "Windows commands must not use single quotes");
});

test("Windows platform with debug uses chained set commands", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new CodexInterceptor({
    projectPath,
    shimPath: "C:\\Users\\case\\shim.js",
    omnodexHome: "C:\\Users\\case\\.omnodex",
    platform: "win32",
    debug: true,
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const hooks = JSON.parse(raw);
  const cmd = hooks.hooks.PreToolUse[0].hooks[0].command;
  assert.match(cmd, /set "OMNODEX_HOME=.*" && set "OMNODEX_DEBUG=1" && /);
});

test("POSIX platform uses env-prefix syntax (default on non-Windows)", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new CodexInterceptor({
    projectPath,
    shimPath: "/opt/shim.js",
    omnodexHome: "/home/case/.omnodex",
    platform: "linux",
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const hooks = JSON.parse(raw);
  const cmd = hooks.hooks.PreToolUse[0].hooks[0].command;
  assert.match(cmd, /^OMNODEX_HOME=/);
  assert.ok(!cmd.includes('set "'), "POSIX commands must not use set");
});
