// Unit tests for AntigravityInterceptor: install/uninstall idempotency,
// named-hook format, and surgical removal.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { AntigravityInterceptor } from "../dist/antigravity-interceptor.js";

async function fresh(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-antigravity-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function makeInterceptor(projectPath) {
  return new AntigravityInterceptor({
    projectPath,
    shimPath: "/opt/omnodex/antigravity-shim.js",
    omnodexHome: path.join(projectPath, ".omnodex-home"),
  });
}

test("install writes named hook with three events", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();

  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const file = JSON.parse(raw);

  // Top-level key is "omnodex", not "hooks".
  assert.ok(file.omnodex, 'expected "omnodex" named hook');
  assert.ok(!file.hooks, 'should not have a "hooks" wrapper');

  // PreToolUse and PostToolUse use matcher groups.
  for (const eventName of ["PreToolUse", "PostToolUse"]) {
    const groups = file.omnodex[eventName];
    assert.ok(groups, `expected ${eventName} array`);
    assert.equal(groups.length, 1);
    const [group] = groups;
    assert.equal(group.matcher, "*");
    assert.equal(group.hooks.length, 1);
    const [handler] = group.hooks;
    assert.equal(handler.type, "command");
    assert.match(handler.command, /OMNODEX_HOME=/);
    assert.match(handler.command, /antigravity-shim/);
    assert.match(handler.command, new RegExp(eventName));
  }

  // Stop uses a flat handler list (no matcher groups).
  const stopHandlers = file.omnodex.Stop;
  assert.ok(stopHandlers, "expected Stop array");
  assert.equal(stopHandlers.length, 1);
  assert.equal(stopHandlers[0].type, "command");
  assert.match(stopHandlers[0].command, /Stop/);
});

test("install does not include SessionStart", async (t) => {
  const projectPath = await fresh(t);
  await makeInterceptor(projectPath).install();

  const raw = await readFile(
    makeInterceptor(projectPath).hooksFilePath(),
    "utf8",
  );
  const file = JSON.parse(raw);
  assert.ok(!file.omnodex.SessionStart, "SessionStart should not be present");
});

test("install is idempotent", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  await interceptor.install();

  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const file = JSON.parse(raw);
  // Should have exactly one matcher group per tool event.
  assert.equal(file.omnodex.PreToolUse.length, 1);
  assert.equal(file.omnodex.PreToolUse[0].hooks.length, 1);
});

test("install preserves other named hooks", async (t) => {
  const projectPath = await fresh(t);
  const agentsDir = path.join(projectPath, ".agents");
  await mkdir(agentsDir, { recursive: true });

  const existing = {
    "team-linter": {
      PreToolUse: [
        {
          matcher: "run_command",
          hooks: [{ type: "command", command: "python3 /team/policy.py" }],
        },
      ],
    },
  };
  await writeFile(
    path.join(agentsDir, "hooks.json"),
    JSON.stringify(existing, null, 2),
  );

  await makeInterceptor(projectPath).install();

  const raw = await readFile(path.join(agentsDir, "hooks.json"), "utf8");
  const file = JSON.parse(raw);
  // Team hook must still be there.
  assert.ok(file["team-linter"], "team-linter hook must be preserved");
  assert.ok(file.omnodex, "omnodex hook must be added");
});

test("uninstall removes only the omnodex named hook", async (t) => {
  const projectPath = await fresh(t);
  const agentsDir = path.join(projectPath, ".agents");
  await mkdir(agentsDir, { recursive: true });

  const existing = {
    "team-linter": {
      PreToolUse: [
        {
          matcher: "run_command",
          hooks: [{ type: "command", command: "python3 /team/policy.py" }],
        },
      ],
    },
  };
  await writeFile(
    path.join(agentsDir, "hooks.json"),
    JSON.stringify(existing, null, 2),
  );

  const interceptor = makeInterceptor(projectPath);
  await interceptor.install();
  await interceptor.uninstall();

  const raw = await readFile(path.join(agentsDir, "hooks.json"), "utf8");
  const file = JSON.parse(raw);
  assert.ok(!file.omnodex, "omnodex hook must be removed");
  assert.ok(file["team-linter"], "team-linter hook must survive");
});

test("uninstall on empty file is a no-op", async (t) => {
  const projectPath = await fresh(t);
  await makeInterceptor(projectPath).uninstall();
  // Should not throw.
});

test("debug flag adds OMNODEX_DEBUG=1 to shim command", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new AntigravityInterceptor({
    projectPath,
    shimPath: "/opt/shim.js",
    omnodexHome: "/tmp/home",
    debug: true,
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const file = JSON.parse(raw);
  const cmd = file.omnodex.PreToolUse[0].hooks[0].command;
  assert.match(cmd, /OMNODEX_DEBUG=1/);
});

test("shim command includes event name as argument", async (t) => {
  const projectPath = await fresh(t);
  await makeInterceptor(projectPath).install();
  const raw = await readFile(
    makeInterceptor(projectPath).hooksFilePath(),
    "utf8",
  );
  const file = JSON.parse(raw);

  const preCmd = file.omnodex.PreToolUse[0].hooks[0].command;
  assert.match(preCmd, /PreToolUse$/);

  const postCmd = file.omnodex.PostToolUse[0].hooks[0].command;
  assert.match(postCmd, /PostToolUse$/);

  const stopCmd = file.omnodex.Stop[0].command;
  assert.match(stopCmd, /Stop$/);
});

test("hooksFilePath returns .agents/hooks.json inside projectPath", (t) => {
  const interceptor = new AntigravityInterceptor({
    projectPath: "/home/case/myrepo",
    shimPath: "/opt/shim.js",
    omnodexHome: "/tmp/home",
  });
  assert.equal(
    interceptor.hooksFilePath(),
    "/home/case/myrepo/.agents/hooks.json",
  );
});

test("kind is antigravity-hook", (t) => {
  const interceptor = new AntigravityInterceptor({
    projectPath: "/tmp",
    shimPath: "/opt/shim.js",
    omnodexHome: "/tmp/home",
  });
  assert.equal(interceptor.kind, "antigravity-hook");
  assert.equal(interceptor.name, "antigravity-hooks");
});

test("Windows platform uses cmd.exe set syntax", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new AntigravityInterceptor({
    projectPath,
    shimPath: "C:\\Users\\case\\shim.js",
    omnodexHome: "C:\\Users\\case\\.omnodex",
    platform: "win32",
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const file = JSON.parse(raw);
  const cmd = file.omnodex.PreToolUse[0].hooks[0].command;
  // Must use set "VAR=value" && ... syntax, not POSIX VAR=value prefix.
  assert.match(cmd, /^set "OMNODEX_HOME=/);
  assert.match(cmd, / && /);
  // Must NOT use single-quote shell quoting.
  assert.ok(!cmd.includes("'"), "Windows commands must not use single quotes");
  // Event name still appended.
  assert.match(cmd, /PreToolUse$/);
});

test("Windows platform with debug uses chained set commands", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new AntigravityInterceptor({
    projectPath,
    shimPath: "C:\\Users\\case\\shim.js",
    omnodexHome: "C:\\Users\\case\\.omnodex",
    platform: "win32",
    debug: true,
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const file = JSON.parse(raw);
  const cmd = file.omnodex.PreToolUse[0].hooks[0].command;
  assert.match(cmd, /set "OMNODEX_HOME=.*" && set "OMNODEX_DEBUG=1" && /);
});

test("POSIX platform uses env-prefix syntax (default)", async (t) => {
  const projectPath = await fresh(t);
  const interceptor = new AntigravityInterceptor({
    projectPath,
    shimPath: "/opt/shim.js",
    omnodexHome: "/home/case/.omnodex",
    platform: "linux",
  });
  await interceptor.install();
  const raw = await readFile(interceptor.hooksFilePath(), "utf8");
  const file = JSON.parse(raw);
  const cmd = file.omnodex.PreToolUse[0].hooks[0].command;
  assert.match(cmd, /^OMNODEX_HOME=/);
  assert.ok(!cmd.includes('set "'), "POSIX commands must not use set");
});
