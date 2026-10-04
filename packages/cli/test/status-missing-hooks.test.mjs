// `omnodex status` names the Claude Code hooks an older install lacks, so
// an upgrade that adds hook events says how to pick them up.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const HANDLER = { type: "command", command: 'node "$HOME/.omnodex/bin/claude-hook-launcher.js"', timeout: 30, async: true };

async function project(t, events) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-status-hooks-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  const projectPath = path.join(home, "repo");
  await fs.mkdir(path.join(projectPath, ".claude"), { recursive: true });
  const hooks = Object.fromEntries(events.map((name) => [name, [{ matcher: "*", hooks: [HANDLER] }]]));
  await fs.writeFile(path.join(projectPath, ".claude", "settings.local.json"), JSON.stringify({ hooks }, null, 2));
  return { home, projectPath };
}

function status({ home, projectPath }) {
  return spawnSync(process.execPath, [CLI, "status", projectPath], {
    cwd: projectPath,
    env: { ...process.env, HOME: home, USERPROFILE: home, OMNODEX_HOME: path.join(home, ".omnodex") },
    encoding: "utf8",
    timeout: 60_000,
  });
}

const OLDER = ["SessionStart", "SessionEnd", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SubagentStart", "SubagentStop", "UserPromptSubmit"];

test("status names the hooks an older Claude Code install lacks", async (t) => {
  const result = status(await project(t, OLDER));
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Claude Code \(settings\.local\.json\): installed/);
  assert.match(result.stdout, /missing hooks: PermissionRequest, PermissionDenied/);
  assert.match(result.stdout, /omnodex install claude-code` in this project/);
});

test("status says nothing about missing hooks for a current install", async (t) => {
  const result = status(await project(t, [...OLDER, "PermissionRequest", "PermissionDenied"]));
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout, /missing hooks/);
});
