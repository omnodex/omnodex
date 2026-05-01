// Integration test for the Claude Code hook shim subprocess.
//
// Spawns the compiled shim at dist/bin/claude-hook-shim.js with a
// canonical Claude Code payload piped to stdin, then asserts the event
// log on disk contains the expected records.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(
  __dirname,
  "..",
  "dist",
  "bin",
  "claude-hook-shim.js",
);

async function runShim(payload, env) {
  return await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    child.stdout.on("data", (c) => stdoutChunks.push(c));
    child.stderr.on("data", (c) => stderrChunks.push(c));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

async function readSessionLog(home, sessionId) {
  const file = path.join(
    home,
    "event-log",
    "sessions",
    `${sessionId}.jsonl`,
  );
  const raw = await readFile(file, "utf8");
  return raw
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line));
}

test("shim writes SessionStart and PostToolUse events to the event log", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-"));
  t.after(() => rm(home, { recursive: true, force: true }));

  const env = { OMNODEX_HOME: home, OMNODEX_DEBUG: "1" };
  const session_id = "integration-sess-1";

  // Fire SessionStart
  let res = await runShim(
    {
      session_id,
      cwd: "/tmp/repo",
      hook_event_name: "SessionStart",
      user: "brian",
      mcp_servers: ["filesystem"],
    },
    env,
  );
  assert.equal(res.code, 0, `SessionStart stderr: ${res.stderr}`);
  assert.equal(res.stdout, "", "shim must write nothing to stdout");

  // Fire PostToolUse for a Read
  res = await runShim(
    {
      session_id,
      cwd: "/tmp/repo",
      hook_event_name: "PostToolUse",
      tool_name: "Read",
      tool_use_id: "tu-1",
      tool_input: { file_path: "/etc/hosts" },
      tool_response: "127.0.0.1 localhost\n",
      duration_ms: 11,
    },
    env,
  );
  assert.equal(res.code, 0, `PostToolUse stderr: ${res.stderr}`);

  // Fire SessionEnd
  res = await runShim(
    {
      session_id,
      hook_event_name: "SessionEnd",
      reason: "completed",
      duration_ms: 100,
    },
    env,
  );
  assert.equal(res.code, 0, `SessionEnd stderr: ${res.stderr}`);

  const events = await readSessionLog(home, session_id);
  // SessionStart(1) + PostToolUse (completed + file.read = 2) + SessionEnd(1)
  assert.equal(events.length, 4, `got ${events.length} events`);

  assert.equal(events[0].event_type, "session.started");
  assert.equal(events[0].interceptor, "claude-code-hook");
  assert.equal(events[0].user, "brian");

  assert.equal(events[1].event_type, "tool.completed");
  assert.equal(events[1].tool_call_id, "tu-1");
  assert.equal(events[1].status, "success");

  assert.equal(events[2].event_type, "file.read");
  assert.equal(events[2].path, "/etc/hosts");

  assert.equal(events[3].event_type, "session.ended");
  assert.equal(events[3].status, "completed");
});

test("shim exits 0 and stays silent on malformed stdin", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-bad-"));
  try {
    const res = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [SHIM], {
        env: { ...process.env, OMNODEX_HOME: home },
        stdio: ["pipe", "pipe", "pipe"],
      });
      const stdoutChunks = [];
      const stderrChunks = [];
      child.stdout.on("data", (c) => stdoutChunks.push(c));
      child.stderr.on("data", (c) => stderrChunks.push(c));
      child.on("error", reject);
      child.on("close", (code) =>
        resolve({
          code,
          stdout: Buffer.concat(stdoutChunks).toString("utf8"),
          stderr: Buffer.concat(stderrChunks).toString("utf8"),
        }),
      );
      child.stdin.end("this is not json");
    });
    assert.equal(res.code, 0, "malformed input must not block Claude");
    assert.equal(res.stdout, "");
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
