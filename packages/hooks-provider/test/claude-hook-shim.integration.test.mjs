// Integration test for the Claude Code hook shim subprocess.
//
// Spawns the compiled shim at dist/bin/claude-hook-shim.js with a
// canonical Claude Code payload piped to stdin, then asserts the event
// log on disk contains the expected records.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
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
      user: "case",
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
  assert.equal(events[0].user, "case");

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

test("shim computes duration_ms from PreToolUse/PostToolUse wall-clock delta when payload omits it", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-dur-"));
  try {
    const session_id = "sess-duration-test";
    const env = { OMNODEX_HOME: home };

    // PreToolUse -- no duration_ms in payload (normal Claude Code behaviour)
    await runShim(
      {
        session_id,
        cwd: "/tmp/repo",
        hook_event_name: "PreToolUse",
        tool_name: "Bash",
        tool_use_id: "tu-dur-1",
        tool_input: { command: "echo hello" },
      },
      env,
    );

    // Small artificial delay so the delta is measurable
    await new Promise((r) => setTimeout(r, 20));

    // PostToolUse -- no duration_ms either
    await runShim(
      {
        session_id,
        cwd: "/tmp/repo",
        hook_event_name: "PostToolUse",
        tool_name: "Bash",
        tool_use_id: "tu-dur-1",
        tool_input: { command: "echo hello" },
        tool_response: "hello\n",
        // intentionally omit duration_ms
      },
      env,
    );

    const events = await readSessionLog(home, session_id);
    const completed = events.find((e) => e.event_type === "tool.completed");
    assert.ok(completed, "expected a tool.completed event");
    assert.ok(
      completed.duration_ms > 0,
      `duration_ms should be > 0 (got ${completed.duration_ms})`,
    );
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test("SessionEnd starts a detached sync that pushes a blob without delaying the hook", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-sync-"));
  const pushes = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      pushes.push({ method: req.method, url: req.url });
      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ blob_id: "blob_case_shim", received_at: new Date().toISOString(), payload_bytes: 1 }));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await rm(home, { recursive: true, force: true });
  });

  const apiUrl = `http://127.0.0.1:${server.address().port}`;
  // live_streaming is left out so the per-event push stays off and only the
  // background sync talks to the server.
  await writeFile(path.join(home, "stream-config.json"), JSON.stringify({
    api_token: "omx_test_case", passphrase: "case-passphrase", api_url: apiUrl,
  }));
  await writeFile(path.join(home, "license-cache.json"), JSON.stringify({
    response: { customer_id: "cust_case", tier: "hosted", features: ["encrypted_sync"] },
    fetched_at: Date.now(),
  }));

  const env = { OMNODEX_HOME: home, OMNODEX_AUTO_SYNC: "" };
  const session_id = "integration-sess-sync";
  await runShim({ session_id, cwd: "/tmp/repo", hook_event_name: "SessionStart", user: "case" }, env);
  assert.equal(pushes.length, 0, "only a session end starts a sync");

  const started = Date.now();
  const res = await runShim({ session_id, hook_event_name: "SessionEnd", reason: "completed" }, env);
  assert.equal(res.code, 0, `SessionEnd stderr: ${res.stderr}`);
  assert.equal(res.stdout, "");
  // The hook returns before the sync (Argon2id alone takes longer than this).
  assert.ok(Date.now() - started < 2000, "hook must not wait for the sync");

  const deadline = Date.now() + 20_000;
  let state = {};
  while (Date.now() < deadline) {
    try {
      state = JSON.parse(await readFile(path.join(home, "auto-sync-state.json"), "utf8"));
    } catch {
      state = {};
    }
    if (state.last_success_at || state.last_error) break;
    await new Promise((r) => setTimeout(r, 100));
  }

  assert.equal(state.last_error ?? null, null, `sync error: ${state.last_error}`);
  assert.equal(state.last_blob_id, "blob_case_shim");
  assert.deepEqual(pushes, [{ method: "PUT", url: "/api/v1/sync/push" }]);
});
