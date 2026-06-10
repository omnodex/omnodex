// Integration tests for codex-hook-shim: spawn the shim as a subprocess
// (exactly as Codex would), feed it a payload on stdin, and assert the
// event log is written correctly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, readdir, readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/codex-hook-shim.js");

async function fresh(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-codex-shim-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function runShim(home, payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM], {
      env: { ...process.env, OMNODEX_HOME: home },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
    child.on("close", (code) => resolve({ code, stderr }));
    child.on("error", reject);
  });
}

async function readEvents(home) {
  // EventLog writes events to event-log/sessions/<session_id>.jsonl;
  // event-log/index.jsonl is a session registry, not event data.
  const sessionsDir = path.join(home, "event-log", "sessions");
  let entries;
  try {
    entries = await readdir(sessionsDir);
  } catch {
    return [];
  }
  const events = [];
  for (const entry of entries.sort()) {
    if (!entry.endsWith(".jsonl")) continue;
    const raw = await readFile(path.join(sessionsDir, entry), "utf8");
    for (const line of raw.split("\n").filter(Boolean)) {
      events.push(JSON.parse(line));
    }
  }
  return events;
}

test("shim writes session.started for SessionStart payload", async (t) => {
  const home = await fresh(t);
  const { code } = await runShim(home, {
    session_id: "s-shim-1",
    cwd: "/repo",
    hook_event_name: "SessionStart",
    source: "startup",
  });
  assert.equal(code, 0);
  const events = await readEvents(home);
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, "session.started");
  assert.equal(events[0].session_id, "s-shim-1");
  assert.equal(events[0].interceptor, "codex-hook");
});

test("shim writes tool.invoked for PreToolUse payload", async (t) => {
  const home = await fresh(t);
  const { code } = await runShim(home, {
    session_id: "s-shim-2",
    cwd: "/repo",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_use_id: "tu-shim-1",
    tool_input: { command: "ls -la" },
  });
  assert.equal(code, 0);
  const events = await readEvents(home);
  assert.equal(events.length, 1);
  const [ev] = events;
  assert.equal(ev.event_type, "tool.invoked");
  assert.equal(ev.tool_name, "Bash");
  assert.equal(ev.tool_call_id, "tu-shim-1");
  assert.deepEqual(ev.parameters, { command: "ls -la" });
});

test("shim computes duration_ms from wall-clock timing on PostToolUse", async (t) => {
  const home = await fresh(t);

  // First, fire PreToolUse to save the timing file.
  await runShim(home, {
    session_id: "s-shim-3",
    cwd: "/repo",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_use_id: "tu-shim-2",
    tool_input: { command: "sleep 0" },
  });

  // Then fire PostToolUse; the shim should compute duration_ms > 0.
  await runShim(home, {
    session_id: "s-shim-3",
    cwd: "/repo",
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_use_id: "tu-shim-2",
    tool_input: { command: "sleep 0" },
    tool_response: { output: "" },
  });

  const events = await readEvents(home);
  const completed = events.find((e) => e.event_type === "tool.completed");
  assert.ok(completed, "expected tool.completed event");
  assert.ok(
    typeof completed.duration_ms === "number" && completed.duration_ms >= 0,
    `expected non-negative duration_ms, got ${completed.duration_ms}`,
  );
});

test("shim writes session.ended for Stop payload", async (t) => {
  const home = await fresh(t);
  await runShim(home, {
    session_id: "s-shim-4",
    cwd: "/repo",
    hook_event_name: "Stop",
    stop_hook_active: false,
    last_assistant_message: "All done.",
  });
  const events = await readEvents(home);
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, "session.ended");
  assert.equal(events[0].status, "completed");
});

test("shim exits 0 and writes nothing for UserPromptSubmit", async (t) => {
  const home = await fresh(t);
  const { code } = await runShim(home, {
    session_id: "s-shim-5",
    cwd: "/repo",
    hook_event_name: "UserPromptSubmit",
    turn_id: "turn-1",
    prompt: "help me refactor this",
  });
  assert.equal(code, 0);
  const events = await readEvents(home);
  assert.equal(events.length, 0);
});

test("shim exits 0 on empty stdin without crashing", async (t) => {
  const home = await fresh(t);
  const child = await new Promise((resolve, reject) => {
    const c = spawn(process.execPath, [SHIM], {
      env: { ...process.env, OMNODEX_HOME: home },
      stdio: ["pipe", "pipe", "pipe"],
    });
    c.stdin.end();
    c.on("close", (code) => resolve({ code }));
    c.on("error", reject);
  });
  assert.equal(child.code, 0);
});

test("shim exits 0 on malformed JSON without crashing", async (t) => {
  const home = await fresh(t);
  const child = await new Promise((resolve, reject) => {
    const c = spawn(process.execPath, [SHIM], {
      env: { ...process.env, OMNODEX_HOME: home },
      stdio: ["pipe", "pipe", "pipe"],
    });
    c.stdin.write("not json at all");
    c.stdin.end();
    c.on("close", (code) => resolve({ code }));
    c.on("error", reject);
  });
  assert.equal(child.code, 0);
});
