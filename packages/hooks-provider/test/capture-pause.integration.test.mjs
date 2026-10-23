// The Claude Code hook shim under a capture pause: a record pause writes
// nothing, a sync pause writes events flagged local-only. The Codex and
// Antigravity shims share the same write path.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { startPause } from "../../event-log/dist/index.js";

const SHIM = fileURLToPath(new URL("../dist/bin/claude-hook-shim.js", import.meta.url));

function runShim(payload, home) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM], {
      env: { ...process.env, OMNODEX_HOME: home, OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
}

async function readLog(home, sessionId) {
  try {
    const raw = await readFile(path.join(home, "event-log", "sessions", `${sessionId}.jsonl`), "utf8");
    return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

const READ = (session_id) => ({
  session_id,
  cwd: "/home/case/repo",
  hook_event_name: "PostToolUse",
  tool_name: "Read",
  tool_use_id: `toolu_${session_id}`,
  tool_input: { file_path: "/home/case/repo/README.md" },
  tool_response: { content: "hello" },
});

test("a record pause writes nothing for a tool call", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-pause-"));
  t.after(() => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  await startPause(home, "record", { untilMs: null });
  const res = await runShim(READ("rec-sess"), home);
  assert.equal(res.code, 0, res.stderr);
  assert.deepEqual(await readLog(home, "rec-sess"), []);
});

test("a sync pause writes the call flagged local-only", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-pause-"));
  t.after(() => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  await startPause(home, "sync", { untilMs: null });
  const res = await runShim(READ("sync-sess"), home);
  assert.equal(res.code, 0, res.stderr);
  const events = await readLog(home, "sync-sess");
  assert.ok(events.length > 0, "nothing was written");
  for (const e of events) assert.equal(e.local_only, true, `${e.event_type} was not flagged`);
});

test("an expired pause writes its end marker and the call normally", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-shim-pause-"));
  t.after(() => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const { entry } = await startPause(home, "record", { untilMs: Date.now() - 1000, now: Date.now() - 60_000 });
  const res = await runShim(READ("after-sess"), home);
  assert.equal(res.code, 0, res.stderr);
  const events = await readLog(home, "after-sess");
  assert.ok(events.length > 0);
  for (const e of events) assert.equal(e.local_only, undefined);
  const control = await readLog(home, "omnodex-capture-control");
  assert.deepEqual(control.map((m) => [m.event_type, m.pause_id, m.reason]), [["capture.resumed", entry.pause_id, "expired"]]);
});
