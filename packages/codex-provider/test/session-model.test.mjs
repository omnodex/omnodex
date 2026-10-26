// Tests for recording the model Codex reports: session.started carries it,
// and the shim emits session.model_changed when a turn reports another.
// Payload shapes as observed from codex hooks (SessionStart, Stop, and
// PreToolUse all carry `model`).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { mapCodexPayload } from "../dist/codex-payload.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "..", "dist", "bin", "codex-hook-shim.js");

const base = (event, model, extra = {}) => ({
  session_id: "codex-model-case",
  transcript_path: null,
  cwd: "/home/case/repo",
  hook_event_name: event,
  model,
  permission_mode: "default",
  ...extra,
});

let n = 0;
const newEventId = () => `e${++n}`;

test("SessionStart carries the model onto session.started", () => {
  const [started] = mapCodexPayload(base("SessionStart", "gpt-6.1-sol", { source: "startup" }), { newEventId });
  assert.equal(started.event_type, "session.started");
  assert.equal(started.model, "gpt-6.1-sol");
});

test("no usable model, no field", () => {
  for (const model of [undefined, "", "  ", 42]) {
    const [started] = mapCodexPayload(base("SessionStart", model), { newEventId });
    assert.ok(!("model" in started), String(model));
  }
});

function runShim(home, payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM], {
      env: { ...process.env, OMNODEX_HOME: home, OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0", OMNODEX_NO_UPDATE_CHECK: "1" },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
}

async function events(home) {
  const raw = await readFile(path.join(home, "event-log", "sessions", "codex-model-case.jsonl"), "utf8").catch(() => "");
  return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

test("the shim records a model change once, at a turn boundary", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-codex-model-"));
  t.after(() => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));

  await runShim(home, base("SessionStart", "gpt-6.1-sol", { source: "startup" }));
  await runShim(home, base("UserPromptSubmit", "gpt-6.1-sol", { prompt: "x" }));
  await runShim(home, base("PreToolUse", "gpt-5.3-codex", { tool_name: "Bash", tool_use_id: "t1", tool_input: { command: "echo" } }));
  await runShim(home, base("Stop", "gpt-5.3-codex", { stop_hook_active: false }));
  await runShim(home, base("UserPromptSubmit", "gpt-5.3-codex", { prompt: "y" }));

  const all = await events(home);
  assert.equal(all.find((e) => e.event_type === "session.started").model, "gpt-6.1-sol");
  const changes = all.filter((e) => e.event_type === "session.model_changed");
  assert.equal(changes.length, 1, JSON.stringify(changes));
  assert.deepEqual(
    { model: changes[0].model, previous: changes[0].previous, source: changes[0].source, interceptor: changes[0].interceptor },
    { model: "gpt-5.3-codex", previous: "gpt-6.1-sol", source: "hook", interceptor: "codex-hook" },
  );
});
