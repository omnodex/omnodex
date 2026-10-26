// Tests for reading a Claude Code session's model from its transcript, and
// for the shim emitting session.model_changed when it changes. Transcript
// lines shaped as Claude Code writes them (the hook payloads name no model).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { modelFromTranscript } from "../dist/session-model.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "..", "dist", "bin", "claude-hook-shim.js");

const assistant = (model, extra = {}) => ({
  type: "assistant",
  isSidechain: false,
  requestedModel: model,
  message: { id: "msg", role: "assistant", model, content: [{ type: "text", text: "secret answer" }] },
  ...extra,
});
const user = { type: "user", message: { role: "user", content: "hi" } };

test("the last main-thread assistant message names the model", () => {
  assert.equal(modelFromTranscript([assistant("claude-sonnet-5-5"), user, assistant("claude-opus-5-5"), user]), "claude-opus-5-5");
});

test("subagent and synthetic messages, and records without a model, are skipped", () => {
  assert.equal(
    modelFromTranscript([assistant("claude-opus-5-5"), assistant("claude-haiku-5-5", { isSidechain: true }), assistant("<synthetic>"), { type: "assistant" }, null, "x"]),
    "claude-opus-5-5",
  );
  assert.equal(modelFromTranscript([user]), null);
});

function runShim(payload, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM], { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
    child.stdin.end(JSON.stringify(payload));
  });
}

async function sessionEvents(home, sessionId) {
  const raw = await readFile(path.join(home, "event-log", "sessions", `${sessionId}.jsonl`), "utf8").catch(() => "");
  return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
}

test("shim: one session.model_changed per change, at the next prompt, with no content", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-cc-shim-model-"));
  t.after(() => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const env = { OMNODEX_HOME: home, HOME: home, USERPROFILE: home, OMNODEX_CAPTURE_DETECT: "0", OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0", OMNODEX_NO_UPDATE_CHECK: "1" };
  const transcript = path.join(home, "transcript.jsonl");
  await writeFile(transcript, JSON.stringify(user) + "\n" + JSON.stringify(assistant("claude-sonnet-5-5")) + "\n", "utf8");
  const prompt = { session_id: "cc-model-1", transcript_path: transcript, cwd: "/home/case/repo", hook_event_name: "UserPromptSubmit", prompt: "go" };

  await runShim(prompt, env);
  await runShim(prompt, env);
  // Tool hooks never read the transcript.
  await appendFile(transcript, JSON.stringify(assistant("claude-opus-5-5")) + "\n");
  await runShim({ ...prompt, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_use_id: "tu1" }, env);
  assert.equal((await sessionEvents(home, "cc-model-1")).filter((e) => e.event_type === "session.model_changed").length, 1);
  await runShim(prompt, env);

  const all = await sessionEvents(home, "cc-model-1");
  const changes = all.filter((e) => e.event_type === "session.model_changed");
  assert.deepEqual(changes.map((e) => `${e.previous ?? "-"}>${e.model}:${e.source}`), ["->claude-sonnet-5-5:transcript", "claude-sonnet-5-5>claude-opus-5-5:transcript"]);
  assert.doesNotMatch(JSON.stringify(changes), /secret answer/);
});
