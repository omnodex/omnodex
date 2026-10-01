// Tests for reading a Claude Code session's title from its transcript, and
// for the shim emitting session.renamed when the title changes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { readTranscriptTitle, titleFromTranscript } from "../dist/session-title.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "..", "dist", "bin", "claude-hook-shim.js");

const custom = (t) => ({ type: "custom-title", customTitle: t, sessionId: "s" });
const ai = (t) => ({ type: "ai-title", aiTitle: t, sessionId: "s" });
const turn = { type: "user", message: { role: "user", content: "hi" } };

test("no title records: no title", () => {
  assert.equal(titleFromTranscript([]), null);
  assert.equal(titleFromTranscript([turn, { type: "custom-title" }, null, "x"]), null);
});

test("several renames: the last one wins", () => {
  assert.deepEqual(titleFromTranscript([custom("one"), turn, custom("two"), turn]), { title: "two", source: "user" });
});

test("a custom title beats an AI title, wherever each appears", () => {
  assert.deepEqual(titleFromTranscript([custom("mine"), ai("Generated")]), { title: "mine", source: "user" });
});

test("an AI title is used when the user never renamed", () => {
  assert.deepEqual(titleFromTranscript([ai("First"), turn, ai("Better")]), { title: "Better", source: "auto" });
});

test("a truncated last line does not hide the title before it", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-cc-title-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "transcript.jsonl");
  await writeFile(file, [custom("kept"), turn].map((r) => JSON.stringify(r)).join("\n") + '\n{"type":"custom-title","customTi', "utf8");
  assert.deepEqual(await readTranscriptTitle(file), { title: "kept", source: "user" });
  assert.equal(await readTranscriptTitle(undefined), null);
  assert.equal(await readTranscriptTitle(path.join(dir, "missing.jsonl")), null);
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

async function renames(home, sessionId) {
  const raw = await readFile(path.join(home, "event-log", "sessions", `${sessionId}.jsonl`), "utf8").catch(() => "");
  return raw.split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((e) => e.event_type === "session.renamed");
}

test("shim: emits session.renamed once per title change", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-cc-shim-title-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  // HOME too, so nothing reaches the real ~/.omnodex.
  const env = { OMNODEX_HOME: home, HOME: home, USERPROFILE: home, OMNODEX_CAPTURE_DETECT: "0" };
  const transcript = path.join(home, "transcript.jsonl");
  await writeFile(transcript, JSON.stringify(ai("Generated name")) + "\n", "utf8");
  const prompt = { session_id: "cc-title-1", transcript_path: transcript, cwd: "/home/case/repo", hook_event_name: "UserPromptSubmit", prompt: "go" };

  assert.equal((await runShim(prompt, env)).code, 0);
  assert.deepEqual((await renames(home, "cc-title-1")).map((e) => e.title), ["Generated name"]);

  // Same title on the next turn: nothing new.
  await runShim(prompt, env);
  assert.equal((await renames(home, "cc-title-1")).length, 1);

  // /rename, then the next prompt.
  await appendFile(transcript, JSON.stringify(custom("fs015_2")) + "\n" + JSON.stringify(ai("Generated name")) + "\n");
  await runShim(prompt, env);
  const events = await renames(home, "cc-title-1");
  assert.deepEqual(events.map((e) => e.title), ["Generated name", "fs015_2"]);
  assert.equal(events[1].interceptor, "claude-code-hook");

  // Tool hooks never read the transcript.
  await appendFile(transcript, JSON.stringify(custom("later")) + "\n");
  await runShim({ ...prompt, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_use_id: "tu1" }, env);
  assert.equal((await renames(home, "cc-title-1")).length, 2);
});
