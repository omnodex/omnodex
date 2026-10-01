// Tests for reading a Codex thread's name from Codex's session index, and
// for the shim emitting session.renamed when the name changes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { appendFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { codexHome, titleFromSessionIndex } from "../dist/session-title.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "..", "dist", "bin", "codex-hook-shim.js");

const entry = (id, name) => ({ id, thread_name: name, updated_at: "2026-10-01T12:00:00Z" });

test("no entry for the session: no title", () => {
  assert.equal(titleFromSessionIndex([], "a"), null);
  assert.equal(titleFromSessionIndex([entry("b", "Other thread"), { id: "a" }, null], "a"), null);
});

test("several names: the last one for the session wins", () => {
  const records = [entry("a", "First"), entry("b", "Other"), entry("a", "Renamed"), entry("b", "Later other")];
  assert.deepEqual(titleFromSessionIndex(records, "a"), { title: "Renamed", source: "user" });
});

test("codexHome: CODEX_HOME, then the transcript's tree, then ~/.codex", () => {
  assert.equal(codexHome("/x/.codex/sessions/2026/10/01/rollout-1.jsonl", { CODEX_HOME: "/custom" }, "/home/case"), "/custom");
  assert.equal(codexHome("/home/case/.codex/sessions/2026/10/01/rollout-1.jsonl", {}, "/home/case"), "/home/case/.codex");
  assert.equal(codexHome("C:\\Users\\case\\.codex\\sessions\\2026\\10\\01\\rollout-1.jsonl", {}, "/home/case"), "C:\\Users\\case\\.codex");
  assert.equal(codexHome(null, {}, "/home/case"), path.join("/home/case", ".codex"));
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

test("shim: emits session.renamed when the thread is named and renamed", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-codex-shim-title-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  const codex = path.join(home, ".codex");
  const env = { OMNODEX_HOME: home, HOME: home, USERPROFILE: home, CODEX_HOME: codex, OMNODEX_CAPTURE_DETECT: "0" };
  const index = path.join(codex, "session_index.jsonl");
  const stop = { session_id: "codex-title-1", cwd: "/home/case/repo", hook_event_name: "Stop" };

  // No index yet: nothing to record.
  assert.equal((await runShim(stop, env)).code, 0);
  assert.equal((await renames(home, "codex-title-1")).length, 0);

  // Codex names the thread after its first turn.
  await mkdir(codex, { recursive: true });
  await writeFile(index, JSON.stringify(entry("codex-title-1", "Fix the build")) + "\n", "utf8");
  await runShim(stop, env);
  await runShim(stop, env);
  await appendFile(index, JSON.stringify(entry("someone-else", "Other")) + "\n" + JSON.stringify(entry("codex-title-1", "Ship it")) + "\n");
  await runShim({ ...stop, hook_event_name: "UserPromptSubmit", prompt: "go" }, env);

  const events = await renames(home, "codex-title-1");
  assert.deepEqual(events.map((e) => e.title), ["Fix the build", "Ship it"]);
  assert.equal(events[0].interceptor, "codex-hook");
});
