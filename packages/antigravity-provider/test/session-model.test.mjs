// Tests for recording the model Antigravity reports: session.started carries
// modelName, and the shim emits session.model_changed when a later turn
// (PreInvocation) reports another, as a resumed conversation does. Payload
// shapes as observed from agy hooks.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { mapAntigravityPayload } from "../dist/antigravity-payload.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "..", "dist", "bin", "antigravity-hook-shim.js");
const CONVERSATION = "f9dca166-0000-4000-8000-00000000case";

const invocation = (modelName, invocationNum) => ({
  artifactDirectoryPath: "/home/case/.gemini/antigravity-cli/brain/x",
  conversationId: CONVERSATION,
  initialNumSteps: 0,
  invocationNum,
  lastUserInput: "Reply with ok.",
  modelName,
  transcriptPath: "/home/case/.gemini/antigravity-cli/brain/x/transcript.jsonl",
  workspacePaths: ["/home/case/repo"],
});

let n = 0;
const newEventId = () => `e${++n}`;

test("the first invocation carries modelName onto session.started", () => {
  const [started] = mapAntigravityPayload("PreInvocation", invocation("gemini-3.8-flash-low", 0), { newEventId });
  assert.equal(started.event_type, "session.started");
  assert.equal(started.model, "gemini-3.8-flash-low");
  const [none] = mapAntigravityPayload("PreInvocation", invocation(undefined, 0), { newEventId });
  assert.ok(!("model" in none));
});

function runShim(home, eventName, payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SHIM, eventName], {
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

test("the shim records a model change on a later turn of the same conversation", async (t) => {
  const home = await mkdtemp(path.join(os.tmpdir(), "omnodex-agy-model-"));
  t.after(() => rm(home, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));

  await runShim(home, "PreInvocation", invocation("gemini-3.8-flash-low", 0));
  await runShim(home, "Stop", { ...invocation("gemini-3.8-flash-low", 0), executionNum: 0, fullyIdle: true, terminationReason: "completed", error: "" });
  await runShim(home, "PreInvocation", invocation("gemini-3.8-flash-medium", 1));
  await runShim(home, "PreInvocation", invocation("gemini-3.8-flash-medium", 2));

  const raw = await readFile(path.join(home, "event-log", "sessions", `${CONVERSATION}.jsonl`), "utf8");
  const all = raw.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  assert.equal(all.find((e) => e.event_type === "session.started").model, "gemini-3.8-flash-low");
  const changes = all.filter((e) => e.event_type === "session.model_changed");
  assert.equal(changes.length, 1, JSON.stringify(changes));
  assert.equal(changes[0].model, "gemini-3.8-flash-medium");
  assert.equal(changes[0].previous, "gemini-3.8-flash-low");
  assert.equal(changes[0].platform, "antigravity");
});
