import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFile, mkdir, rm, readFile, rename } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { AntigravityInterceptor } from "../dist/antigravity-interceptor.js";
import { scratch, runShim, loggedEvents, pushedEvents } from "../../analyzer/test/helpers/shim-harness.mjs";
import { Projector, InMemoryReadModelStore } from "../../projection/dist/index.js";

const shim = fileURLToPath(new URL("../dist/bin/antigravity-hook-shim.js", import.meta.url));
const common = {
  conversationId: "case-conversation", workspacePaths: ["/home/case/repo"],
  transcriptPath: "/home/case/transcript.jsonl", artifactDirectoryPath: "/home/case/artifacts",
  modelName: "case-model",
};

test("separate hook processes capture one multi-invocation execution and wait for background work", async (t) => {
  const s = await scratch(t);
  async function send(event, fields = {}) {
    const result = await runShim(shim, s, { ...common, ...fields }, { args: [event] });
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), event === "Stop" ? { decision: "allow" } : {});
  }
  for (let invocationNum = 0; invocationNum < 3; invocationNum++) {
    const fields = { invocationNum, initialNumSteps: invocationNum * 2 };
    await send("PreInvocation", fields);
    await send("PostInvocation", fields);
    await send("PostToolUse", { stepIdx: invocationNum, toolCall: {
      name: "view_file", args: { AbsolutePath: "/home/case/example.txt" },
    } });
  }
  await send("Stop", { executionNum: 1, terminationReason: "model_stop", fullyIdle: false });
  assert.equal((await loggedEvents(s.home)).filter(e => e.event_type === "session.ended").length, 0);
  await send("Stop", { executionNum: 1, terminationReason: "model_stop", fullyIdle: true });
  await send("Stop", { executionNum: 1, terminationReason: "model_stop", fullyIdle: true });
  const events = await loggedEvents(s.home);
  assert.equal(events.filter(e => e.event_type === "session.started").length, 1);
  assert.equal(events.filter(e => e.event_type === "session.ended").length, 1);
  assert.equal(events.filter(e => e.event_type === "tool.invoked").length, 3);
  assert.equal(events.filter(e => e.event_type === "tool.completed").length, 3);
  assert.ok(events.at(-1).duration_ms > 0);
  assert.deepEqual((await pushedEvents(s.pushLog)).map(e => e.event_id), events.map(e => e.event_id));
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  await projector.replay(events);
  const session = await store.getSession(common.conversationId);
  assert.equal(session.tool_call_count, 3);
  assert.equal(session.platform, "antigravity");
  assert.equal(session.status, "completed");
  assert.ok(session.duration_ms > 0);
});

test("same trajectory step in two conversations remains two projected calls", async (t) => {
  const s = await scratch(t);
  for (const conversationId of ["case-first", "case-second"]) {
    const result = await runShim(shim, s, { ...common, conversationId, stepIdx: 1,
      toolCall: { name: "view_file", args: { AbsolutePath: "/home/case/example.txt" } },
    }, { args: ["PostToolUse"] });
    assert.equal(result.code, 0, result.stderr);
  }
  const events = await loggedEvents(s.home);
  const calls = events.filter(e => e.event_type === "tool.invoked");
  assert.equal(new Set(calls.map(e => e.tool_call_id)).size, 2);
  const store = new InMemoryReadModelStore();
  await new Projector(store).replay(events);
  assert.equal((await store.getSession("case-first")).tool_call_count, 1);
  assert.equal((await store.getSession("case-second")).tool_call_count, 1);
});

test("capture starts when installed into an already-running conversation", async (t) => {
  const s = await scratch(t);
  await runShim(shim, s, { ...common, invocationNum: 5, initialNumSteps: 12 }, { args: ["PreInvocation"] });
  await runShim(shim, s, { ...common, invocationNum: 6, initialNumSteps: 14 }, { args: ["PreInvocation"] });
  assert.equal((await loggedEvents(s.home)).filter(e => e.event_type === "session.started").length, 1);
});

test("legacy PreToolUse never auto-approves on success, invalid input or storage failure", async (t) => {
  const s = await scratch(t);
  const payloads = [null, "invalid", { ...common, stepIdx: 1, toolCall: { name: "run_command", args: {} } }];
  for (const payload of payloads) {
    const result = await runShim(shim, s, payload, { args: ["PreToolUse"] });
    assert.equal(result.code, 0);
    assert.deepEqual(JSON.parse(result.stdout), { decision: "ask" });
  }
  const broken = await scratch(t);
  await mkdir(broken.home, { recursive: true });
  await writeFile(`${broken.home}/antigravity-state`, "not a directory");
  const result = await runShim(shim, broken, payloads[2], { args: ["PreToolUse"] });
  assert.equal(result.code, 0);
  assert.deepEqual(JSON.parse(result.stdout), { decision: "ask" });
});

test("failed log writes do not suppress the next successful start or stop", async (t) => {
  const s = await scratch(t);
  await mkdir(s.home, { recursive: true });
  await writeFile(`${s.home}/event-log`, "not a directory");
  const payload = { ...common, invocationNum: 0, initialNumSteps: 1 };
  await runShim(shim, s, payload, { args: ["PreInvocation"] });
  await rm(`${s.home}/event-log`);
  await runShim(shim, s, payload, { args: ["PreInvocation"] });
  const events = await loggedEvents(s.home);
  assert.equal(events.filter(e => e.event_type === "session.started").length, 1);
  await rename(join(s.home, "event-log"), join(s.home, "saved-log"));
  await writeFile(join(s.home, "event-log"), "not a directory");
  const stop = { ...common, fullyIdle: true, executionNum: 0, terminationReason: "model_stop" };
  await runShim(shim, s, stop, { args: ["Stop"] });
  await rm(join(s.home, "event-log"));
  await rename(join(s.home, "saved-log"), join(s.home, "event-log"));
  await runShim(shim, s, stop, { args: ["Stop"] });
  assert.equal((await loggedEvents(s.home)).filter(e => e.event_type === "session.ended").length, 1);
});

test("installed command executes in this host's shell and records a completed call", async (t) => {
  const s = await scratch(t);
  const interceptor = new AntigravityInterceptor({ projectPath: s.userHome, shimPath: shim, omnodexHome: s.home, nodePath: process.execPath });
  await interceptor.install();
  const hooks = JSON.parse(await readFile(interceptor.hooksFilePath(), "utf8"));
  assert.equal(hooks.omnodex.PreToolUse, undefined);
  const result = spawnSync(hooks.omnodex.PostToolUse[0].hooks[0].command, {
    shell: true, input: JSON.stringify({ ...common, stepIdx: 1, toolCall: { name: "view_file", args: { AbsolutePath: "/home/case/example.txt" } } }),
    encoding: "utf8", env: { ...process.env, OMNODEX_AUTO_SYNC: "0", OMNODEX_AUTO_DETECT: "0" },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {});
  assert.equal((await loggedEvents(s.home)).filter(e => e.event_type === "tool.completed").length, 1);
});
