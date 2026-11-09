// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
// The generated plugin file, run against a stand-in launcher: what it sends
// for each OpenCode event, when it throws, and that nothing else can.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { buildPluginSource, PLUGIN_MARKER } from "../dist/index.js";

const FAKE_LAUNCHER = `
const fs = require("node:fs");
let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  fs.appendFileSync(process.env.FAKE_LOG, input + "\\n");
  const mode = process.env.FAKE_MODE || "";
  if (mode === "hang") return setTimeout(() => {}, 60000);
  if (mode === "crash") process.exit(3);
  if (mode === "garbage") return process.stdout.write("not json");
  const env = JSON.parse(input);
  if (mode === "deny" && env.event === "tool.before") process.stdout.write(JSON.stringify({ decision: "deny", reason: "blocked by test" }));
  else process.stdout.write("{}");
});
`;

async function setup(t, { mode = "", timeoutMs, userScope = false } = {}) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-oc-plugin-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const launcher = path.join(dir, "launcher.cjs");
  await writeFile(launcher, FAKE_LAUNCHER);
  const log = path.join(dir, "log.jsonl");
  process.env.FAKE_LOG = log;
  process.env.FAKE_MODE = mode;
  t.after(() => { delete process.env.FAKE_LOG; delete process.env.FAKE_MODE; });
  const file = path.join(dir, "plugin.mjs");
  await writeFile(file, buildPluginSource({ nodePath: process.execPath, launcherPath: launcher, omnodexHome: path.join(dir, "home"), userScope, timeoutMs }));
  const mod = await import(pathToFileURL(file).href + "?" + Math.random());
  const hooks = await mod.OmnodexPlugin({ directory: "/home/case/repo" });
  const sent = async () => (await readFile(log, "utf8").catch(() => "")).split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return { hooks, sent, dir };
}
// Events are queued; this lets the queue drain.
const settle = (hooks) => hooks["tool.execute.before"]({ tool: "noop", sessionID: "drain", callID: "drain" }, { args: {} });

test("the file starts with the marker and holds the launcher it was given", () => {
  const src = buildPluginSource({ nodePath: "/n/node", launcherPath: "/h/.omnodex/bin/opencode-plugin-launcher.js", omnodexHome: "/h/.omnodex", userScope: true });
  assert.ok(src.split("\n")[0].includes(PLUGIN_MARKER));
  assert.match(src, /opencode-plugin-launcher\.js/);
  assert.match(src, /"userScope": true/);
});

test("a session, a prompt, a call and its result arrive in order, with the root session and project", async (t) => {
  const { hooks, sent } = await setup(t);
  await hooks.event({ event: { type: "session.created", properties: { info: { id: "s1", directory: "/home/case/repo", title: "t" } } } });
  await hooks["chat.message"]({ sessionID: "s1", model: { providerID: "p", modelID: "free-model" } }, { parts: [{ type: "text", text: "say hi" }, { type: "text", text: "synthetic", synthetic: true }] });
  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "ls" } });
  await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s1", callID: "c1", args: { command: "ls" } }, { title: "ls", output: "a b", metadata: {} });
  await hooks.event({ event: { type: "session.deleted", properties: { info: { id: "s1" } } } });
  await settle(hooks);
  const got = await sent();
  assert.deepEqual(got.slice(0, 5).map((e) => e.event), ["session.start", "prompt", "tool.before", "tool.after", "session.end"]);
  assert.ok(got.every((e) => e.session_id === "s1" || e.session_id === "drain"));
  assert.equal(got[0].cwd, "/home/case/repo");
  assert.equal(got[1].prompt, "say hi");
  assert.equal(got[1].model, "free-model");
  assert.deepEqual(got[2].args, { command: "ls" });
  assert.equal(got[3].output, "a b");
  assert.equal(typeof got[3].duration_ms, "number");
});

test("a deny becomes a thrown error carrying the reason; anything else lets the call run", async (t) => {
  const denying = await setup(t, { mode: "deny" });
  await assert.rejects(denying.hooks["tool.execute.before"]({ tool: "read", sessionID: "s2", callID: "c" }, { args: { filePath: "/etc/shadow" } }), /blocked by test/);
  for (const mode of ["", "garbage", "crash"]) {
    const { hooks } = await setup(t, { mode });
    await assert.doesNotReject(hooks["tool.execute.before"]({ tool: "read", sessionID: "s3", callID: "c" }, { args: {} }), mode);
  }
});

test("a launcher that hangs is cut off at the time limit and the call runs", async (t) => {
  const { hooks } = await setup(t, { mode: "hang", timeoutMs: 300 });
  const started = Date.now();
  await assert.doesNotReject(hooks["tool.execute.before"]({ tool: "read", sessionID: "s4", callID: "c" }, { args: {} }));
  assert.ok(Date.now() - started < 5000);
});

test("a missing launcher or node binary never throws", async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "omnodex-oc-plugin-"));
  t.after(() => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const file = path.join(dir, "plugin.mjs");
  await writeFile(file, buildPluginSource({ nodePath: path.join(dir, "no-such-node"), launcherPath: path.join(dir, "no-such.js"), omnodexHome: dir }));
  const hooks = await (await import(pathToFileURL(file).href)).OmnodexPlugin({});
  await assert.doesNotReject(hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, { args: {} }));
  await assert.doesNotReject(hooks.event({ event: { type: "session.created", properties: { info: { id: "s" } } } }));
  await assert.doesNotReject(hooks["chat.message"]({ sessionID: "s" }, { parts: [] }));
  await assert.doesNotReject(hooks["tool.execute.after"]({ tool: "bash", sessionID: "s", callID: "c" }, {}));
});

test("malformed hook arguments are ignored, not thrown", async (t) => {
  const { hooks } = await setup(t);
  await assert.doesNotReject(hooks.event(undefined));
  await assert.doesNotReject(hooks.event({ event: { type: "session.created" } }));
  await assert.doesNotReject(hooks["chat.message"](undefined, undefined));
  await assert.doesNotReject(hooks["tool.execute.before"](undefined, undefined));
  await assert.doesNotReject(hooks["tool.execute.after"](undefined, undefined));
});

test("a subagent's session is recorded under its parent, with its own id as the agent", async (t) => {
  const { hooks, sent } = await setup(t);
  await hooks.event({ event: { type: "session.created", properties: { info: { id: "root", directory: "/home/case/repo" } } } });
  await hooks.event({ event: { type: "session.created", properties: { info: { id: "child", parentID: "root", title: "explore" } } } });
  await hooks["tool.execute.before"]({ tool: "grep", sessionID: "child", callID: "k1" }, { args: { pattern: "x" } });
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "child" } } });
  await settle(hooks);
  const got = await sent();
  assert.deepEqual(got.slice(0, 4).map((e) => [e.event, e.session_id, e.agent_id]), [
    ["session.start", "root", undefined],
    ["subagent.start", "root", "child"],
    ["tool.before", "root", "child"],
    ["subagent.stop", "root", "child"],
  ]);
  assert.equal(got[1].agent_type, "explore");
});

test("a failed tool part is recorded once, and not again if the after-hook also fires", async (t) => {
  const { hooks, sent } = await setup(t);
  const part = { type: "tool", sessionID: "s5", callID: "c5", tool: "bash", state: { status: "error", input: { command: "false" }, error: "exit 1" } };
  await hooks.event({ event: { type: "message.part.updated", properties: { part } } });
  await hooks.event({ event: { type: "message.part.updated", properties: { part } } });
  await hooks["tool.execute.after"]({ tool: "bash", sessionID: "s5", callID: "c5", args: {} }, { output: "" });
  await settle(hooks);
  const errors = (await sent()).filter((e) => e.event === "tool.error" || e.event === "tool.after");
  assert.deepEqual(errors.map((e) => e.event), ["tool.error"]);
  assert.equal(errors[0].error, "exit 1");
});

test("the every-project file passes the user-scope marker to the launcher", async (t) => {
  const { hooks, sent } = await setup(t, { userScope: true });
  await hooks["chat.message"]({ sessionID: "s6" }, { parts: [{ type: "text", text: "hi" }] });
  await settle(hooks);
  assert.ok((await sent()).length > 0);
});
