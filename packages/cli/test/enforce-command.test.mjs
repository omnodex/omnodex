// `omnodex enforce monitor|shadow|status`, and the shadow-mode offer on a
// first install. Moving between modes that never act needs no
// confirmation; leaving one that acts needs a person at a terminal.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { currentMode, offerShadowMode, runEnforce, setMode } from "../dist/enforce-command.js";

async function tempHome(t) {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "omnodex-enforce-"));
  t.after(() => fs.rm(home, { recursive: true, force: true }));
  return home;
}

/** A terminal that answers every question with `answer`. */
function fakeIo({ tty = true, answer = "" } = {}) {
  const out = [];
  const err = [];
  const asked = [];
  return {
    out, err, asked,
    stdinIsTTY: tty,
    stdoutIsTTY: tty,
    async ask(q) { asked.push(q); return answer; },
    log: (l) => out.push(l),
    error: (l) => err.push(l),
  };
}

const configFile = (home) => path.join(home, "omnodex-config.json");
const readConfig = async (home) => JSON.parse(await fs.readFile(configFile(home), "utf8"));

test("status defaults to monitor with no configuration", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo();
  assert.equal(await runEnforce(["status"], { home, io }), 0);
  assert.match(io.out[0], /monitor/);
});

test("shadow and back to monitor, without a terminal, keeping the rest of the file", async (t) => {
  const home = await tempHome(t);
  await fs.writeFile(configFile(home), JSON.stringify({ workspace_roots: ["~/code"], enforcement: { rules: { RULE_A: "deny" } } }));
  const io = fakeIo({ tty: false });
  assert.equal(await runEnforce(["shadow"], { home, io }), 0);
  assert.deepEqual(await readConfig(home), {
    workspace_roots: ["~/code"],
    enforcement: { rules: { RULE_A: "deny" }, mode: "shadow" },
  });
  assert.equal(await runEnforce(["monitor"], { home, io }), 0);
  assert.equal(await currentMode(home), "monitor");
  assert.equal(io.asked.length, 0);
});

test("an unknown mode is refused", async (t) => {
  const home = await tempHome(t);
  for (const mode of ["enforce-only", "block"]) {
    const io = fakeIo();
    assert.equal(await runEnforce([mode], { home, io }), 1);
    assert.match(io.err[0], /unknown mode/);
  }
});

test("guardrails makes the hooks wait for a decision, and leaving it puts them back", async (t) => {
  const home = await tempHome(t);
  const calls = [];
  const applyHookTiming = async (sync) => { calls.push(sync); return ["/home/case/.claude/settings.json"]; };

  const on = fakeIo({ tty: false });
  assert.equal(await runEnforce(["guardrails"], { home, io: on, applyHookTiming }), 0);
  assert.equal(await currentMode(home), "guardrails");
  assert.ok(on.out.some((l) => /hooks now answer before each call/.test(l)));

  // An agent cannot leave it; nothing is rewritten.
  assert.equal(await runEnforce(["shadow"], { home, io: fakeIo({ tty: false }), applyHookTiming }), 1);
  assert.deepEqual(calls, [true]);

  assert.equal(await runEnforce(["shadow"], { home, io: fakeIo({ answer: "shadow" }), applyHookTiming }), 0);
  assert.deepEqual(calls, [true, false]);

  // Between modes that never act, the hooks are left alone.
  assert.equal(await runEnforce(["monitor"], { home, io: fakeIo(), applyHookTiming }), 0);
  assert.deepEqual(calls, [true, false]);
});

test("leaving guardrails needs a person at a terminal", async (t) => {
  const home = await tempHome(t);
  await setMode(home, "guardrails");

  const agent = fakeIo({ tty: false });
  assert.equal(await runEnforce(["monitor"], { home, io: agent }), 1);
  assert.match(agent.err[0], /needs a person at an interactive terminal/);
  assert.equal(await currentMode(home), "guardrails");

  const wrong = fakeIo({ answer: "yes" });
  assert.equal(await runEnforce(["monitor"], { home, io: wrong }), 1);
  assert.equal(await currentMode(home), "guardrails");

  const person = fakeIo({ answer: "monitor" });
  assert.equal(await runEnforce(["monitor"], { home, io: person }), 0);
  assert.equal(await currentMode(home), "monitor");
});

test("a malformed configuration file is reported, not overwritten", async (t) => {
  const home = await tempHome(t);
  await fs.writeFile(configFile(home), "{ not json");
  const io = fakeIo();
  assert.equal(await runEnforce(["shadow"], { home, io }), 1);
  assert.equal(await fs.readFile(configFile(home), "utf8"), "{ not json");
});

test("first install: shadow is offered and Enter accepts it", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo({ answer: "" });
  assert.equal(await offerShadowMode({ home, io, yes: false }), "shadow");
  assert.equal(io.asked.length, 1);
  assert.equal(await currentMode(home), "shadow");
});

test("first install: declining records monitor, so the offer is not repeated", async (t) => {
  const home = await tempHome(t);
  assert.equal(await offerShadowMode({ home, io: fakeIo({ answer: "n" }), yes: false }), "monitor");
  assert.equal((await readConfig(home)).enforcement.mode, "monitor");
  const again = fakeIo({ answer: "" });
  assert.equal(await offerShadowMode({ home, io: again, yes: false }), "monitor");
  assert.equal(again.asked.length, 0);
});

test("first install: --yes takes the default, and no terminal without --yes changes nothing", async (t) => {
  const home = await tempHome(t);
  assert.equal(await offerShadowMode({ home, io: fakeIo({ tty: false }), yes: true }), "shadow");
  const other = await tempHome(t);
  assert.equal(await offerShadowMode({ home: other, io: fakeIo({ tty: false }), yes: false }), "monitor");
  await assert.rejects(fs.stat(configFile(other)));
});

test("a mode the user already chose is never changed by the offer", async (t) => {
  const home = await tempHome(t);
  await setMode(home, "monitor");
  assert.equal(await offerShadowMode({ home, io: fakeIo(), yes: true }), "monitor");
  assert.equal(await currentMode(home), "monitor");
});

test("guardrails need a plan that includes them; shadow is suggested instead", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo();
  const prepareGuardrails = async () => ({ entitled: false, ready: false, detail: "not included in this plan" });
  assert.equal(await runEnforce(["guardrails"], { home, io, prepareGuardrails }), 1);
  assert.match(io.err[0], /part of Omnodex Pro/);
  assert.match(io.err[0], /omnodex enforce shadow/);
  assert.equal(await currentMode(home), "monitor");
});

test("an entitled account without the module yet is told calls are recorded as shadow until it arrives", async (t) => {
  const home = await tempHome(t);
  const io = fakeIo();
  const prepareGuardrails = async () => ({ entitled: true, ready: false, detail: "no guardrails module installed (Pro)" });
  assert.equal(await runEnforce(["guardrails"], { home, io, prepareGuardrails }), 0);
  assert.equal(await currentMode(home), "guardrails");
  assert.ok(io.out.some((l) => /recorded as in shadow mode/.test(l)));
});

test("status in guardrails mode names the module's state", async (t) => {
  const home = await tempHome(t);
  await setMode(home, "guardrails");
  const io = fakeIo();
  assert.equal(await runEnforce(["status"], { home, io, describeGuardrails: async () => "guardrails module 1.0.0 (valid until 2026-11-18)" }), 0);
  assert.match(io.out[1], /guardrails module 1\.0\.0/);
});
