/**
 * The shim contract: whatever a hook shim's work does, the agent gets exit
 * code 0 and one valid JSON document. Copilot denies a call when a hook
 * crashes or exits non-zero, and Cursor blocks it on invalid JSON, so a bug
 * in Omnodex must never reach the agent.
 *
 * Run: node --test packages/shared/test/shim-contract.test.mjs
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { runShim } from "../dist/shim-contract.js";

const capture = () => {
  const out = [];
  return { out, write: (text) => out.push(text) };
};

test("a decision the work returns is printed as one JSON document", async () => {
  const io = capture();
  const decision = { permissionDecision: "deny", permissionDecisionReason: "blocked by policy" };
  const r = await runShim({ run: () => decision, write: io.write });
  assert.equal(r.exitCode, 0);
  assert.equal(r.failed, false);
  assert.deepEqual(io.out, [JSON.stringify(decision)]);
  assert.deepEqual(JSON.parse(r.output), decision);
});

test("work that returns nothing prints the no-decision document, which is {} by default", async () => {
  for (const value of [undefined, null]) {
    const io = capture();
    const r = await runShim({ run: async () => value, write: io.write });
    assert.deepEqual(io.out, ["{}"]);
    assert.equal(r.failed, false);
  }
  const io = capture();
  await runShim({ run: () => undefined, noDecision: { continue: true }, write: io.write });
  assert.deepEqual(io.out, ['{"continue":true}']);
});

test("a throw, a rejection and a timeout all become no decision, exit 0, valid JSON", async () => {
  const errors = [];
  const cases = {
    throw: () => { throw new Error("boom"); },
    reject: () => Promise.reject(new Error("rejected")),
    timeout: () => new Promise(() => undefined),
  };
  for (const [name, run] of Object.entries(cases)) {
    const io = capture();
    const r = await runShim({
      run,
      write: io.write,
      noDecision: { permissionDecision: "allow" },
      onError: (e) => errors.push(`${name}: ${e.message}`),
      timeoutMs: name === "timeout" ? 20 : undefined,
    });
    assert.equal(r.exitCode, 0, name);
    assert.equal(r.failed, true, name);
    assert.deepEqual(JSON.parse(io.out.join("")), { permissionDecision: "allow" }, name);
  }
  assert.deepEqual(errors.map((e) => e.split(":")[0]), ["throw", "reject", "timeout"]);
});

test("a result that is not a serializable JSON object is replaced, never printed", async () => {
  const circular = {};
  circular.self = circular;
  for (const bad of ["a string", 42, true, ["array"], circular, { n: 10n }]) {
    const io = capture();
    const r = await runShim({ run: () => bad, write: io.write });
    assert.equal(r.failed, true, String(bad));
    assert.equal(io.out.join(""), "{}", String(bad));
    assert.doesNotThrow(() => JSON.parse(io.out.join("")));
  }
});

test("a failing logger or writer cannot break the contract", async () => {
  const r = await runShim({
    run: () => { throw new Error("first"); },
    onError: () => { throw new Error("logger is broken too"); },
    write: () => { throw new Error("stdout closed"); },
  });
  assert.equal(r.exitCode, 0);
  assert.equal(r.output, "{}");
});

test("a no-decision document that cannot be serialized falls back to {}", async () => {
  const circular = {};
  circular.self = circular;
  const io = capture();
  await runShim({ run: () => undefined, noDecision: circular, write: io.write });
  assert.deepEqual(io.out, ["{}"]);
});

test("by default the output goes to stdout", async () => {
  const original = process.stdout.write;
  const seen = [];
  process.stdout.write = (chunk) => { seen.push(String(chunk)); return true; };
  try {
    await runShim({ run: () => ({ ok: true }) });
  } finally {
    process.stdout.write = original;
  }
  assert.deepEqual(seen, ['{"ok":true}']);
});
