import { test } from "node:test";
import assert from "node:assert/strict";
import { asPlatform } from "../dist/core/events.js";

test("the proxy accepts every platform name Omnodex records", () => {
  for (const p of ["claude-code", "codex", "cowork", "web", "antigravity", "copilot", "cursor", "opencode"]) {
    assert.equal(asPlatform(p), p);
    assert.equal(asPlatform(` ${p.toUpperCase()} `), p);
  }
  assert.equal(asPlatform("vim"), undefined);
});
