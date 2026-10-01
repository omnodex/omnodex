/**
 * Dashboard conformance fixtures, local side: collapsing correlated pairs
 * gives the calls, findings and per-session counts each fixture expects.
 * The hosted dashboard runs its own collapse over the same files.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { collapseCorrelated } from "../dist/index.js";

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "dashboard");
const fixtures = readdirSync(DIR).filter((f) => f.endsWith(".json"));

test("there are conformance fixtures to check", () => {
  assert.ok(fixtures.length >= 3);
});

for (const file of fixtures) {
  test(`fixture ${file}: collapsed calls, findings and session counts`, () => {
    const { snapshot, expected } = JSON.parse(readFileSync(path.join(DIR, file), "utf8"));
    const out = collapseCorrelated(snapshot);
    const count = (byId) => Object.values(byId).reduce((n, rows) => n + rows.length, 0);
    assert.equal(count(out.tool_calls), expected.calls, "calls");
    assert.equal(count(out.risk_events), expected.findings, "findings");
    for (const [id, want] of Object.entries(expected.sessions)) {
      const s = out.sessions.find((x) => x.session_id === id);
      assert.ok(s, `session ${id}`);
      assert.equal((out.tool_calls[id] ?? []).length, want.calls, `${id} calls`);
      assert.equal((out.risk_events[id] ?? []).length, want.findings, `${id} findings`);
      assert.equal(s.tool_call_count, want.tool_call_count, `${id} tool_call_count`);
    }
  });
}
