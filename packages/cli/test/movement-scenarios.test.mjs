import { test } from "node:test";
import assert from "node:assert/strict";
import { MOVEMENT_SCENARIOS, buildMovementScenarios, COMMUNITY_SCENARIOS } from "../../hooks-provider/dist/index.js";
import { normalizeAction } from "../../analyzer/dist/action.js";
import { parseSpikeOptions } from "../dist/spike-options.js";

for (const seed of [0, 1, 42, -1, 12345]) {
  test(`loopback movement set is deterministic and preserves every chain: ${seed}`, () => {
    const events = buildMovementScenarios({ seed });
    assert.deepEqual(events, buildMovementScenarios({ seed }));
    const ids = [...new Set(events.map(e => e.session_id))];
    assert.equal(ids.length, COMMUNITY_SCENARIOS.length + MOVEMENT_SCENARIOS.length + 4);
    for (const [index, fixture] of MOVEMENT_SCENARIOS.entries()) {
      const calls = events.filter(e => e.session_id === ids[COMMUNITY_SCENARIOS.length + index] && e.event_type === "tool.invoked");
      assert.equal(calls.length, fixture.calls.length, fixture.id);
      assert.deepEqual(calls.map(e => e.parameters), fixture.calls.map(c => c.parameters));
      for (const call of calls) {
        for (const destination of normalizeAction(call).destinations) assert.ok(["127.0.0.1", "localhost"].includes(destination.host), `${fixture.id}: ${destination.host}`);
        assert.ok(!JSON.stringify(call.parameters).includes("sk_live_"));
        assert.ok(!JSON.stringify(call.parameters).includes("ghp_"));
      }
    }
  });
}
test("CLI opts into movement fixtures and enforces the larger minimum", () => {
  assert.equal(parseSpikeOptions(["--scenario-set", "movement"]).additionalScenarios, MOVEMENT_SCENARIOS);
  assert.throws(() => parseSpikeOptions(["--scenario-set", "unknown"]));
  assert.throws(() => parseSpikeOptions(["--scenario-set", "movement", "--sessions", "12"]));
});
