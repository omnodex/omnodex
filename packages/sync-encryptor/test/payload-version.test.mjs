import { test } from "node:test";
import * as assert from "node:assert/strict";
import { InMemoryReadModelStore, Projector } from "../../projection/dist/index.js";
import { serializeReadModel, SYNC_PAYLOAD_VERSION } from "../dist/index.js";
import { RISK_SEVERITY_WEIGHT } from "../../shared/dist/index.js";

/**
 * The payload version is how a reader tells which risk scale a blob is on.
 *
 * v1 blobs scored LOW/MEDIUM/HIGH/CRITICAL as 5/15/30/60; v2 scores them on
 * RISK_SEVERITY_WEIGHT. The two are not related by a constant factor, so a
 * consumer cannot convert a v1 score arithmetically and must not guess from
 * the magnitude of the number. It can recompute exactly from the risk_events
 * the payload carries, which is what the hosted dashboard does, but only if
 * it can tell the vintages apart.
 */

const AT = "2026-09-18T12:00:00.000Z";

function event(overrides) {
  return {
    schema_version: 1,
    session_id: "sess_v2",
    occurred_at: AT,
    recorded_at: AT,
    interceptor: "claude-code-hook",
    ...overrides,
  };
}

async function buildStore() {
  const store = new InMemoryReadModelStore();
  const projector = new Projector(store);
  await projector.apply(
    event({
      event_id: "e_start",
      event_type: "session.started",
      user: "case",
      project_path: "/home/case/repo",
      mcp_servers: [],
    }),
  );
  await projector.apply(
    event({
      event_id: "e_risk",
      event_type: "risk.detected",
      interceptor: "analyzer",
      severity: "HIGH",
      category: "sensitive_path_read",
      description: "read a sensitive path",
      related_event_id: "tc_1",
      rule_id: "rule_sensitive_path",
    }),
  );
  return store;
}

test("serializeReadModel stamps the current payload version", async () => {
  const payload = await serializeReadModel(await buildStore());
  assert.equal(payload.payload_version, SYNC_PAYLOAD_VERSION);
});

test("the current version is 2, meaning the small risk scale", async () => {
  // Pinned deliberately. Bumping this without teaching the hosted dashboard
  // what the new version means would leave it reading blobs it cannot
  // interpret, which is the failure this version exists to prevent.
  assert.equal(SYNC_PAYLOAD_VERSION, 2);
});

test("a v2 payload carries scores on the weight scale", async () => {
  const payload = await serializeReadModel(await buildStore());
  const session = payload.sessions.find((s) => s.session_id === "sess_v2");

  assert.equal(session.risk_score, RISK_SEVERITY_WEIGHT.HIGH);
  assert.ok(session.risk_score < 5, "a v1 reader would have seen 30 here");
});

test("a v2 payload carries the risk events a reader would recompute from", async () => {
  // The hosted dashboard recomputes a v1 blob's scores from these rather
  // than scaling the number, so they have to be present per session.
  const payload = await serializeReadModel(await buildStore());
  assert.equal(payload.risk_events["sess_v2"].length, 1);
  assert.equal(payload.risk_events["sess_v2"][0].severity, "HIGH");
});
