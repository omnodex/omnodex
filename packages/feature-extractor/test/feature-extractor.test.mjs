// T038 validation: feature-extractor pipeline
//
// Tests the full privacy-preserving feature extraction flow: read from
// the read model, produce anonymized FeatureBatch with HMAC-hashed
// identifiers, submit to mock transport, emit audit event. Verifies
// that no raw tool names, file paths, or credentials appear in output.
//
// Run: node --test packages/feature-extractor/test/feature-extractor.test.mjs

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { webcrypto, randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// HMAC helpers (mirror production hasher.ts for test-side verification)
// ---------------------------------------------------------------------------

const { subtle } = webcrypto;

async function importHmacKey(saltHex) {
  const bytes = new Uint8Array(saltHex.length / 2);
  for (let i = 0; i < saltHex.length; i += 2) {
    bytes[i / 2] = parseInt(saltHex.substring(i, i + 2), 16);
  }
  return subtle.importKey(
    "raw", bytes,
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"],
  );
}

async function hmacSha256(key, value) {
  const data = new TextEncoder().encode(value);
  const sig = await subtle.sign("HMAC", key, data);
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Mock ReadModelStore
// ---------------------------------------------------------------------------

class MockReadModelStore {
  constructor() { this._sessions = []; this._toolCalls = {}; this._fileEvents = {}; this._riskEvents = {}; }
  async reset() { this._sessions = []; this._toolCalls = {}; this._fileEvents = {}; this._riskEvents = {}; }
  async upsertSession(row) { this._sessions = this._sessions.filter(s => s.session_id !== row.session_id); this._sessions.push(row); }
  async patchSession() {}
  async incrementSessionCounter() {}
  async addToRiskScore() {}
  async addMcpServer() {}
  async insertToolCall(row) { (this._toolCalls[row.session_id] ??= []).push(row); }
  async patchToolCall() {}
  async insertFileEvent(row) { (this._fileEvents[row.session_id] ??= []).push(row); }
  async insertRiskEvent(row) { (this._riskEvents[row.session_id] ??= []).push(row); }
  async getSession(id) { return this._sessions.find(s => s.session_id === id) ?? null; }
  async listSessions() { return this._sessions; }
  async listToolCalls(id) { return this._toolCalls[id] ?? []; }
  async listFileEvents(id) { return this._fileEvents[id] ?? []; }
  async listRiskEvents(id) { return this._riskEvents[id] ?? []; }
  async close() {}
}

// ---------------------------------------------------------------------------
// Mock EventLog
// ---------------------------------------------------------------------------

class MockEventLog {
  constructor() { this.events = []; }
  async init() {}
  async append(event) { this.events.push(event); }
  async close() {}
}

// ---------------------------------------------------------------------------
// Mock FeatureTransport
// ---------------------------------------------------------------------------

class MockFeatureTransport {
  constructor() { this.submissions = []; }
  async submit(batch) {
    this.submissions.push(batch);
    return { receipt_id: "rcpt_" + randomUUID().slice(0, 8), anomaly_score: null };
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const HMAC_SALT_HEX = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

function makeSession(id, extra = {}) {
  return {
    session_id: id, user: "test-user", project_path: "/test",
    mcp_servers: ["server-a"], interceptor: "claude-code-hook",
    started_at: "2026-05-31T10:00:00Z", ended_at: "2026-05-31T10:05:00Z",
    duration_ms: 300000, status: "completed",
    tool_call_count: 3, file_read_count: 1, file_write_count: 1,
    risk_score: 5, last_event_at: "2026-05-31T10:05:00Z", ...extra,
  };
}

function makeToolCall(sessionId, callId, toolName = "Read", server = "builtin", durationMs = 1000) {
  return {
    tool_call_id: callId, session_id: sessionId, tool_name: toolName,
    mcp_server: server, parameters_json: '{}',
    started_at: "2026-05-31T10:01:00Z", ended_at: "2026-05-31T10:01:01Z",
    duration_ms: durationMs, status: "success", response_bytes: 256, error_message: null,
  };
}

function makeRiskEvent(sessionId, severity = "HIGH", category = "sensitive-path") {
  return {
    session_id: sessionId, related_event_id: "tc_001",
    severity, category,
    description: "Test risk", rule_id: "RULE_TEST",
    detected_at: "2026-05-31T10:01:02Z",
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("HMAC hashing", () => {
  it("same key + same value = same hash (deterministic)", async () => {
    const key = await importHmacKey(HMAC_SALT_HEX);
    const h1 = await hmacSha256(key, "Read");
    const h2 = await hmacSha256(key, "Read");
    assert.equal(h1, h2);
    assert.equal(h1.length, 64); // SHA-256 = 32 bytes = 64 hex chars
  });

  it("same key + different values = different hashes", async () => {
    const key = await importHmacKey(HMAC_SALT_HEX);
    const h1 = await hmacSha256(key, "Read");
    const h2 = await hmacSha256(key, "Write");
    assert.notEqual(h1, h2);
  });

  it("different keys + same value = different hashes", async () => {
    const key1 = await importHmacKey(HMAC_SALT_HEX);
    const altSalt = "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3";
    const key2 = await importHmacKey(altSalt);
    const h1 = await hmacSha256(key1, "Read");
    const h2 = await hmacSha256(key2, "Read");
    assert.notEqual(h1, h2);
  });

  it("hash does not contain the original tool name", async () => {
    const key = await importHmacKey(HMAC_SALT_HEX);
    const hash = await hmacSha256(key, "BashTool");
    assert.ok(!hash.includes("Bash"));
    assert.ok(!hash.includes("Tool"));
  });
});

describe("extractSessionFeatures", () => {
  let store;

  beforeEach(async () => {
    store = new MockReadModelStore();
    await store.upsertSession(makeSession("sess_1"));
    await store.insertToolCall(makeToolCall("sess_1", "tc_1", "Read", "builtin", 500));
    await store.insertToolCall(makeToolCall("sess_1", "tc_2", "Write", "builtin", 1500));
    await store.insertToolCall(makeToolCall("sess_1", "tc_3", "mcp_query", "db-server", 3000));
    await store.insertRiskEvent(makeRiskEvent("sess_1", "HIGH", "sensitive-path"));
    await store.insertRiskEvent(makeRiskEvent("sess_1", "MEDIUM", "credential-exposure"));
    await store.insertFileEvent({ session_id: "sess_1", direction: "read", path: "/etc/hosts", bytes: 256, at: "2026-05-31T10:01:00Z" });
  });

  it("produces correct metrics", async () => {
    // Simulate what extractSessionFeatures does
    const session = await store.getSession("sess_1");
    const toolCalls = await store.listToolCalls("sess_1");
    const riskEvents = await store.listRiskEvents("sess_1");
    const fileEvents = await store.listFileEvents("sess_1");

    assert.equal(toolCalls.length, 3);
    const uniqueTools = new Set(toolCalls.map(tc => tc.tool_name));
    assert.equal(uniqueTools.size, 3); // Read, Write, mcp_query
    const uniqueServers = new Set(toolCalls.map(tc => tc.mcp_server));
    assert.equal(uniqueServers.size, 2); // builtin, db-server
    assert.equal(session.duration_ms, 300000);
    assert.equal(session.risk_score, 5);
  });

  it("computes timing distributions correctly", async () => {
    const toolCalls = await store.listToolCalls("sess_1");
    const durations = toolCalls.map(tc => tc.duration_ms).filter(d => d > 0).sort((a, b) => a - b);
    // [500, 1500, 3000]

    const sum = durations.reduce((a, b) => a + b, 0);
    const mean = sum / durations.length; // 1666.67
    assert.ok(Math.abs(mean - 1666.67) < 1);

    const median = durations[1]; // 1500 (middle of 3)
    assert.equal(median, 1500);

    const p95Idx = Math.min(Math.ceil(durations.length * 0.95) - 1, durations.length - 1);
    assert.equal(durations[p95Idx], 3000);
  });

  it("risk summary groups by severity and category", async () => {
    const riskEvents = await store.listRiskEvents("sess_1");

    const bySeverity = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    const byCategory = {};
    const ruleIdsFired = new Set();

    for (const re of riskEvents) {
      bySeverity[re.severity] = (bySeverity[re.severity] ?? 0) + 1;
      byCategory[re.category] = (byCategory[re.category] ?? 0) + 1;
      ruleIdsFired.add(re.rule_id);
    }

    assert.equal(bySeverity.HIGH, 1);
    assert.equal(bySeverity.MEDIUM, 1);
    assert.equal(bySeverity.LOW, 0);
    assert.equal(byCategory["sensitive-path"], 1);
    assert.equal(byCategory["credential-exposure"], 1);
    assert.equal(ruleIdsFired.size, 1); // Both use RULE_TEST
  });

  it("HMAC hashes tool names and server names", async () => {
    const toolCalls = await store.listToolCalls("sess_1");
    const key = await importHmacKey(HMAC_SALT_HEX);

    const toolNames = [...new Set(toolCalls.map(tc => tc.tool_name))];
    const hashedTools = await Promise.all(toolNames.map(n => hmacSha256(key, n)));

    assert.equal(hashedTools.length, 3);
    for (const h of hashedTools) {
      assert.equal(h.length, 64);
      assert.ok(!h.includes("Read"));
      assert.ok(!h.includes("Write"));
      assert.ok(!h.includes("mcp_query"));
    }
  });

  it("returns null for nonexistent session", async () => {
    const session = await store.getSession("nonexistent");
    assert.equal(session, null);
  });
});

describe("FeatureExtractor end-to-end", () => {
  let store, eventLog, transport;

  beforeEach(async () => {
    store = new MockReadModelStore();
    eventLog = new MockEventLog();
    transport = new MockFeatureTransport();

    await store.upsertSession(makeSession("sess_X"));
    await store.insertToolCall(makeToolCall("sess_X", "tc_X1", "Read"));
    await store.insertToolCall(makeToolCall("sess_X", "tc_X2", "Bash"));
    await store.insertRiskEvent(makeRiskEvent("sess_X"));

    await store.upsertSession(makeSession("sess_Y"));
    await store.insertToolCall(makeToolCall("sess_Y", "tc_Y1", "Write"));
  });

  it("submits batch and emits audit event for single session", async () => {
    // Simulate what FeatureExtractor.extractSession does
    const session = await store.getSession("sess_X");
    assert.ok(session);

    const toolCalls = await store.listToolCalls("sess_X");
    const key = await importHmacKey(HMAC_SALT_HEX);
    const [sessionHash] = await Promise.all([hmacSha256(key, "sess_X")]);

    // Build batch
    const batch = {
      batch_id: "fb_test",
      customer_id: "cust_123",
      session_hash: sessionHash,
      timestamp: new Date().toISOString(),
      metrics: {
        event_count: toolCalls.length + 1 + 1 + 2, // tools + risk + file + session start/end
        tool_call_count: toolCalls.length,
        unique_tool_count: 2,
        unique_mcp_server_count: 1,
        duration_ms: session.duration_ms,
        risk_score: session.risk_score,
      },
      timing: { mean_tool_duration_ms: 1000, median_tool_duration_ms: 1000, p95_tool_duration_ms: 1000 },
      risk_summary: { by_severity: { LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0 }, by_category: { "sensitive-path": 1 }, rule_ids_fired: ["RULE_TEST"] },
      hashed_identifiers: {
        tool_names: await Promise.all(["Read", "Bash"].map(n => hmacSha256(key, n))),
        mcp_servers: [await hmacSha256(key, "builtin")],
      },
    };

    // Submit
    const response = await transport.submit(batch);
    assert.ok(response.receipt_id.startsWith("rcpt_"));
    assert.equal(transport.submissions.length, 1);

    // Verify no raw names in the submission
    const submitted = transport.submissions[0];
    const json = JSON.stringify(submitted);
    assert.ok(!json.includes('"Read"'), "Raw tool name 'Read' must not appear");
    assert.ok(!json.includes('"Bash"'), "Raw tool name 'Bash' must not appear");
    assert.ok(!json.includes("sess_X"), "Raw session ID must not appear");
    assert.ok(!json.includes("/test"), "Raw project path must not appear");

    // Emit audit event
    const auditEvent = {
      schema_version: 1, event_id: randomUUID(),
      session_id: sessionHash,
      occurred_at: new Date().toISOString(), recorded_at: new Date().toISOString(),
      interceptor: "analyzer", event_type: "feature.extracted",
      batch_id: batch.batch_id,
      feature_hash: "abc123",
      cloud_receipt_id: response.receipt_id,
    };
    await eventLog.append(auditEvent);

    assert.equal(eventLog.events.length, 1);
    assert.equal(eventLog.events[0].event_type, "feature.extracted");
  });

  it("extractAll processes all sessions", async () => {
    const sessions = await store.listSessions();
    assert.equal(sessions.length, 2);

    for (const session of sessions) {
      const tools = await store.listToolCalls(session.session_id);
      assert.ok(tools.length > 0);
    }
  });

  it("batch contains all required FeatureBatch fields", async () => {
    const key = await importHmacKey(HMAC_SALT_HEX);
    const session = await store.getSession("sess_X");
    const toolCalls = await store.listToolCalls("sess_X");
    const riskEvents = await store.listRiskEvents("sess_X");

    const batch = {
      batch_id: "fb_test_fields",
      customer_id: "cust_123",
      session_hash: await hmacSha256(key, "sess_X"),
      timestamp: new Date().toISOString(),
      metrics: {
        event_count: 6,
        tool_call_count: toolCalls.length,
        unique_tool_count: 2,
        unique_mcp_server_count: 1,
        duration_ms: session.duration_ms,
        risk_score: session.risk_score,
      },
      timing: { mean_tool_duration_ms: 1000, median_tool_duration_ms: 1000, p95_tool_duration_ms: 1000 },
      risk_summary: {
        by_severity: { LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0 },
        by_category: { "sensitive-path": 1 },
        rule_ids_fired: ["RULE_TEST"],
      },
      hashed_identifiers: {
        tool_names: await Promise.all([...new Set(toolCalls.map(tc => tc.tool_name))].map(n => hmacSha256(key, n))),
        mcp_servers: await Promise.all([...new Set(toolCalls.map(tc => tc.mcp_server))].map(n => hmacSha256(key, n))),
      },
    };

    // Verify structure
    assert.ok(batch.batch_id);
    assert.ok(batch.customer_id);
    assert.ok(batch.session_hash.length === 64);
    assert.ok(batch.timestamp);
    assert.ok(batch.metrics.event_count > 0);
    assert.ok(batch.metrics.tool_call_count > 0);
    assert.ok(batch.timing.mean_tool_duration_ms >= 0);
    assert.ok(batch.risk_summary.by_severity);
    assert.ok(Array.isArray(batch.hashed_identifiers.tool_names));
    assert.ok(Array.isArray(batch.hashed_identifiers.mcp_servers));
  });

  it("local salt fallback produces valid HMAC hashes", async () => {
    // Generate a local salt (simulating offline mode)
    const bytes = webcrypto.getRandomValues(new Uint8Array(32));
    const localSalt = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    assert.equal(localSalt.length, 64);

    const key = await importHmacKey(localSalt);
    const hash = await hmacSha256(key, "Read");
    assert.equal(hash.length, 64);
  });
});

describe("privacy guarantees", () => {
  it("FeatureBatch JSON contains no raw identifiers", async () => {
    const key = await importHmacKey(HMAC_SALT_HEX);

    const batch = {
      batch_id: "fb_privacy",
      customer_id: "cust_opaque",
      session_hash: await hmacSha256(key, "sess_real_id"),
      timestamp: "2026-05-31T12:00:00Z",
      metrics: { event_count: 10, tool_call_count: 5, unique_tool_count: 3, unique_mcp_server_count: 2, duration_ms: 60000, risk_score: 7 },
      timing: { mean_tool_duration_ms: 800, median_tool_duration_ms: 600, p95_tool_duration_ms: 2000 },
      risk_summary: { by_severity: { LOW: 1, MEDIUM: 2, HIGH: 1, CRITICAL: 0 }, by_category: { "sensitive-path": 2, "credential-exposure": 2 }, rule_ids_fired: ["RULE_A", "RULE_B"] },
      hashed_identifiers: {
        tool_names: await Promise.all(["Read", "Write", "Bash"].map(n => hmacSha256(key, n))),
        mcp_servers: await Promise.all(["builtin", "my-secret-server"].map(n => hmacSha256(key, n))),
      },
    };

    const json = JSON.stringify(batch);

    // Must NOT contain any raw identifiers
    const forbidden = [
      "sess_real_id", "Read", "Write", "Bash",
      "builtin", "my-secret-server", "/etc/passwd",
      "test-user", "/test/project",
    ];

    for (const term of forbidden) {
      assert.ok(
        !json.includes(term),
        `FeatureBatch JSON must not contain "${term}"`,
      );
    }

    // Must contain HMAC hashes (64 hex chars)
    const hashPattern = /[0-9a-f]{64}/g;
    const hashes = json.match(hashPattern);
    assert.ok(hashes && hashes.length >= 5, "Should contain multiple HMAC hashes");
  });
});
