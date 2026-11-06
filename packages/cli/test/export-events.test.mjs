// Redaction defaults and the OCSF mapping for `omnodex export`.
// MUST cases name what has to appear; MUST_NOT cases what has to stay out.

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { normalizeEvent, parseInclude, parseTimeArg, inWindow, toOcsf, EXPORT_SCHEMA, OCSF_VERSION } from "../dist/export-events.js";

const base = (over) => ({
  schema_version: 1,
  event_id: "e1",
  session_id: "s1",
  occurred_at: "2026-11-06T12:00:00.000Z",
  recorded_at: "2026-11-06T12:00:01.000Z",
  interceptor: "claude-code-hook",
  platform: "claude-code",
  ...over,
});

const toolCall = base({ event_type: "tool.invoked", tool_call_id: "t1", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "echo SECRET-VALUE" }, cwd: "/home/case/repo" });
const prompt = base({ event_type: "prompt.submitted", prompt: "deploy with password hunter2" });
const finding = base({ event_type: "risk.detected", severity: "HIGH", category: "exfiltration", description: "Sent a credential file to a new host", related_event_id: "t1", related_event_ids: ["t0", "t1"], rule_id: "rule-1", rule_tier: "community" });

test("MUST_NOT: tool parameters, prompts, titles and error text are left out by default", () => {
  const params = normalizeEvent(toolCall);
  assert.equal("parameters" in params, false);
  assert.ok(!JSON.stringify(params).includes("SECRET-VALUE"));
  assert.deepEqual(params.redacted, ["parameters"]);

  const p = normalizeEvent(prompt);
  assert.equal("prompt" in p, false);
  assert.ok(!JSON.stringify(p).includes("hunter2"));

  const title = normalizeEvent(base({ event_type: "session.renamed", title: "Fix the payroll bug" }));
  assert.equal("title" in title, false);

  const failed = normalizeEvent(base({ event_type: "tool.completed", tool_call_id: "t1", duration_ms: 5, status: "error", response_bytes: 0, error_message: "token abc123 rejected" }));
  assert.equal("error_message" in failed, false);
  assert.ok(!JSON.stringify(failed).includes("abc123"));

  const denied = normalizeEvent(base({ event_type: "permission.denied", tool_name: "Bash", mcp_server: "builtin", parameters: { command: "rm x" }, reason: "blocked rm x" }));
  assert.deepEqual(denied.redacted, ["parameters", "reason"]);
});

test("MUST: metadata and findings are exported by default", () => {
  const n = normalizeEvent(toolCall);
  assert.equal(n.export_schema, EXPORT_SCHEMA);
  assert.equal(n.tool_name, "Bash");
  assert.equal(n.mcp_server, "builtin");
  assert.equal(n.session_id, "s1");
  assert.equal("schema_version" in n, false);

  const f = normalizeEvent(finding);
  assert.equal(f.severity, "HIGH");
  assert.equal(f.description, "Sent a credential file to a new host");
  assert.equal(f.redacted, undefined);
});

test("MUST: --include puts back only the groups named", () => {
  const withParams = normalizeEvent(toolCall, parseInclude("parameters").groups);
  assert.deepEqual(withParams.parameters, { command: "echo SECRET-VALUE" });
  assert.equal(withParams.redacted, undefined);
  // Another group stays out.
  assert.equal("prompt" in normalizeEvent(prompt, parseInclude("parameters").groups), false);
  assert.equal(normalizeEvent(prompt, parseInclude("all").groups).prompt, prompt.prompt);
  assert.ok(parseInclude("nonsense").error);
  assert.ok(parseInclude("prompts, titles").groups.has("titles"));
});

test("OCSF MUST: a tool call is API Activity with the tool and server", () => {
  const o = toOcsf(normalizeEvent(toolCall));
  assert.equal(o.class_uid, 6003);
  assert.equal(o.category_uid, 6);
  assert.equal(o.type_uid, 600399);
  assert.equal(o.api.operation, "Bash");
  assert.equal(o.api.service.name, "builtin");
  assert.equal(o.time, Date.parse(toolCall.occurred_at));
  assert.equal(o.metadata.version, OCSF_VERSION);
  assert.equal(o.metadata.uid, "e1");
  assert.equal(o.actor.session.uid, "s1");
  assert.equal(o.unmapped.cwd, "/home/case/repo");
  assert.equal(o.unmapped.platform, "claude-code");
});

test("OCSF MUST_NOT: redacted content never reaches the OCSF record", () => {
  const o = toOcsf(normalizeEvent(toolCall));
  assert.ok(!JSON.stringify(o).includes("SECRET-VALUE"));
  assert.deepEqual(o.unmapped.redacted, ["parameters"]);
  const p = toOcsf(normalizeEvent(prompt));
  assert.ok(!JSON.stringify(p).includes("hunter2"));
  // Asked for, the parameters appear under unmapped.
  const inc = toOcsf(normalizeEvent(toolCall, parseInclude("parameters").groups));
  assert.deepEqual(inc.unmapped.parameters, { command: "echo SECRET-VALUE" });
});

test("OCSF MUST: a finding is a Detection Finding with severity and rule", () => {
  const o = toOcsf(normalizeEvent(finding));
  assert.equal(o.class_uid, 2004);
  assert.equal(o.activity_id, 1);
  assert.equal(o.severity_id, 4);
  assert.equal(o.severity, "High");
  assert.equal(o.finding_info.analytic.name, "rule-1");
  assert.equal(o.finding_info.title, "exfiltration");
  assert.equal(o.finding_info.desc, "Sent a credential file to a new host");
  assert.deepEqual(o.finding_info.related_events.map((r) => r.uid), ["t1", "t0"]);
  for (const [sev, id] of [["LOW", 2], ["MEDIUM", 3], ["HIGH", 4], ["CRITICAL", 5]]) {
    assert.equal(toOcsf(normalizeEvent({ ...finding, severity: sev })).severity_id, id);
  }
});

test("OCSF MUST: file reads and writes are File System Activity", () => {
  const read = toOcsf(normalizeEvent(base({ event_type: "file.read", path: "/home/case/.aws/credentials", bytes: 120 })));
  assert.equal(read.class_uid, 1001);
  assert.equal(read.activity_id, 2);
  assert.equal(read.file.path, "/home/case/.aws/credentials");
  assert.equal(read.file.name, "credentials");
  assert.equal(read.file.size, 120);
  const write = toOcsf(normalizeEvent(base({ event_type: "file.written", path: "C:\\Users\\case\\a.txt", bytes: 3 })));
  assert.equal(write.activity_id, 3);
  assert.equal(write.file.name, "a.txt");
});

test("OCSF MUST: tool results carry status, and sessions are lifecycle events", () => {
  const ok = toOcsf(normalizeEvent(base({ event_type: "tool.completed", tool_call_id: "t1", duration_ms: 5, status: "success", response_bytes: 9 })));
  assert.equal(ok.status_id, 1);
  assert.equal(ok.api.request.uid, "t1");
  const bad = toOcsf(normalizeEvent(base({ event_type: "tool.completed", tool_call_id: "t1", duration_ms: 5, status: "error", response_bytes: 0 })));
  assert.equal(bad.status_id, 2);
  const start = toOcsf(normalizeEvent(base({ event_type: "session.started", user: "case", project_path: "/home/case/repo", mcp_servers: ["a"], model: "m1" })));
  assert.equal(start.class_uid, 6002);
  assert.equal(start.activity_id, 3);
  assert.equal(start.actor.user.name, "case");
  assert.equal(start.unmapped.model, "m1");
  const end = toOcsf(normalizeEvent(base({ event_type: "session.ended", duration_ms: 9, status: "errored" })));
  assert.equal(end.activity_id, 4);
  assert.equal(end.status_id, 2);
});

test("OCSF MUST: other event types become Base Events that keep their data", () => {
  const o = toOcsf(normalizeEvent(base({ event_type: "capture.paused", kind: "record" })));
  assert.equal(o.class_uid, 0);
  assert.equal(o.activity_name, "capture.paused");
  assert.equal(o.unmapped.omnodex_event_type, "capture.paused");
  assert.equal(o.unmapped.data.kind, "record");
});

test("time arguments take dates and ages; windows are half open", () => {
  const now = Date.parse("2026-11-06T12:00:00Z");
  assert.equal(parseTimeArg("24h", now), now - 86_400_000);
  assert.equal(parseTimeArg("7d", now), now - 7 * 86_400_000);
  assert.equal(parseTimeArg("2026-11-01", now), Date.parse("2026-11-01"));
  assert.equal(parseTimeArg("soon", now), undefined);
  const at = Date.parse(toolCall.occurred_at);
  assert.equal(inWindow(toolCall, at, undefined), true);
  assert.equal(inWindow(toolCall, at + 1, undefined), false);
  assert.equal(inWindow(toolCall, undefined, at), false);
  assert.equal(inWindow(toolCall, undefined, at + 1), true);
});
