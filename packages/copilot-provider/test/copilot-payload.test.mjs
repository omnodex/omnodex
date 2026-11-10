// The Copilot payload normalizer and mapper: both payload namings, every
// recorded event, and the labels the events carry.
//
// Run: node --test packages/copilot-provider/test/copilot-payload.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { mapCopilotPayload, normalizeCopilotPayload, sessionEndStatus, shellExitCode } from "../dist/copilot-payload.js";
import { copilotDecision } from "../dist/decision.js";

let n = 0;
const opts = (extra = {}) => ({ newEventId: () => `evt-${++n}`, nowIso: () => "2026-11-06T12:00:00.000Z", ...extra });
const map = (raw, extra) => {
  const payload = normalizeCopilotPayload(raw);
  assert.ok(payload, "payload should normalize");
  return mapCopilotPayload(payload, opts(extra));
};

const base = { session_id: "s1", cwd: "/home/case/repo", timestamp: "2026-11-06T11:59:00.000Z" };

test("every event carries the Copilot interceptor and platform, and the payload's own time", () => {
  const [started] = map({ ...base, hook_event_name: "SessionStart", source: "startup" });
  assert.equal(started.event_type, "session.started");
  assert.equal(started.interceptor, "copilot-hook");
  assert.equal(started.platform, "copilot");
  assert.equal(started.project_path, "/home/case/repo");
  assert.equal(started.occurred_at, "2026-11-06T11:59:00.000Z");
});

test("a tool call: PreToolUse invokes, PostToolUse completes with the call id and duration", () => {
  const input = { command: "ls -la" };
  const [invoked] = map({ ...base, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: input }, { callId: "call-1" });
  assert.equal(invoked.event_type, "tool.invoked");
  assert.equal(invoked.tool_call_id, "call-1");
  assert.equal(invoked.tool_name, "Bash");
  assert.deepEqual(invoked.parameters, input);

  const done = map({
    ...base, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: input,
    tool_result: { result_type: "success", text_result_for_llm: "total 0" },
  }, { callId: "call-1", durationMs: 42 });
  const completed = done.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.tool_call_id, "call-1");
  assert.equal(completed.status, "success");
  assert.equal(completed.duration_ms, 42);
  assert.ok(done.every((e) => e.interceptor === "copilot-hook" && e.platform === "copilot"));
});

test("a failed call completes with status error and the message", () => {
  const [completed] = map({ ...base, hook_event_name: "PostToolUseFailure", tool_name: "Bash", tool_input: { command: "false" }, error: "exit 1" }, { callId: "c" });
  assert.equal(completed.event_type, "tool.completed");
  assert.equal(completed.status, "error");
  assert.equal(completed.error_message, "exit 1");
});

test("file reads and writes keep their file events (Claude tool names under a PascalCase registration)", () => {
  const read = map({ ...base, hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: "/home/case/repo/a.txt" }, tool_result: "x" }, { callId: "c" });
  assert.equal(read.find((e) => e.event_type === "file.read").path, "/home/case/repo/a.txt");
  const write = map({ ...base, hook_event_name: "PostToolUse", tool_name: "Edit", tool_input: { file_path: "/home/case/repo/b.txt", new_string: "hi" }, tool_result: "x" }, { callId: "c" });
  assert.equal(write.find((e) => e.event_type === "file.written").path, "/home/case/repo/b.txt");
});

test("an MCP tool is attributed to its server", () => {
  const [invoked] = map({ ...base, hook_event_name: "PreToolUse", tool_name: "mcp__github__list_issues", tool_input: {} }, { callId: "c" });
  assert.equal(invoked.mcp_server, "github");
});

test("prompts, permission requests and subagents", () => {
  const [prompt] = map({ ...base, hook_event_name: "UserPromptSubmit", prompt: "fix the bug" });
  assert.equal(prompt.event_type, "prompt.submitted");
  assert.equal(prompt.prompt, "fix the bug");

  const [asked] = map({ ...base, hook_event_name: "PermissionRequest", tool_name: "Bash", tool_input: { command: "rm x" } });
  assert.equal(asked.event_type, "permission.requested");

  const [start] = map({ ...base, hook_event_name: "SubagentStart", agent_id: "a1", agent_name: "explore" });
  assert.equal(start.event_type, "subagent.started");
  assert.equal(start.agent_id, "a1");
  const [stop] = map({ ...base, hook_event_name: "SubagentStop", agent_id: "a1", agent_type: "explore", last_assistant_message: "done" });
  assert.equal(stop.event_type, "subagent.stopped");
  assert.equal(stop.response_bytes, 4);
  // A subagent start without an id falls back to the agent's name.
  const [byName] = map({ ...base, hook_event_name: "SubagentStart", agent_name: "reviewer" });
  assert.equal(byName.agent_id, "reviewer");
});

test("work inside a subagent is attributed to it", () => {
  const [invoked] = map({ ...base, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: {}, agent_id: "a9" }, { callId: "c" });
  assert.equal(invoked.agent_id, "a9");
});

test("session end maps Copilot's reasons", () => {
  assert.equal(sessionEndStatus("complete"), "completed");
  assert.equal(sessionEndStatus("error"), "errored");
  assert.equal(sessionEndStatus("timeout"), "errored");
  assert.equal(sessionEndStatus("abort"), "interrupted");
  assert.equal(sessionEndStatus("user_exit"), "interrupted");
  assert.equal(sessionEndStatus(undefined), "completed");
  const [ended] = map({ ...base, hook_event_name: "SessionEnd", reason: "user_exit" });
  assert.equal(ended.event_type, "session.ended");
  assert.equal(ended.status, "interrupted");
});

test("the end of a turn is not the end of the session", () => {
  assert.deepEqual(map({ ...base, hook_event_name: "Stop", stop_reason: "end_turn" }), []);
});

test("the camelCase naming normalizes to the same payload", () => {
  const p = normalizeCopilotPayload({
    event: "preToolUse", sessionId: "s2", timestamp: Date.parse("2026-11-06T11:00:00.000Z"), cwd: "/r",
    toolName: "bash", toolArgs: '{"command":"pwd"}',
  });
  assert.equal(p.event, "PreToolUse");
  assert.equal(p.sessionId, "s2");
  assert.equal(p.toolName, "bash");
  assert.deepEqual(p.toolInput, { command: "pwd" });
  assert.equal(p.timestamp, "2026-11-06T11:00:00.000Z");
  // Tool input given as plain text is kept as the command.
  assert.deepEqual(normalizeCopilotPayload({ hook_event_name: "PreToolUse", session_id: "s", tool_name: "bash", tool_input: "echo hi" }).toolInput, { command: "echo hi" });
});

test("a payload Omnodex does not record is refused, never thrown on", () => {
  for (const bad of [null, undefined, 5, "x", [], {}, { hook_event_name: "PreToolUse" }, { session_id: "s" }, { hook_event_name: "Notification", session_id: "s" }]) {
    assert.equal(normalizeCopilotPayload(bad), null, JSON.stringify(bad));
  }
  // A tool event without a tool name maps to nothing.
  assert.deepEqual(map({ ...base, hook_event_name: "PreToolUse", tool_input: {} }), []);
});

test("the decision is repeated at the top level for readers of the CLI form", () => {
  const out = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "blocked" } };
  const d = copilotDecision(out);
  assert.equal(d.permissionDecision, "deny");
  assert.equal(d.permissionDecisionReason, "blocked");
  assert.deepEqual(d.hookSpecificOutput, out.hookSpecificOutput);
  assert.equal(copilotDecision(null), undefined);
  assert.deepEqual(copilotDecision({ other: 1 }), { other: 1 });
});

// Payload shapes sent by Copilot CLI 1.0.108 (paths and ids redacted).
const cli108 = {
  sessionId: "6d9ef4f3-9d3a-4d51-bc22-b834a889100a",
  timestamp: 1794320170381,
  cwd: "/home/case/proj",
  transcriptPath: "/home/case/.copilot/session-state/6d9ef4f3/events.jsonl",
  agentName: "task",
  agent_id: "2567cb6c-f2fa-47c3-b056-39b4508cdec7",
  agent_type: "task",
  parent_agent_id: "6d9ef4f3-9d3a-4d51-bc22-b834a889100a",
};

test("MUST_FIRE: a 1.0.108 subagent start, which carries no event name, is recorded", () => {
  const p = normalizeCopilotPayload(cli108);
  assert.equal(p.event, "SubagentStart");
  const [started] = map(cli108);
  assert.equal(started.event_type, "subagent.started");
  assert.equal(started.agent_id, "2567cb6c-f2fa-47c3-b056-39b4508cdec7");
  assert.equal(started.platform, "copilot");
  assert.equal(started.session_id, "6d9ef4f3-9d3a-4d51-bc22-b834a889100a");
  assert.equal(started.occurred_at, new Date(1794320170381).toISOString());
  // Either naming, and a name alone is enough to identify the kind of agent.
  assert.equal(normalizeCopilotPayload({ sessionId: "s", agentId: "a", agentName: "explore" }).event, "SubagentStart");
  assert.equal(normalizeCopilotPayload({ session_id: "s", agent_id: "a", agent_type: "task" }).event, "SubagentStart");
});

test("MUST_NOT_FIRE: an unnamed payload is not a subagent start unless it has the subagent shape", () => {
  // No session, or no agent id, or neither a name nor a type.
  for (const bad of [
    { ...cli108, sessionId: undefined },
    { ...cli108, agent_id: undefined },
    { ...cli108, agentName: undefined, agent_type: undefined },
    // Fields of other events: a tool call, a prompt, a subagent stop, a session end.
    { ...cli108, tool_name: "Bash" },
    { ...cli108, toolName: "bash", toolArgs: "{}" },
    { ...cli108, prompt: "hi" },
    { ...cli108, last_assistant_message: "done" },
    { ...cli108, reason: "complete" },
  ]) assert.equal(normalizeCopilotPayload(bad), null, JSON.stringify(bad));
  // A named event that is not recorded stays unrecorded, whatever else it carries.
  assert.equal(normalizeCopilotPayload({ ...cli108, hook_event_name: "Notification" }), null);
  // A named subagent stop keeps its own name.
  assert.equal(normalizeCopilotPayload({ ...cli108, hook_event_name: "SubagentStop" }).event, "SubagentStop");
});

const shellCall = { ...base, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "cat missing-file.txt", mode: "sync" } };
const shellResult = (text) => ({ result_type: "success", text_result_for_llm: text });

test("MUST_FIRE: a shell call that exits non-zero completes with status error", () => {
  const done = map({ ...shellCall, tool_use_id: "call_1", tool_result: shellResult("cat: missing-file.txt: No such file or directory\n<shellId: 0 completed with exit code 1>") }, { callId: "call_1" });
  const completed = done.find((e) => e.event_type === "tool.completed");
  assert.equal(completed.status, "error");
  assert.equal(completed.error_message, "Command exited with code 1");
  assert.equal(completed.tool_call_id, "call_1");
  assert.equal(completed.platform, "copilot");
  // Negative codes (killed by a signal) and trailing whitespace count too.
  assert.equal(shellExitCode("Bash", shellResult("x\n<shellId: 3 completed with exit code -1>\n")), -1);
  assert.equal(shellExitCode("powershell", "out\n<shellId: 0 completed with exit code 127>"), 127);
});

test("MUST_NOT_FIRE: exit code 0, other tools and ordinary text stay successful", () => {
  const ok = map({ ...shellCall, tool_result: shellResult("hi\n<shellId: 0 completed with exit code 0>") }, { callId: "c" });
  assert.equal(ok.find((e) => e.event_type === "tool.completed").status, "success");
  // Older Copilot versions put no exit code in the text.
  const old = map({ ...shellCall, tool_result: "hi" }, { callId: "c" });
  assert.equal(old.find((e) => e.event_type === "tool.completed").status, "success");
  // A file whose text happens to end that way, read by a non-shell tool.
  const read = map({ ...base, hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: "/home/case/a.txt" }, tool_result: shellResult("<shellId: 0 completed with exit code 2>") }, { callId: "c" });
  assert.equal(read.find((e) => e.event_type === "tool.completed").status, "success");
  // The words in the middle of the output are not the closing line.
  assert.equal(shellExitCode("Bash", shellResult("exit code 2> then more output")), undefined);
  assert.equal(shellExitCode("Bash", undefined), undefined);
  assert.equal(shellExitCode(undefined, shellResult("<shellId: 0 completed with exit code 1>")), undefined);
});
