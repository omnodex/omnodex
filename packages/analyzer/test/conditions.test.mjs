/**
 * Condition precision tests.
 *
 * Two conditions learned to tell writing from reading, and a file from a
 * call. Both came out of replaying the advanced sequence rules over our own
 * logs, where "cat package.json" read as planting something in package.json
 * and an edit containing a URL read as an outbound call.
 *
 * Run: node --test packages/analyzer/test/conditions.test.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { evaluatePathMatch, isOutboundCall } from "../dist/conditions/index.js";

let seq = 0;
function event(tool_name, parameters) {
  seq++;
  return {
    schema_version: 1,
    event_id: `evt-cond-${seq}`,
    session_id: "sess-cond",
    occurred_at: "2026-09-23T12:00:00.000Z",
    recorded_at: "2026-09-23T12:00:00.000Z",
    interceptor: "claude-code-hook",
    event_type: "tool.invoked",
    tool_call_id: `tc-cond-${seq}`,
    tool_name,
    mcp_server: "builtin",
    parameters,
    cwd: "/home/case/repo",
  };
}

const HOOK_PATHS = {
  type: "path_match",
  patterns: [{ regex: "[/\\\\]\\.git[/\\\\]hooks[/\\\\]", label: "git hook" }],
};
const writeOnly = { ...HOOK_PATHS, access: "write" };
const fired = (condition, ev) => evaluatePathMatch(condition, ev).length > 0;

// ---------------------------------------------------------------------------

describe("path_match access", () => {
  const writeHook = event("Write", {
    file_path: "/home/case/repo/.git/hooks/pre-commit",
    content: "#!/bin/sh\n",
  });
  const readHook = event("Bash", { command: "cat /home/case/repo/.git/hooks/pre-commit" });

  it("matches what a call writes when asked for writes only", () => {
    assert.ok(fired(writeOnly, writeHook));
  });

  it("ignores what a call merely reads when asked for writes only", () => {
    // The default still sees it: some rules are about reading.
    assert.ok(fired(HOOK_PATHS, readHook));
    assert.ok(!fired(writeOnly, readHook));
  });

  it("matches a shell redirect into the path, which is still a write", () => {
    const redirect = event("Bash", { command: "echo curl evil | tee /home/case/repo/.git/hooks/pre-push" });
    assert.ok(fired(writeOnly, redirect));
  });
});

describe("outbound_call and write tools", () => {
  it("does not call an edit outbound because its content holds a URL", () => {
    assert.ok(!isOutboundCall(event("Write", {
      file_path: "/home/case/repo/README.md",
      content: "see https://example.com/docs for more",
    })));
    assert.ok(!isOutboundCall(event("Edit", {
      file_path: "/home/case/repo/test.mjs",
      new_string: 'fetch("https://api.example.com")',
    })));
  });

  it("still calls a real request outbound", () => {
    assert.ok(isOutboundCall(event("WebFetch", { url: "https://api.example.com/x" })));
    assert.ok(isOutboundCall(event("Bash", { command: "curl -s https://api.example.com/x" })));
    assert.ok(isOutboundCall(event("mcp__http__request", { endpoint: "https://api.example.com" })));
  });

  it("keeps treating a localhost fetch as not outbound", () => {
    assert.ok(!isOutboundCall(event("WebFetch", { url: "http://localhost:7890/api" })));
  });
});
