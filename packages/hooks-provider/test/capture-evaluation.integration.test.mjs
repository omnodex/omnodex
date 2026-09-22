// Validation: the Claude Code hook shim judges each tool call it captures
// against the per-event rules, and never fails the hook doing so.
//
// Run: node --test packages/hooks-provider/test/capture-evaluation.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { captureEvaluationCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const preToolUse = (sessionId, toolInput) => ({
  payload: {
    session_id: sessionId,
    cwd: "/tmp/repo",
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_use_id: `tu-${sessionId}`,
    tool_input: toolInput,
  },
});

captureEvaluationCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/claude-hook-shim.js"),
  interceptor: "claude-code-hook",
  sensitiveRead: (id) => preToolUse(id, { file_path: "/etc/shadow" }),
  harmlessCall: (id) => preToolUse(id, { file_path: "/tmp/repo/README.md" }),
  checkResult: (result) => assert.equal(result.stdout, "", "the shim writes nothing to stdout"),
});
