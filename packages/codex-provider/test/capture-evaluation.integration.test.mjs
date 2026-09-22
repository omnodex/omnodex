// Validation: the Codex hook shim judges each tool call it captures against
// the per-event rules, and never fails the hook doing so.
//
// Run: node --test packages/codex-provider/test/capture-evaluation.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { captureEvaluationCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const preToolUse = (sessionId, command) => ({
  payload: {
    session_id: sessionId,
    cwd: "/tmp/repo",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_use_id: `tu-${sessionId}`,
    tool_input: { command },
  },
});

captureEvaluationCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/codex-hook-shim.js"),
  interceptor: "codex-hook",
  sensitiveRead: (id) => preToolUse(id, "cat /etc/shadow"),
  harmlessCall: (id) => preToolUse(id, "ls -la"),
  checkResult: (result) => assert.equal(result.stdout, "", "the shim writes nothing to stdout"),
});
