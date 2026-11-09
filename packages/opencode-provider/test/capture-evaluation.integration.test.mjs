// Validation: the OpenCode hook shim judges each tool call it captures against
// the per-event rules, and never fails the hook doing so.
//
// Run: node --test packages/opencode-provider/test/capture-evaluation.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { captureEvaluationCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const preToolUse = (sessionId, command) => ({
  payload: {
    event: "tool.before",
    session_id: sessionId,
    cwd: "/tmp/repo",
    tool: "bash",
    call_id: `c-${sessionId}`,
    args: { command },
  },
});

captureEvaluationCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/opencode-plugin-shim.js"),
  interceptor: "opencode-plugin",
  sensitiveRead: (id) => preToolUse(id, "cat /etc/shadow"),
  harmlessCall: (id) => preToolUse(id, "ls -la"),
  // OpenCode reads stdout as the hook's answer: always one JSON document, {} for no decision.
  checkResult: (result) => assert.equal(result.stdout, "{}"),
});
