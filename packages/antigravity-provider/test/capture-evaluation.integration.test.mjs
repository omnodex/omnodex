// Validation: the Antigravity hook shim judges each tool call it captures
// against the per-event rules, and never fails the hook doing so.
//
// Run: node --test packages/antigravity-provider/test/capture-evaluation.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { captureEvaluationCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const preToolUse = (conversationId, command) => ({
  args: ["PreToolUse"],
  payload: {
    conversationId,
    workspacePaths: ["/tmp/repo"],
    transcriptPath: "/tmp/transcript.jsonl",
    artifactDirectoryPath: "/tmp/artifacts",
    stepIdx: 1,
    toolCall: { name: "run_command", args: { CommandLine: command } },
  },
});

captureEvaluationCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/antigravity-hook-shim.js"),
  interceptor: "antigravity-hook",
  sensitiveRead: (id) => preToolUse(id, "cat /etc/shadow"),
  harmlessCall: (id) => preToolUse(id, "ls -la"),
  // Evaluation must not change the hook's answer.
  checkResult: (result) => assert.deepEqual(JSON.parse(result.stdout), { decision: "allow" }),
});
