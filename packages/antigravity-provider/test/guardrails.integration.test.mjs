// Validation: in guardrails mode the Antigravity shim hands PreToolUse to the
// guardrails module and writes its answer; otherwise it answers allow, which
// defers to Antigravity's own permission policy.
//
// Run: node --test packages/antigravity-provider/test/guardrails.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { guardrailsCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

guardrailsCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/antigravity-hook-shim.js"),
  sensitiveRead: (id) => ({
    args: ["PreToolUse"],
    payload: {
      conversationId: id, workspacePaths: ["/tmp/repo"], transcriptPath: "/tmp/transcript.jsonl",
      artifactDirectoryPath: "/tmp/artifacts", stepIdx: 1,
      toolCall: { name: "run_command", args: { CommandLine: "cat /etc/shadow" } },
    },
  }),
  host: "antigravity",
  // Antigravity needs an answer: "allow" defers to its own policy.
  passOutput: JSON.stringify({ decision: "allow" }),
});
