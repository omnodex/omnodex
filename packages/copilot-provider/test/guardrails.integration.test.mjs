// Validation: in guardrails mode the Copilot shim hands preToolUse to the
// guardrails module and prints its answer; otherwise it prints no decision.
//
// Run: node --test packages/copilot-provider/test/guardrails.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { guardrailsCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

guardrailsCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/copilot-hook-shim.js"),
  sensitiveRead: (id) => ({
    payload: { session_id: id, cwd: "/tmp/repo", hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/etc/shadow" } },
  }),
  // A PascalCase registration gets the same answer shape as Claude Code.
  host: "claude-code",
  passOutput: "{}",
});
