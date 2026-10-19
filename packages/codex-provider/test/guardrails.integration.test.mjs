// Validation: in guardrails mode the Codex shim hands PreToolUse to the
// guardrails module and writes its answer to stdout.
//
// Run: node --test packages/codex-provider/test/guardrails.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { guardrailsCases } from "../../analyzer/test/helpers/shim-harness.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

guardrailsCases(test, assert, {
  shim: path.resolve(__dirname, "../dist/bin/codex-hook-shim.js"),
  sensitiveRead: (id) => ({
    payload: {
      session_id: id, cwd: "/tmp/repo", hook_event_name: "PreToolUse", tool_name: "Bash",
      tool_use_id: `tu-${id}`, tool_input: { command: "cat /etc/shadow" },
    },
  }),
  host: "codex",
});
