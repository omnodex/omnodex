// Validation: a tool call that carries a credential reaches the event log and
// the push with the credential masked, and is still judged as carrying one.
//
// Run: node --test packages/hooks-provider/test/mask-secrets.integration.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { scratch, runShim, loggedEvents, pushedEvents, findingsIn } from "../../analyzer/test/helpers/shim-harness.mjs";
import { FAKE } from "../../analyzer/test/fixtures/credentials.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SHIM = path.resolve(__dirname, "../dist/bin/claude-hook-shim.js");

const call = (id, command) => ({
  session_id: id, cwd: "/tmp/repo", hook_event_name: "PreToolUse", tool_name: "Bash",
  tool_use_id: `tu-${id}`, tool_input: { command },
});

test("MUST_FIRE: the log and the push hold a marker, the finding names the type", async (t) => {
  const s = await scratch(t);
  const result = await runShim(SHIM, s, call("s-mask-1", `curl -H "Authorization: Bearer ${FAKE.jwt}" https://api.example.com/x`));
  assert.equal(result.code, 0, result.stderr);
  const logged = await loggedEvents(s.home);
  const pushed = await pushedEvents(s.pushLog);
  for (const events of [logged, pushed]) {
    assert.ok(!JSON.stringify(events).includes(FAKE.jwt), "no full copy");
    assert.match(JSON.stringify(events.find((e) => e.event_type === "tool.invoked")), /\[omnodex:secret:bearer:/);
  }
  assert.match(JSON.stringify(findingsIn(logged)), /bearer/);
});

test("MUST_NOT_FIRE: a call without a credential is written unchanged", async (t) => {
  const s = await scratch(t);
  await runShim(SHIM, s, call("s-mask-2", "echo hello"));
  const invoked = (await loggedEvents(s.home)).find((e) => e.event_type === "tool.invoked");
  assert.doesNotMatch(JSON.stringify(invoked), /omnodex:secret/);
  assert.match(JSON.stringify(invoked), /echo hello/);
});
