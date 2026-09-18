import { test } from "node:test";
import * as assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { splitMcpToolName, mapClaudeCodePayload } from "../dist/index.js";

/**
 * Freezes the measured tool-name mapping.
 *
 * How an agent treats a tool name it cannot represent is undocumented and
 * version-dependent, so the fixture records what was actually observed and
 * these assertions hold the code to it. If a platform changes behaviour, this
 * fails rather than events quietly failing to correlate.
 *
 * See scripts/capture-tool-name-mapping.md to re-measure.
 */

const fixture = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("./fixtures/tool-name-mapping.json", import.meta.url)),
    "utf8",
  ),
);

const claudeCapture = fixture.captures.find(
  (c) => c.platform === "claude-code" && Array.isArray(c.tools),
);

test("the fixture still describes claude-code", () => {
  assert.ok(claudeCapture, "expected a claude-code capture with tools");
  assert.equal(claudeCapture.proxy_tool_name_separator, "__");
});

test("splitting agrees with every captured name that reached the model", () => {
  for (const tool of claudeCapture.tools) {
    if (!tool.reaches_model) continue;
    const split = splitMcpToolName(tool.model_visible_name);
    assert.ok(split, `expected to split ${tool.model_visible_name}`);
    assert.equal(split.mcpServer, "omnodex");
    assert.equal(
      split.upstreamToolName,
      tool.proxy_tool_name,
      "the tool half must be exactly the name the proxy offered, so the two " +
        "observations of one call can be matched",
    );
  }
});

test("a name the agent dropped has no model-visible form to map", () => {
  // Recorded so the absence stays deliberate: '.' and '/' are not rewritten
  // into something callable, the tool simply never appears.
  const dropped = claudeCapture.tools.filter((t) => !t.reaches_model);
  assert.ok(dropped.length > 0, "fixture should record at least one dropped name");
  for (const tool of dropped) {
    assert.equal(tool.model_visible_name, null);
  }
});

test("a server name containing underscores is attributed to the server, not builtin", () => {
  // The regression that sent every plugin-provided MCP tool to "builtin".
  const split = splitMcpToolName(
    "mcp__plugin_omnodex-cowork_omnodex__filesystem__read_text_file",
  );
  assert.deepEqual(split, {
    mcpServer: "plugin_omnodex-cowork_omnodex",
    upstreamToolName: "filesystem__read_text_file",
  });
});

test("the mapper records that server on the event", () => {
  const events = mapClaudeCodePayload(
    {
      hook_event_name: "PreToolUse",
      session_id: "sess_map",
      cwd: "/home/case/repo",
      tool_name: "mcp__plugin_omnodex-cowork_omnodex__filesystem__read_text_file",
      tool_input: { path: "/home/case/repo/a.md" },
      tool_use_id: "toolu_map",
    },
    { newEventId: () => "e1", nowIso: () => "2026-09-18T12:00:00.000Z" },
  );

  assert.equal(events.length, 1);
  assert.equal(events[0].mcp_server, "plugin_omnodex-cowork_omnodex");
});

test("built-in and malformed names stay builtin", () => {
  assert.equal(splitMcpToolName("Bash"), null);
  assert.equal(splitMcpToolName("mcp__"), null);
  assert.equal(splitMcpToolName("mcp__server"), null);
  assert.equal(splitMcpToolName("mcp____tool"), null, "empty server half");
  assert.equal(splitMcpToolName("mcp__server__"), null, "empty tool half");
});

test("a direct MCP tool still splits into server and tool", () => {
  // Not every MCP tool is proxied. The single-underscore server name here is
  // the common case and must keep working.
  assert.deepEqual(splitMcpToolName("mcp__plane__workitem"), {
    mcpServer: "plane",
    upstreamToolName: "workitem",
  });
});
