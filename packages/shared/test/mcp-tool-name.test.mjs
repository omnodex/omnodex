import { test } from "node:test";
import assert from "node:assert/strict";
import { splitMcpToolName } from "../dist/index.js";

test("MUST_FIRE: splits MCP names with underscores in the server", () => {
  assert.deepEqual(
    splitMcpToolName("mcp__codex_apps__plane__workitem"),
    {
      mcpServer: "codex_apps",
      upstreamToolName: "plane__workitem",
    },
  );
  assert.deepEqual(
    splitMcpToolName("mcp__server_with_underscores__read_file"),
    {
      mcpServer: "server_with_underscores",
      upstreamToolName: "read_file",
    },
  );
});

test("MUST_NOT_FIRE: rejects builtins and incomplete MCP names", () => {
  for (const toolName of ["Bash", "mcp__", "mcp____tool", "mcp__server__"]) {
    assert.equal(splitMcpToolName(toolName), null, toolName);
  }
});
