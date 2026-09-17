#!/usr/bin/env node
/**
 * mock-mcp-server.mjs
 *
 * A minimal MCP server that speaks the real MCP protocol over stdio.
 * Used by upstream-client.test.mjs to exercise UpstreamClientPool without
 * needing a real installed MCP server.
 *
 * Configuration via env vars (all optional):
 *   MOCK_SERVER_NAME    reported in serverInfo (default: "mock")
 *   MOCK_TOOLS          JSON array of tool names to expose (default: 3 tools)
 *   MOCK_RESULT_TEXT    text to return from every tools/call (default: "ok")
 *   MOCK_ERROR          if "1", every tools/call returns isError:true
 *   MOCK_STRUCTURED     if "1", tools declare an outputSchema and return
 *                       structuredContent alongside the text content
 *   MOCK_FAIL_STARTUP   if "1", exit with code 1 before speaking MCP
 *   MOCK_STARTUP_DELAY_MS  wait this long before speaking MCP
 *   MOCK_EXIT_AFTER_MS  exit this long after connecting (simulates a crash)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

if (process.env.MOCK_FAIL_STARTUP === "1") {
  process.stderr.write("mock server: startup failure\n");
  process.exit(1);
}

const startupDelayMs = Number(process.env.MOCK_STARTUP_DELAY_MS ?? 0);
if (startupDelayMs > 0) {
  await new Promise((resolve) => setTimeout(resolve, startupDelayMs));
}

const name = process.env.MOCK_SERVER_NAME ?? "mock";
const resultText = process.env.MOCK_RESULT_TEXT ?? "ok";
const returnError = process.env.MOCK_ERROR === "1";
const structured = process.env.MOCK_STRUCTURED === "1";

const defaultTools = ["read_file", "write_file", "list_dir"];
let tools;
try {
  tools = process.env.MOCK_TOOLS
    ? JSON.parse(process.env.MOCK_TOOLS)
    : defaultTools;
} catch {
  tools = defaultTools;
}

const server = new McpServer({ name, version: "0.0.0" });

for (const toolName of tools) {
  if (structured) {
    server.registerTool(
      toolName,
      {
        description: `Mock tool: ${toolName}`,
        inputSchema: { input: z.string().optional() },
        outputSchema: { content: z.string() },
      },
      async ({ input }) => {
        const text = `${resultText}:${toolName}:${input ?? ""}`;
        return {
          content: [{ type: "text", text }],
          structuredContent: { content: text },
        };
      }
    );
    continue;
  }
  server.tool(
    toolName,
    `Mock tool: ${toolName}`,
    { input: z.string().optional() },
    async ({ input }) => {
      if (returnError) {
        return {
          content: [{ type: "text", text: `error from ${toolName}` }],
          isError: true,
        };
      }
      return {
        content: [{ type: "text", text: `${resultText}:${toolName}:${input ?? ""}` }],
      };
    }
  );
}

const transport = new StdioServerTransport();
await server.connect(transport);

const exitAfterMs = Number(process.env.MOCK_EXIT_AFTER_MS ?? 0);
if (exitAfterMs > 0) {
  setTimeout(() => process.exit(0), exitAfterMs);
}
