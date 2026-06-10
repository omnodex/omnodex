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
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const name = process.env.MOCK_SERVER_NAME ?? "mock";
const resultText = process.env.MOCK_RESULT_TEXT ?? "ok";
const returnError = process.env.MOCK_ERROR === "1";

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
