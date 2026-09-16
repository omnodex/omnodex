// Integration tests for UpstreamClientPool.
// Spawns a real mock MCP subprocess to exercise the full stdio round-trip.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import {
  UpstreamClientPool,
  McpToolNotFoundError,
  normalizeSchemaDialect,
} from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Returns a config that points at the mock MCP subprocess. */
function makeConfig(overrides = {}) {
  return ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: {
          MOCK_SERVER_NAME: "filesystem",
          MOCK_TOOLS: JSON.stringify(["read_file", "write_file", "list_dir"]),
          MOCK_RESULT_TEXT: "mock-result",
        },
        ...overrides,
      },
    ],
  });
}

/** Opens a pool, runs fn, then closes it. */
async function withPool(config, fn) {
  const pool = new UpstreamClientPool();
  await pool.connect(config);
  try {
    return await fn(pool);
  } finally {
    await pool.close();
  }
}

// ---------------------------------------------------------------------------
// Tool discovery
// ---------------------------------------------------------------------------

test("discovers tools from mock upstream with prefixed names", async () => {
  await withPool(makeConfig(), async (pool) => {
    const tools = pool.getTools();
    assert.equal(tools.length, 3);
    const names = tools.map((t) => t.prefixedName).sort();
    assert.deepEqual(names, [
      "filesystem__list_dir",
      "filesystem__read_file",
      "filesystem__write_file",
    ]);
  });
});

test("tool definition name matches prefixedName", async () => {
  await withPool(makeConfig(), async (pool) => {
    const tool = pool.getTools().find((t) => t.prefixedName === "filesystem__read_file");
    assert.ok(tool, "filesystem__read_file not found");
    assert.equal(tool.definition.name, "filesystem__read_file");
    assert.equal(tool.originalName, "read_file");
    assert.equal(tool.serverName, "filesystem");
  });
});

test("getServerName returns correct server for a prefixed tool", async () => {
  await withPool(makeConfig(), async (pool) => {
    assert.equal(pool.getServerName("filesystem__read_file"), "filesystem");
    assert.equal(pool.getServerName("filesystem__list_dir"), "filesystem");
  });
});

test("getServerName returns undefined for unknown tool", async () => {
  await withPool(makeConfig(), async (pool) => {
    assert.equal(pool.getServerName("unknown__tool"), undefined);
  });
});

// ---------------------------------------------------------------------------
// name_override prefix
// ---------------------------------------------------------------------------

test("name_override changes the tool name prefix", async () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: {
          MOCK_TOOLS: JSON.stringify(["read_file"]),
        },
        name_override: "fs",
      },
    ],
  });
  await withPool(cfg, async (pool) => {
    const names = pool.getTools().map((t) => t.prefixedName);
    assert.deepEqual(names, ["fs__read_file"]);
    assert.equal(pool.getServerName("fs__read_file"), "filesystem");
  });
});

// ---------------------------------------------------------------------------
// callTool routing
// ---------------------------------------------------------------------------

test("callTool routes to correct upstream and returns result", async () => {
  await withPool(makeConfig(), async (pool) => {
    const result = await pool.callTool("filesystem__read_file", { input: "hello" });
    assert.equal(result.isError, false);
    assert.equal(result.content.length, 1);
    const text = result.content[0].text;
    assert.ok(text.includes("mock-result"), `unexpected result: ${text}`);
    assert.ok(text.includes("read_file"), `unexpected result: ${text}`);
    assert.ok(text.includes("hello"), `unexpected result: ${text}`);
  });
});

test("callTool with a different tool in the same server", async () => {
  await withPool(makeConfig(), async (pool) => {
    const result = await pool.callTool("filesystem__list_dir", { input: "/tmp" });
    assert.equal(result.isError, false);
    assert.ok(result.content[0].text.includes("list_dir"));
  });
});

test("callTool throws McpToolNotFoundError for unknown prefixed name", async () => {
  await withPool(makeConfig(), async (pool) => {
    await assert.rejects(
      () => pool.callTool("filesystem__nonexistent_tool", {}),
      (err) => {
        assert.ok(err instanceof McpToolNotFoundError, `got: ${err.constructor.name}`);
        assert.match(err.message, /not found/i);
        assert.equal(err.prefixedName, "filesystem__nonexistent_tool");
        return true;
      }
    );
  });
});

test("callTool throws McpToolNotFoundError for entirely wrong server prefix", async () => {
  await withPool(makeConfig(), async (pool) => {
    await assert.rejects(
      () => pool.callTool("github__create_issue", {}),
      McpToolNotFoundError,
    );
  });
});

// ---------------------------------------------------------------------------
// isError forwarding
// ---------------------------------------------------------------------------

test("callTool forwards isError:true from upstream", async () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: {
          MOCK_TOOLS: JSON.stringify(["read_file"]),
          MOCK_ERROR: "1",
        },
      },
    ],
  });
  await withPool(cfg, async (pool) => {
    const result = await pool.callTool("filesystem__read_file", {});
    assert.equal(result.isError, true);
    assert.ok(result.content[0].text.includes("error"));
  });
});

// ---------------------------------------------------------------------------
// Multi-server pool
// ---------------------------------------------------------------------------

test("multi-server pool merges tools from both upstreams", async () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: { MOCK_TOOLS: JSON.stringify(["read_file"]) },
      },
      {
        name: "github",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: { MOCK_TOOLS: JSON.stringify(["create_issue", "list_prs"]) },
      },
    ],
  });
  await withPool(cfg, async (pool) => {
    const names = pool.getTools().map((t) => t.prefixedName).sort();
    assert.deepEqual(names, [
      "filesystem__read_file",
      "github__create_issue",
      "github__list_prs",
    ]);
    // Each routes to the right server
    assert.equal(pool.getServerName("filesystem__read_file"), "filesystem");
    assert.equal(pool.getServerName("github__create_issue"), "github");
  });
});

test("multi-server callTool routes to the correct upstream", async () => {
  const cfg = ProxyConfigSchema.parse({
    version: 1,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: {
          MOCK_TOOLS: JSON.stringify(["read_file"]),
          MOCK_RESULT_TEXT: "fs-result",
        },
      },
      {
        name: "github",
        transport: "stdio",
        command: "node",
        args: [MOCK_SERVER],
        env: {
          MOCK_TOOLS: JSON.stringify(["create_issue"]),
          MOCK_RESULT_TEXT: "gh-result",
        },
      },
    ],
  });
  await withPool(cfg, async (pool) => {
    const fsResult = await pool.callTool("filesystem__read_file", {});
    assert.ok(fsResult.content[0].text.includes("fs-result"));

    const ghResult = await pool.callTool("github__create_issue", {});
    assert.ok(ghResult.content[0].text.includes("gh-result"));
  });
});

// ---------------------------------------------------------------------------
// Tool name separator
// ---------------------------------------------------------------------------

test("prefixed tool names only use characters MCP clients accept", async () => {
  await withPool(makeConfig(), async (pool) => {
    for (const tool of pool.getTools()) {
      assert.match(tool.prefixedName, /^[a-zA-Z0-9_-]{1,64}$/);
      assert.match(tool.definition.name, /^[a-zA-Z0-9_-]{1,64}$/);
    }
  });
});

test("upstream tool name containing the separator routes to the original name", async () => {
  const cfg = makeConfig({
    env: { MOCK_TOOLS: JSON.stringify(["read__file"]), MOCK_RESULT_TEXT: "sep" },
  });
  await withPool(cfg, async (pool) => {
    const [tool] = pool.getTools();
    assert.equal(tool.prefixedName, "filesystem__read__file");
    assert.equal(tool.originalName, "read__file");
    const result = await pool.callTool("filesystem__read__file", { input: "x" });
    assert.equal(result.isError, false);
    assert.equal(result.content[0].text, "sep:read__file:x");
  });
});

test("name_override containing the separator still routes correctly", async () => {
  const cfg = makeConfig({
    name_override: "my__fs",
    env: { MOCK_TOOLS: JSON.stringify(["list_dir"]), MOCK_RESULT_TEXT: "ovr" },
  });
  await withPool(cfg, async (pool) => {
    assert.deepEqual(pool.getTools().map((t) => t.prefixedName), ["my__fs__list_dir"]);
    const result = await pool.callTool("my__fs__list_dir", {});
    assert.equal(result.content[0].text, "ovr:list_dir:");
  });
});

// ---------------------------------------------------------------------------
// JSON Schema dialect normalization
// ---------------------------------------------------------------------------

test("normalizeSchemaDialect removes a draft-07 $schema and keeps everything else", () => {
  const schema = {
    $schema: "http://json-schema.org/draft-07/schema#",
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
    additionalProperties: false,
  };
  assert.deepEqual(normalizeSchemaDialect(schema), {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
    additionalProperties: false,
  });
  // Input is not mutated.
  assert.equal(schema.$schema, "http://json-schema.org/draft-07/schema#");
});

test("normalizeSchemaDialect keeps a 2020-12 $schema, with or without a trailing #", () => {
  const plain = { $schema: "https://json-schema.org/draft/2020-12/schema", type: "object" };
  const hashed = { $schema: "https://json-schema.org/draft/2020-12/schema#", type: "object" };
  assert.equal(normalizeSchemaDialect(plain), plain);
  assert.equal(normalizeSchemaDialect(hashed), hashed);
});

test("normalizeSchemaDialect returns schemas without $schema unchanged", () => {
  const schema = { type: "object", properties: {} };
  assert.equal(normalizeSchemaDialect(schema), schema);
  assert.equal(normalizeSchemaDialect(undefined), undefined);
});

test("discovered inputSchema no longer declares the upstream's draft-07 dialect", async () => {
  await withPool(makeConfig(), async (pool) => {
    const tool = pool.getTools().find((t) => t.prefixedName === "filesystem__read_file");
    assert.equal(tool.definition.inputSchema.$schema, undefined);
    assert.equal(tool.definition.inputSchema.type, "object");
    assert.deepEqual(tool.definition.inputSchema.properties, { input: { type: "string" } });
  });
});

// ---------------------------------------------------------------------------
// Output schemas and structuredContent
// ---------------------------------------------------------------------------

test("outputSchema is passed through without a draft-07 $schema", async () => {
  const cfg = makeConfig({
    env: { MOCK_TOOLS: JSON.stringify(["get_info"]), MOCK_STRUCTURED: "1" },
  });
  await withPool(cfg, async (pool) => {
    const [tool] = pool.getTools();
    assert.ok(tool.definition.outputSchema, "outputSchema missing");
    assert.equal(tool.definition.outputSchema.$schema, undefined);
    assert.deepEqual(tool.definition.outputSchema.properties, { content: { type: "string" } });
  });
});

test("callTool forwards structuredContent from upstream", async () => {
  const cfg = makeConfig({
    env: {
      MOCK_TOOLS: JSON.stringify(["get_info"]),
      MOCK_STRUCTURED: "1",
      MOCK_RESULT_TEXT: "structured",
    },
  });
  await withPool(cfg, async (pool) => {
    const result = await pool.callTool("filesystem__get_info", { input: "a" });
    assert.equal(result.isError, false);
    assert.deepEqual(result.structuredContent, { content: "structured:get_info:a" });
    assert.equal(result.content[0].text, "structured:get_info:a");
  });
});

test("callTool omits structuredContent when upstream does not return it", async () => {
  await withPool(makeConfig(), async (pool) => {
    const result = await pool.callTool("filesystem__read_file", {});
    assert.equal("structuredContent" in result, false);
  });
});

// ---------------------------------------------------------------------------
// close() is safe to call
// ---------------------------------------------------------------------------

test("close() resolves without error", async () => {
  const pool = new UpstreamClientPool();
  await pool.connect(makeConfig());
  await assert.doesNotReject(() => pool.close());
});
