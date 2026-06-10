// Integration tests for UpstreamClientPool.
// Spawns a real mock MCP subprocess to exercise the full stdio round-trip.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import { UpstreamClientPool, McpToolNotFoundError } from "../dist/upstream-client.js";
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
      "filesystem/list_dir",
      "filesystem/read_file",
      "filesystem/write_file",
    ]);
  });
});

test("tool definition name matches prefixedName", async () => {
  await withPool(makeConfig(), async (pool) => {
    const tool = pool.getTools().find((t) => t.prefixedName === "filesystem/read_file");
    assert.ok(tool, "filesystem/read_file not found");
    assert.equal(tool.definition.name, "filesystem/read_file");
    assert.equal(tool.originalName, "read_file");
    assert.equal(tool.serverName, "filesystem");
  });
});

test("getServerName returns correct server for a prefixed tool", async () => {
  await withPool(makeConfig(), async (pool) => {
    assert.equal(pool.getServerName("filesystem/read_file"), "filesystem");
    assert.equal(pool.getServerName("filesystem/list_dir"), "filesystem");
  });
});

test("getServerName returns undefined for unknown tool", async () => {
  await withPool(makeConfig(), async (pool) => {
    assert.equal(pool.getServerName("unknown/tool"), undefined);
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
    assert.deepEqual(names, ["fs/read_file"]);
    assert.equal(pool.getServerName("fs/read_file"), "filesystem");
  });
});

// ---------------------------------------------------------------------------
// callTool routing
// ---------------------------------------------------------------------------

test("callTool routes to correct upstream and returns result", async () => {
  await withPool(makeConfig(), async (pool) => {
    const result = await pool.callTool("filesystem/read_file", { input: "hello" });
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
    const result = await pool.callTool("filesystem/list_dir", { input: "/tmp" });
    assert.equal(result.isError, false);
    assert.ok(result.content[0].text.includes("list_dir"));
  });
});

test("callTool throws McpToolNotFoundError for unknown prefixed name", async () => {
  await withPool(makeConfig(), async (pool) => {
    await assert.rejects(
      () => pool.callTool("filesystem/nonexistent_tool", {}),
      (err) => {
        assert.ok(err instanceof McpToolNotFoundError, `got: ${err.constructor.name}`);
        assert.match(err.message, /not found/i);
        assert.equal(err.prefixedName, "filesystem/nonexistent_tool");
        return true;
      }
    );
  });
});

test("callTool throws McpToolNotFoundError for entirely wrong server prefix", async () => {
  await withPool(makeConfig(), async (pool) => {
    await assert.rejects(
      () => pool.callTool("github/create_issue", {}),
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
    const result = await pool.callTool("filesystem/read_file", {});
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
      "filesystem/read_file",
      "github/create_issue",
      "github/list_prs",
    ]);
    // Each routes to the right server
    assert.equal(pool.getServerName("filesystem/read_file"), "filesystem");
    assert.equal(pool.getServerName("github/create_issue"), "github");
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
    const fsResult = await pool.callTool("filesystem/read_file", {});
    assert.ok(fsResult.content[0].text.includes("fs-result"));

    const ghResult = await pool.callTool("github/create_issue", {});
    assert.ok(ghResult.content[0].text.includes("gh-result"));
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
