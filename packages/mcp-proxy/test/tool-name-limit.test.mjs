// Tool names shortened for hosts that limit their length (Antigravity drops
// any tool whose prefixed name, with its own prefix, passes 64 characters).

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import * as url from "node:url";

import { fitToolName, toolNameLimit } from "../dist/core/tool-routing.js";
import { UpstreamClientPool } from "../dist/upstream-client.js";
import { ProxyConfigSchema } from "../dist/config.js";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const MOCK_SERVER = path.join(__dirname, "helpers", "mock-mcp-server.mjs");
const NAME_PATTERN = /^[a-zA-Z0-9_-]+$/;

// ---------------------------------------------------------------------------
// toolNameLimit
// ---------------------------------------------------------------------------

test("toolNameLimit: Antigravity has a limit, other platforms none", () => {
  assert.equal(toolNameLimit("antigravity"), 32);
  assert.equal(toolNameLimit("claude-code"), undefined);
  assert.equal(toolNameLimit("cowork"), undefined);
  assert.equal(toolNameLimit(undefined), undefined);
});

test("toolNameLimit: a valid override wins over the platform", () => {
  assert.equal(toolNameLimit("antigravity", "40"), 40);
  assert.equal(toolNameLimit(undefined, "24"), 24);
});

test("toolNameLimit: an invalid or too-small override is ignored", () => {
  assert.equal(toolNameLimit("antigravity", "abc"), 32);
  assert.equal(toolNameLimit("antigravity", "8"), 32);
  assert.equal(toolNameLimit("antigravity", "20.5"), 32);
  assert.equal(toolNameLimit(undefined, ""), undefined);
});

// ---------------------------------------------------------------------------
// fitToolName
// ---------------------------------------------------------------------------

test("fitToolName: a name within the limit is unchanged", () => {
  assert.equal(fitToolName("filesystem", "read_file", 32), "filesystem__read_file");
  assert.equal(fitToolName("filesystem", "list_directory_with_sizes"), "filesystem__list_directory_with_sizes");
});

test("fitToolName: a long name is shortened to the limit, keeping its prefix", () => {
  for (const tool of ["list_directory_with_sizes", "list_allowed_directories"]) {
    const name = fitToolName("filesystem", tool, 32);
    assert.ok(name.length <= 32, `${name} is ${name.length} characters`);
    assert.ok(name.startsWith("filesystem__list_"), name);
    assert.match(name, NAME_PATTERN);
    assert.doesNotMatch(name, /__.*__/, "no doubled separator after the prefix");
  }
});

test("fitToolName: shortening is deterministic and keeps similar names distinct", () => {
  const a = fitToolName("filesystem", "list_directory_with_sizes", 32);
  assert.equal(fitToolName("filesystem", "list_directory_with_sizes", 32), a);
  const b = fitToolName("filesystem", "list_directory_with_owners", 32);
  assert.notEqual(a, b);
});

test("fitToolName: a prefix too long to keep is cut with the rest", () => {
  const name = fitToolName("a_very_long_upstream_server_name", "do_something", 32);
  assert.ok(name.length <= 32, `${name} is ${name.length} characters`);
  assert.match(name, NAME_PATTERN);
});

// ---------------------------------------------------------------------------
// Pool: shortened names route to the upstream's own tool name
// ---------------------------------------------------------------------------

const LONG_TOOLS = ["read_file", "list_directory_with_sizes", "list_allowed_directories"];

function makeConfig() {
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
          MOCK_TOOLS: JSON.stringify(LONG_TOOLS),
          MOCK_RESULT_TEXT: "mock-result",
        },
      },
    ],
  });
}

test("pool with a limit lists every tool within it and routes shortened names", async () => {
  const pool = new UpstreamClientPool({ toolNameLimit: 32 });
  await pool.connect(makeConfig());
  try {
    const tools = pool.getTools();
    assert.equal(tools.length, LONG_TOOLS.length);
    for (const tool of tools) {
      assert.ok(tool.prefixedName.length <= 32, tool.prefixedName);
      assert.equal(tool.definition.name, tool.prefixedName);
      assert.equal(tool.fullName, `filesystem__${tool.originalName}`);
      assert.equal(pool.getServerName(tool.prefixedName), "filesystem");
      assert.equal(pool.getFullToolName(tool.prefixedName), tool.fullName);
    }

    const short = tools.find((t) => t.originalName === "list_directory_with_sizes");
    assert.notEqual(short.prefixedName, short.fullName, "the long name was shortened");
    const result = await pool.callTool(short.prefixedName, { input: "x" });
    assert.equal(result.isError, false);
    assert.ok(
      result.content[0].text.includes("list_directory_with_sizes"),
      `upstream got the wrong name: ${result.content[0].text}`,
    );

    // A name that already fit is offered as-is.
    assert.ok(tools.some((t) => t.prefixedName === "filesystem__read_file"));
  } finally {
    await pool.close();
  }
});

test("pool without a limit keeps full names", async () => {
  const pool = new UpstreamClientPool();
  await pool.connect(makeConfig());
  try {
    const names = pool.getTools().map((t) => t.prefixedName).sort();
    assert.deepEqual(names, LONG_TOOLS.map((t) => `filesystem__${t}`).sort());
  } finally {
    await pool.close();
  }
});
