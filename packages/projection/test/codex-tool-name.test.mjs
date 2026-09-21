import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  codexToolName,
  matchCodexToolName,
} from "../dist/index.js";

const fixture = JSON.parse(
  await readFile(
    new URL(
      "../../hooks-provider/test/fixtures/tool-name-mapping.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const capture = fixture.captures.find((entry) => entry.platform === "codex");

test("reproduces every captured Codex model-visible tool name", () => {
  for (const tool of capture.tools) {
    const separator = tool.model_visible_name.indexOf("__", "mcp__".length);
    const serverName = tool.model_visible_name.slice("mcp__".length, separator);
    const collision = /_[0-9a-f]{12}$/.test(tool.model_visible_name);
    assert.equal(
      codexToolName(serverName, tool.proxy_tool_name, {
        toolCollision: collision,
      }),
      tool.model_visible_name,
      tool.proxy_tool_name,
    );
  }
});

test("derives namespace hashes and truncated names", () => {
  const hashedNamespace = codexToolName("server-name", "read_file", {
    namespaceCollision: true,
  });
  assert.equal(
    hashedNamespace,
    "mcp__server_name_7abdd30d7267__read_file",
  );
  const recoverableNamespace = codexToolName("server_name", "read.file", {
    namespaceCollision: true,
  });
  assert.equal(
    matchCodexToolName(recoverableNamespace, "read.file"),
    "derived",
  );

  const longToolName = `demo__${"x".repeat(180)}`;
  const generated = codexToolName("capture_long", longToolName);
  assert.equal(generated.length, 128);
  assert.match(generated, /_[0-9a-f]{12}$/);
  assert.equal(matchCodexToolName(generated, longToolName), "derived");
});

test("matches captured names and excludes direct Codex Apps calls", () => {
  for (const tool of capture.tools) {
    assert.equal(
      matchCodexToolName(tool.model_visible_name, tool.proxy_tool_name),
      "derived",
      tool.proxy_tool_name,
    );
  }
  assert.equal(
    matchCodexToolName(
      "mcp__codex_apps__plane__workitem",
      "plane__workitem",
    ),
    null,
  );
});
