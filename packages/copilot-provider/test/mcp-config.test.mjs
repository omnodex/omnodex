// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { copilotMcpConfigPath, copilotMcpEntry, hasCopilotMcp, installCopilotMcp, uninstallCopilotMcp } from "../dist/index.js";

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), "copilot-mcp-"));
  return { dir, env: { COPILOT_HOME: dir } };
}

test("config path follows COPILOT_HOME", () => {
  const { dir, env } = scratch();
  assert.equal(copilotMcpConfigPath(env), join(dir, "mcp-config.json"));
  rmSync(dir, { recursive: true, force: true });
});

test("install writes the omnodex entry and keeps other servers and keys", async () => {
  const { dir, env } = scratch();
  const file = join(dir, "mcp-config.json");
  writeFileSync(file, JSON.stringify({ extra: 1, mcpServers: { other: { type: "local", command: "x" } } }));
  await installCopilotMcp({ omnodexHome: "/h/case/.omnodex" }, env);
  const got = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(got.extra, 1);
  assert.deepEqual(got.mcpServers.other, { type: "local", command: "x" });
  assert.deepEqual(got.mcpServers.omnodex, copilotMcpEntry({ omnodexHome: "/h/case/.omnodex" }));
  assert.equal(got.mcpServers.omnodex.env.OMNODEX_PLATFORM, "copilot");
  assert.equal(await hasCopilotMcp(env), true);
  rmSync(dir, { recursive: true, force: true });
});

test("install creates a missing file and is idempotent", async () => {
  const { dir, env } = scratch();
  await installCopilotMcp({ omnodexHome: "/h" }, env);
  await installCopilotMcp({ omnodexHome: "/h" }, env);
  const got = JSON.parse(readFileSync(join(dir, "mcp-config.json"), "utf8"));
  assert.deepEqual(Object.keys(got.mcpServers), ["omnodex"]);
  rmSync(dir, { recursive: true, force: true });
});

test("uninstall removes only omnodex", async () => {
  const { dir, env } = scratch();
  writeFileSync(join(dir, "mcp-config.json"), JSON.stringify({ mcpServers: { other: {}, omnodex: {} } }));
  assert.equal(await uninstallCopilotMcp(env), true);
  assert.equal(await uninstallCopilotMcp(env), false);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(join(dir, "mcp-config.json"), "utf8")).mcpServers), ["other"]);
  rmSync(dir, { recursive: true, force: true });
});

test("a file that is not JSON is reported, not overwritten", async () => {
  const { dir, env } = scratch();
  const file = join(dir, "mcp-config.json");
  writeFileSync(file, "{ nope");
  await assert.rejects(installCopilotMcp({ omnodexHome: "/h" }, env));
  assert.equal(readFileSync(file, "utf8"), "{ nope");
  assert.equal(await hasCopilotMcp(env), false);
  rmSync(dir, { recursive: true, force: true });
});
