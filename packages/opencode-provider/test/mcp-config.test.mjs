// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hasOpenCodeMcp, installOpenCodeMcp, opencodeMcpConfigPath, opencodeMcpEntry, uninstallOpenCodeMcp } from "../dist/index.js";

function scratch() {
  const dir = mkdtempSync(join(tmpdir(), "opencode-mcp-"));
  mkdirSync(join(dir, "opencode"));
  return { dir, env: { XDG_CONFIG_HOME: dir }, file: join(dir, "opencode", "opencode.json") };
}

test("the config path follows XDG_CONFIG_HOME", () => {
  const { dir, env } = scratch();
  assert.equal(opencodeMcpConfigPath(env), join(dir, "opencode", "opencode.json"));
  assert.equal(opencodeMcpConfigPath({}, "/h/case"), join("/h/case", ".config", "opencode", "opencode.json"));
  rmSync(dir, { recursive: true, force: true });
});

test("install adds the omnodex server and keeps every other key", async () => {
  const { dir, env, file } = scratch();
  writeFileSync(file, JSON.stringify({ theme: "x", mcp: { other: { type: "local", command: ["x"] } } }));
  await installOpenCodeMcp({ omnodexHome: "/h/case/.omnodex" }, env);
  const got = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(got.theme, "x");
  assert.deepEqual(got.mcp.other, { type: "local", command: ["x"] });
  assert.deepEqual(got.mcp.omnodex, opencodeMcpEntry({ omnodexHome: "/h/case/.omnodex" }));
  assert.deepEqual(got.mcp.omnodex.command, ["omnodex", "mcp-proxy", "start"]);
  assert.equal(got.mcp.omnodex.environment.OMNODEX_PLATFORM, "opencode");
  assert.equal(await hasOpenCodeMcp(env), true);
  rmSync(dir, { recursive: true, force: true });
});

test("install creates a missing file and is idempotent; uninstall removes only omnodex", async () => {
  const { dir, env, file } = scratch();
  await installOpenCodeMcp({ omnodexHome: "/h" }, env);
  await installOpenCodeMcp({ omnodexHome: "/h" }, env);
  writeFileSync(file, JSON.stringify({ mcp: { ...JSON.parse(readFileSync(file, "utf8")).mcp, other: {} } }));
  assert.equal(await uninstallOpenCodeMcp(env), true);
  assert.equal(await uninstallOpenCodeMcp(env), false);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(file, "utf8")).mcp), ["other"]);
  rmSync(dir, { recursive: true, force: true });
});

test("a file that is not JSON, or a jsonc config, is reported and left alone", async () => {
  const { dir, env, file } = scratch();
  writeFileSync(file, "{ nope");
  await assert.rejects(installOpenCodeMcp({ omnodexHome: "/h" }, env));
  assert.equal(readFileSync(file, "utf8"), "{ nope");
  assert.equal(await hasOpenCodeMcp(env), false);
  rmSync(file);
  writeFileSync(join(dir, "opencode", "opencode.jsonc"), "// comment\n{}");
  await assert.rejects(installOpenCodeMcp({ omnodexHome: "/h" }, env), /opencode\.jsonc/);
  rmSync(dir, { recursive: true, force: true });
});
