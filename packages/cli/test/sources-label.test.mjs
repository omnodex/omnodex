// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { test } from "node:test";
import assert from "node:assert/strict";
import { sourcesLabel } from "../dist/dashboard-model/labels.js";

test("a merged call names each source; the OpenCode plugin is not a hook", () => {
  assert.equal(sourcesLabel(["claude-code-hook", "mcp-proxy"]), "Claude Code hook + MCP Proxy");
  assert.equal(sourcesLabel(["opencode-plugin", "mcp-proxy"]), "OpenCode + MCP Proxy");
});
