#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- bin/omnodex-mcp-proxy
 *
 * Subprocess entrypoint. Registered as the "omnodex-mcp-proxy" bin in
 * package.json and referenced from Cowork / Codex plugin mcp.json configs.
 *
 * Usage (direct):
 *   omnodex-mcp-proxy [--config /path/to/omnodex-proxy.json]
 *
 * Usage (via Cowork plugin mcp.json):
 *   { "command": "omnodex-mcp-proxy", "args": [] }
 *
 * The process communicates via stdio MCP (JSON-RPC 2.0, newline-delimited).
 * It exits when the agent closes the connection (stdin EOF).
 *
 * Environment:
 *   OMNODEX_HOME          event log root parent; defaults to ~/.omnodex
 *   OMNODEX_PROJECT_PATH  project path recorded in session.started events
 */

import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "@omnodex/event-log";
import { loadProxyConfig } from "../config.js";
import { MCPProxy } from "../mcp-proxy.js";

async function main(): Promise<void> {
  // Parse --config flag if present.
  const args = process.argv.slice(2);
  let configPath: string | undefined;
  const configFlagIdx = args.indexOf("--config");
  if (configFlagIdx !== -1 && args[configFlagIdx + 1]) {
    configPath = args[configFlagIdx + 1];
  }

  const config = await loadProxyConfig(configPath);

  // Resolve the event log root using the same convention as the hooks shim.
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  const eventLogRoot = path.join(home, "event-log");
  const log = new EventLog({ root: eventLogRoot });
  await log.init();

  const proxy = new MCPProxy(config, {
    projectPath: process.env.OMNODEX_PROJECT_PATH ?? process.cwd(),
  });

  const emit = log.append.bind(log);
  const stop = await proxy.start(emit);

  async function shutdown(): Promise<void> {
    await stop();
    await log.close();
  }

  // Clean up on SIGTERM (sent by Cowork / Codex when the session ends).
  process.on("SIGTERM", () => void shutdown().then(() => process.exit(0)));
  // SIGINT (Ctrl-C during local dev).
  process.on("SIGINT", () => void shutdown().then(() => process.exit(0)));
}

main().catch((err: unknown) => {
  process.stderr.write(
    `[omnodex-mcp-proxy] Startup error: ${err instanceof Error ? err.message : String(err)}\n`
  );
  process.exit(1);
});
