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
 * It is also its own background-sync worker: started with
 * OMNODEX_AUTO_SYNC_CHILD=1 it runs one sync blob push and exits instead of
 * speaking MCP. A running proxy re-spawns itself that way on a timer and once
 * the agent disconnects.
 *
 * Environment:
 *   OMNODEX_HOME               event log root parent; defaults to ~/.omnodex
 *   OMNODEX_PROJECT_PATH       project path recorded in session.started events
 *   OMNODEX_AUTO_SYNC_CHILD=1  run one background sync and exit
 */

import * as os from "node:os";
import * as path from "node:path";
import { EventLog } from "@omnodex/event-log";
import {
  AUTO_SYNC_CHILD_ENV,
  runAutoSync,
  startBackgroundSync,
} from "@omnodex/sync-encryptor";
import { loadProxyConfig } from "../config.js";
import { MCPProxy } from "../mcp-proxy.js";

async function main(): Promise<void> {
  // Resolve the event log root using the same convention as the hooks shim.
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");

  // Detached sync child spawned by a running proxy, not an agent connection.
  // Checked before anything touches stdio: this process has no MCP peer.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    await runAutoSync(home, {
      detect: async () => (await import("@omnodex/analyzer")).runBackgroundDetect(home),
    });
    return;
  }

  // Parse --config flag if present.
  const args = process.argv.slice(2);
  let configPath: string | undefined;
  const configFlagIdx = args.indexOf("--config");
  if (configFlagIdx !== -1 && args[configFlagIdx + 1]) {
    configPath = args[configFlagIdx + 1];
  }

  const config = await loadProxyConfig(configPath, { allowMissing: true });

  const eventLogRoot = path.join(home, "event-log");
  const log = new EventLog({ root: eventLogRoot });
  await log.init();

  const scriptPath = process.argv[1] ?? "";
  const proxy = new MCPProxy(config, {
    projectPath: process.env.OMNODEX_PROJECT_PATH ?? process.cwd(),
    home,
    autoSyncScriptPath: scriptPath,
  });

  const emit = log.append.bind(log);
  const stop = await proxy.start(emit);

  async function shutdown(): Promise<void> {
    await stop();
    await log.close();
    // One last blob refresh, after the log is closed so the detached child
    // reads a file with session.ended already in it. Subject to the usual
    // guards, so a sync from the timer moments ago wins and this is a no-op.
    await startBackgroundSync({ home, scriptPath, detect: true });
  }

  // Normal end: the agent closes stdin.
  void proxy.whenClosed().then(shutdown).then(() => process.exit(0));
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
