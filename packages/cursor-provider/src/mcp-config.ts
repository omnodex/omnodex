// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * The Omnodex MCP proxy entry in Cursor's user MCP config.
 *
 * Cursor reads `~/.cursor/mcp.json`, with servers under `mcpServers`; a
 * local server is `{ command, args, env }`. Only the `omnodex` entry is
 * ever written or removed, and every other server in the file is kept.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const MCP_SERVER_NAME = "omnodex";

export function cursorMcpConfigPath(home: string = os.homedir()): string {
  return path.join(home, ".cursor", "mcp.json");
}

export interface McpEntryOptions {
  omnodexHome: string;
  /** The command that starts the proxy; `omnodex` is found on PATH when the agent starts. */
  command?: string;
}

/** The server entry: the CLI's proxy, labelled as Cursor in the dashboards. */
export function cursorMcpEntry(opts: McpEntryOptions): Record<string, unknown> {
  return {
    command: opts.command ?? "omnodex",
    args: ["mcp-proxy", "start"],
    env: { OMNODEX_HOME: opts.omnodexHome, OMNODEX_PLATFORM: "cursor" },
  };
}

async function readConfig(file: string): Promise<Record<string, unknown>> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw err;
  }
  if (!raw.trim()) return {};
  const parsed: unknown = JSON.parse(raw);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${file} is not a JSON object`);
  }
  return parsed as Record<string, unknown>;
}

async function writeConfig(file: string, config: Record<string, unknown>): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(config, null, 2) + "\n", "utf8");
}

/** Add or replace the omnodex entry; returns the file written. Throws on a file that is not JSON. */
export async function installCursorMcp(opts: McpEntryOptions, home: string = os.homedir()): Promise<string> {
  const file = cursorMcpConfigPath(home);
  const config = await readConfig(file);
  const servers = (config.mcpServers ?? {}) as Record<string, unknown>;
  servers[MCP_SERVER_NAME] = cursorMcpEntry(opts);
  await writeConfig(file, { ...config, mcpServers: servers });
  return file;
}

/** Remove only the omnodex entry; true when there was one. */
export async function uninstallCursorMcp(home: string = os.homedir()): Promise<boolean> {
  const file = cursorMcpConfigPath(home);
  const config = await readConfig(file);
  const servers = config.mcpServers as Record<string, unknown> | undefined;
  if (!servers || !(MCP_SERVER_NAME in servers)) return false;
  delete servers[MCP_SERVER_NAME];
  await writeConfig(file, { ...config, mcpServers: servers });
  return true;
}

/** Whether the omnodex entry is present (a missing or unreadable file reads as no). */
export async function hasCursorMcp(home: string = os.homedir()): Promise<boolean> {
  try {
    const servers = (await readConfig(cursorMcpConfigPath(home))).mcpServers as Record<string, unknown> | undefined;
    return !!servers && MCP_SERVER_NAME in servers;
  } catch {
    return false;
  }
}
