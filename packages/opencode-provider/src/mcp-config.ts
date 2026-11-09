// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The Omnodex MCP proxy entry in OpenCode's user config.
 *
 * OpenCode reads `opencode.json` from its config folder
 * (`$XDG_CONFIG_HOME/opencode`, or `~/.config/opencode`), with MCP servers
 * under `mcp`; a local server is
 * `{ type: "local", command: [...], environment, enabled }`. Only the
 * `omnodex` entry is ever written or removed, and every other key in the
 * file is kept. A `opencode.jsonc` file with comments cannot be rewritten
 * without losing them, so it is reported and left alone.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

export const MCP_SERVER_NAME = "omnodex";

export function opencodeConfigDir(env: NodeJS.ProcessEnv = process.env, home: string = os.homedir()): string {
  return path.join(env.XDG_CONFIG_HOME?.trim() || path.join(home, ".config"), "opencode");
}

export function opencodeMcpConfigPath(env: NodeJS.ProcessEnv = process.env, home: string = os.homedir()): string {
  return path.join(opencodeConfigDir(env, home), "opencode.json");
}

export interface McpEntryOptions {
  omnodexHome: string;
  /** The command that starts the proxy; `omnodex` is found on PATH when the agent starts. */
  command?: string;
}

/** The server entry: the CLI's proxy, labelled as OpenCode in the dashboards. */
export function opencodeMcpEntry(opts: McpEntryOptions): Record<string, unknown> {
  return {
    type: "local",
    command: [opts.command ?? "omnodex", "mcp-proxy", "start"],
    environment: { OMNODEX_HOME: opts.omnodexHome, OMNODEX_PLATFORM: "opencode" },
    enabled: true,
  };
}

async function exists(file: string): Promise<boolean> {
  return fs.access(file).then(() => true, () => false);
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

/**
 * Add or replace the omnodex entry; returns the file written. Throws on a file
 * that is not JSON, and when the config is an opencode.jsonc with no opencode.json.
 */
export async function installOpenCodeMcp(
  opts: McpEntryOptions,
  env: NodeJS.ProcessEnv = process.env,
  home: string = os.homedir(),
): Promise<string> {
  const file = opencodeMcpConfigPath(env, home);
  const jsonc = path.join(opencodeConfigDir(env, home), "opencode.jsonc");
  if (!(await exists(file)) && (await exists(jsonc))) {
    throw new Error(`${jsonc} is the OpenCode config and may hold comments; add the omnodex MCP entry to it by hand`);
  }
  const config = await readConfig(file);
  const servers = (config.mcp ?? {}) as Record<string, unknown>;
  servers[MCP_SERVER_NAME] = opencodeMcpEntry(opts);
  await writeConfig(file, { ...config, mcp: servers });
  return file;
}

/** Remove only the omnodex entry; true when there was one. */
export async function uninstallOpenCodeMcp(env: NodeJS.ProcessEnv = process.env, home: string = os.homedir()): Promise<boolean> {
  const file = opencodeMcpConfigPath(env, home);
  const config = await readConfig(file);
  const servers = config.mcp as Record<string, unknown> | undefined;
  if (!servers || !(MCP_SERVER_NAME in servers)) return false;
  delete servers[MCP_SERVER_NAME];
  await writeConfig(file, { ...config, mcp: servers });
  return true;
}

/** Whether the omnodex entry is present (a missing or unreadable file reads as no). */
export async function hasOpenCodeMcp(env: NodeJS.ProcessEnv = process.env, home: string = os.homedir()): Promise<boolean> {
  try {
    const servers = (await readConfig(opencodeMcpConfigPath(env, home))).mcp as Record<string, unknown> | undefined;
    return !!servers && MCP_SERVER_NAME in servers;
  } catch {
    return false;
  }
}
