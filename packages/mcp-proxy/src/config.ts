// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- config
 *
 * Zod schema and loader for omnodex-proxy.json, the config file that tells
 * the proxy which upstream MCP servers to connect to and how.
 *
 * Default location: $OMNODEX_HOME/omnodex-proxy.json
 * Fallback: ./omnodex-proxy.json (cwd of the proxy process)
 */

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const StdioUpstreamSchema = z.object({
  /** Logical name for this upstream server. Used as the tool name prefix. */
  name: z.string().min(1),
  transport: z.literal("stdio"),
  /** Executable to spawn. */
  command: z.string().min(1),
  /** Arguments passed to the executable. */
  args: z.array(z.string()).default([]),
  /**
   * Environment variables passed to the upstream process.
   * Values may use ${VAR} syntax; they are resolved from the proxy's own env.
   * Secrets (API keys, tokens) should be passed this way rather than stored
   * as literal values in the config file.
   */
  env: z.record(z.string()).optional(),
  /** Working directory for the upstream process. Defaults to proxy cwd. */
  cwd: z.string().optional(),
  /**
   * Override the tool name prefix exposed to the agent.
   * If set, tools appear as "{name_override}/{tool_name}" instead of
   * "{name}/{tool_name}". Useful when the server name is long or conflicts.
   */
  name_override: z.string().optional(),
  /**
   * When true, parameter values in tool.invoked TraceEvents are replaced with
   * "[REDACTED]" before writing to the event log. Tool names, timing, and
   * response_bytes are still recorded. Overrides the top-level default.
   *
   * Default: inherits top-level redact_parameters (which defaults to false).
   * Set to true for upstream servers that handle highly sensitive data.
   */
  redact_parameters: z.boolean().optional(),
});

const HttpUpstreamSchema = z.object({
  name: z.string().min(1),
  transport: z.literal("http"),
  /** Full URL of the HTTP+SSE MCP server. */
  url: z.string().url(),
  name_override: z.string().optional(),
  redact_parameters: z.boolean().optional(),
});

const UpstreamServerSchema = z.discriminatedUnion("transport", [
  StdioUpstreamSchema,
  HttpUpstreamSchema,
]);

export const ProxyConfigSchema = z.object({
  /** Schema version. Currently always 1. */
  version: z.literal(1),
  /**
   * Global default for parameter redaction.
   *
   * false (default): parameter values are written to the local event log.
   *   Consistent with the hooks shim; enables content-based analysis rules.
   *   All data stays on the local machine -- never leaves without sync consent.
   *
   * true: parameter values are replaced with "[REDACTED]" before logging.
   *   Tool names, timing, and response_bytes are still recorded.
   *   Use when even local logging of parameter content is unacceptable,
   *   at the cost of disabling content-based security rules.
   *
   * Individual upstream servers can override this via their own
   * redact_parameters field.
   */
  redact_parameters: z.boolean().default(false),
  upstream_servers: z.array(UpstreamServerSchema).min(1),
});

export type ProxyConfig = z.infer<typeof ProxyConfigSchema>;
export type UpstreamServer = z.infer<typeof UpstreamServerSchema>;
export type StdioUpstream = z.infer<typeof StdioUpstreamSchema>;
export type HttpUpstream = z.infer<typeof HttpUpstreamSchema>;

// ---------------------------------------------------------------------------
// Env var interpolation
// ---------------------------------------------------------------------------

/**
 * Resolves ${VAR} references in a string using the current process env.
 * Unknown vars are left as-is so the error is visible rather than silent.
 */
function interpolateEnvVar(value: string): string {
  return value.replace(/\$\{([^}]+)\}/g, (match, varName: string) => {
    return process.env[varName] ?? match;
  });
}

/**
 * Resolves env var references in the env record of a stdio upstream.
 * Returns a new record with all values interpolated.
 */
export function resolveUpstreamEnv(
  env: Record<string, string> | undefined
): Record<string, string> | undefined {
  if (!env) return undefined;
  const resolved: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    resolved[key] = interpolateEnvVar(value);
  }
  return resolved;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolves the effective redact_parameters setting for an upstream server,
 * combining the global default with the per-server override.
 */
export function shouldRedactParams(
  server: UpstreamServer,
  config: ProxyConfig
): boolean {
  return server.redact_parameters ?? config.redact_parameters;
}

/**
 * Returns the tool name prefix for an upstream server.
 * Uses name_override if set, otherwise falls back to server name.
 */
export function toolNamePrefix(server: UpstreamServer): string {
  return server.name_override ?? server.name;
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/**
 * Locates and parses the proxy config file.
 * Search order:
 *   1. Explicit path (from --config CLI flag or env)
 *   2. $OMNODEX_HOME/omnodex-proxy.json
 *   3. ~/.omnodex/omnodex-proxy.json (os.homedir)
 *   4. ./omnodex-proxy.json (cwd)
 */
export async function loadProxyConfig(
  explicitPath?: string
): Promise<ProxyConfig> {
  const candidates: string[] = [];
  if (explicitPath) candidates.push(explicitPath);
  if (process.env.OMNODEX_HOME) {
    candidates.push(path.join(process.env.OMNODEX_HOME, "omnodex-proxy.json"));
  }
  // Always check ~/.omnodex/ so the proxy works when spawned by Claude Code
  // or other agents that don't set OMNODEX_HOME or pass --config.
  candidates.push(path.join(os.homedir(), ".omnodex", "omnodex-proxy.json"));
  candidates.push(path.join(process.cwd(), "omnodex-proxy.json"));

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      const raw = await readFile(candidate, "utf8");
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (err) {
        throw new Error(
          `Failed to parse omnodex-proxy.json at ${candidate}: ${(err as Error).message}`
        );
      }
      const result = ProxyConfigSchema.safeParse(parsed);
      if (!result.success) {
        throw new Error(
          `Invalid omnodex-proxy.json at ${candidate}: ${result.error.message}`
        );
      }
      return result.data;
    }
  }

  throw new Error(
    `omnodex-proxy.json not found. Searched: ${candidates.join(", ")}. ` +
      `Run 'omnodex mcp-proxy install' to create one.`
  );
}
