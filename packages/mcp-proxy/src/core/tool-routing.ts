// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- core/tool-routing
 *
 * How upstream tools are named and found: the prefix scheme, tool definition
 * rewriting, and resolving an agent-visible name back to its upstream.
 *
 * Runtime-neutral: no Node APIs, so a proxy running on another JavaScript
 * runtime routes tools exactly the same way.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { TOOL_NAME_SEPARATOR, fitToolName } from "@omnodex/shared";

// Naming and shortening live in @omnodex/shared, so the projection can
// recognize a shortened name when it pairs hook and proxy observations.
export { TOOL_NAME_SEPARATOR, fitToolName };

/**
 * JSON Schema dialect that MCP clients validate tool schemas against. Schemas
 * declaring any other "$schema" (commonly draft-07, emitted by
 * zod-to-json-schema) are rejected by clients whose validator only supports
 * this dialect.
 */
const SUPPORTED_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema";

/**
 * Removes a top-level "$schema" declaration that names a dialect other than
 * JSON Schema 2020-12, so the schema is validated under the client's default
 * dialect. The keywords MCP servers use in tool schemas (type, properties,
 * required, items, enum, additionalProperties, description) behave the same
 * in draft-07 and 2020-12. Returns the input unchanged when there is nothing
 * to remove.
 */
export function normalizeSchemaDialect<T>(schema: T): T {
  if (schema === null || typeof schema !== "object" || !("$schema" in schema)) {
    return schema;
  }
  const { $schema, ...rest } = schema as Record<string, unknown>;
  if (typeof $schema === "string" && $schema.replace(/#$/, "") === SUPPORTED_SCHEMA_DIALECT) {
    return schema;
  }
  return rest as T;
}

/** The agent-visible name for an upstream tool. */
export function prefixedToolName(prefix: string, toolName: string): string {
  return `${prefix}${TOOL_NAME_SEPARATOR}${toolName}`;
}

/**
 * Longest tool name the proxy may offer on each platform, where the host
 * adds its own prefix and drops any tool whose full name exceeds 64
 * characters. Antigravity names a plugin's tools
 * `mcp_<plugin>_<server>_<tool>`, which is 32 characters for the Omnodex
 * plugin, leaving 32. A proxy registered under a shorter server name only
 * gets shorter names than it needed. Platforms not listed keep full names.
 */
const PLATFORM_TOOL_NAME_LIMITS: Readonly<Record<string, number>> = {
  antigravity: 32,
};

/** The shortest limit accepted, so a shortened name keeps some of its prefix. */
const MIN_TOOL_NAME_LIMIT = 16;

/**
 * The tool name limit for this proxy: OMNODEX_TOOL_NAME_MAX when it is a
 * whole number of at least 16, otherwise the platform's limit, otherwise
 * none.
 */
export function toolNameLimit(platform: string | undefined, override?: string): number | undefined {
  if (override !== undefined && override.trim() !== "") {
    const parsed = Number(override);
    if (Number.isInteger(parsed) && parsed >= MIN_TOOL_NAME_LIMIT) return parsed;
  }
  return platform ? PLATFORM_TOOL_NAME_LIMITS[platform] : undefined;
}

/**
 * The tool definition the agent sees: renamed with the prefix (shortened to
 * the limit when one is given) and with its schemas' dialect normalized.
 * Everything else passes through unchanged.
 */
export function prefixToolDefinition(prefix: string, tool: Tool, limit?: number): Tool {
  const definition: Tool = {
    ...tool,
    name: fitToolName(prefix, tool.name, limit),
    inputSchema: normalizeSchemaDialect(tool.inputSchema),
  };
  if (tool.outputSchema) {
    definition.outputSchema = normalizeSchemaDialect(tool.outputSchema);
  }
  return definition;
}

/**
 * Finds which prefix an agent-visible name belongs to, preferring the
 * longest match when one prefix starts with another, and returns the
 * upstream's own tool name. Undefined when no prefix matches.
 */
export function resolvePrefixedName(
  prefixedName: string,
  prefixes: Iterable<string>
): { prefix: string; originalName: string } | undefined {
  let best: string | undefined;
  for (const prefix of prefixes) {
    if (!prefixedName.startsWith(`${prefix}${TOOL_NAME_SEPARATOR}`)) continue;
    if (best === undefined || prefix.length > best.length) best = prefix;
  }
  if (best === undefined) return undefined;
  return { prefix: best, originalName: prefixedName.slice(best.length + TOOL_NAME_SEPARATOR.length) };
}
