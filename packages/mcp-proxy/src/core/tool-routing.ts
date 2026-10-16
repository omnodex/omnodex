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

/**
 * Joins the upstream prefix and the upstream tool name in the name the agent
 * sees. Clients restrict tool names to letters, digits, "_" and "-" (the
 * Claude API enforces ^[a-zA-Z0-9_-]{1,64}$), so the separator must stay
 * inside that set. A "/" separator gets rewritten by some clients, which
 * breaks per-tool approval because the approved name no longer matches the
 * called name.
 */
export const TOOL_NAME_SEPARATOR = "__";

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

/** Separator and hex digits appended to a shortened name. */
const SHORT_NAME_HASH_LENGTH = 6;

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

/** FNV-1a, so the same name shortens the same way on every runtime. */
function shortHash(value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, "0").slice(0, SHORT_NAME_HASH_LENGTH);
}

/**
 * The agent-visible name for an upstream tool within a length limit. A name
 * that fits is the plain prefixed name. A longer one keeps the prefix and
 * separator, so it still resolves to its upstream, and as much of the tool
 * name as fits, then "_" and a hash of the full name so two long names that
 * start alike stay distinct. Only when the prefix itself leaves no room is
 * the whole name cut.
 */
export function fitToolName(prefix: string, toolName: string, limit?: number): string {
  const full = prefixedToolName(prefix, toolName);
  if (limit === undefined || full.length <= limit) return full;
  const suffix = `_${shortHash(full)}`;
  const room = limit - prefix.length - TOOL_NAME_SEPARATOR.length - suffix.length;
  if (room >= 4) {
    return `${prefix}${TOOL_NAME_SEPARATOR}${toolName.slice(0, room).replace(/[_-]+$/, "")}${suffix}`;
  }
  return `${full.slice(0, limit - suffix.length).replace(/[_-]+$/, "")}${suffix}`;
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
