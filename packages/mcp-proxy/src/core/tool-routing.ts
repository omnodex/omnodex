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
 * The tool definition the agent sees: renamed with the prefix and with its
 * schemas' dialect normalized. Everything else passes through unchanged.
 */
export function prefixToolDefinition(prefix: string, tool: Tool): Tool {
  const definition: Tool = {
    ...tool,
    name: prefixedToolName(prefix, tool.name),
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
