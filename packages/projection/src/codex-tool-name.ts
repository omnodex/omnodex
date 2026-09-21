// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { createHash } from "node:crypto";
import { splitMcpToolName } from "@omnodex/shared";

const MAX_TOOL_NAME_LENGTH = 128;
const HASH_LENGTH = 12;
const HASH_SUFFIX = new RegExp(`_([0-9a-f]{${HASH_LENGTH}})$`);

export interface CodexToolNameOptions {
  /** Two raw tools normalize to the same callable name. */
  toolCollision?: boolean;
  /** Two raw MCP servers normalize to the same callable namespace. */
  namespaceCollision?: boolean;
  /** Retry number used only if a generated name also collides. */
  attempt?: number;
}

/** Replace characters the Responses API does not allow with underscores. */
export function sanitizeCodexToolNamePart(value: string): string {
  const sanitized = value.replace(/[^A-Za-z0-9_]/g, "_");
  return sanitized || "_";
}

/**
 * Reproduce Codex's model-visible name for a plain MCP server and tool.
 *
 * This mirrors `normalize_tools_for_model_with_prefix` and
 * `unique_callable_parts` in openai/codex at commit a4c8fc7. The raw MCP
 * identities remain the hash input while only the callable parts are
 * sanitized. Connector-backed tools cannot always be reproduced because the
 * connector id is not present in hook payloads; correlation handles those as
 * a lower-confidence match instead.
 */
export function codexToolName(
  serverName: string,
  toolName: string,
  options: CodexToolNameOptions = {},
): string {
  const rawNamespaceIdentity = `${serverName}\0${serverName}\0`;
  const rawToolIdentity = `${rawNamespaceIdentity}\0${toolName}\0${toolName}`;
  let namespace = `mcp__${sanitizeCodexToolNamePart(serverName)}__`;

  if (options.namespaceCollision) {
    const withoutDelimiter = namespace.slice(0, -2);
    namespace = `${withoutDelimiter}${hashSuffix(rawNamespaceIdentity)}__`;
  }

  const callableToolName = sanitizeCodexToolNamePart(toolName);
  const modelName = `${namespace}${callableToolName}`;
  if (!options.toolCollision && modelName.length <= MAX_TOOL_NAME_LENGTH) {
    return modelName;
  }

  const attemptIdentity =
    (options.attempt ?? 0) > 0
      ? `${rawToolIdentity}\0${options.attempt}`
      : rawToolIdentity;
  return fitWithHash(namespace, callableToolName, attemptIdentity);
}

export type CodexNameMatch = "exact" | "derived" | "loose" | null;

/** Match a Codex hook name to one raw tool name observed by the proxy. */
export function matchCodexToolName(
  hookToolName: string,
  proxyToolName: string,
): CodexNameMatch {
  const parsed = splitMcpToolName(hookToolName);
  if (!parsed || parsed.mcpServer === "codex_apps") return null;
  if (parsed.upstreamToolName === proxyToolName) return "exact";

  const serverCandidates: Array<{
    serverName: string;
    namespaceCollision: boolean;
  }> = [];

  if (sanitizeCodexToolNamePart(parsed.mcpServer) === parsed.mcpServer) {
    serverCandidates.push({
      serverName: parsed.mcpServer,
      namespaceCollision: false,
    });
  }

  const namespaceMatch = parsed.mcpServer.match(HASH_SUFFIX);
  if (namespaceMatch) {
    const serverName = parsed.mcpServer.slice(0, -(HASH_LENGTH + 1));
    const rawNamespaceIdentity = `${serverName}\0${serverName}\0`;
    if (
      sanitizeCodexToolNamePart(serverName) === serverName &&
      hashSuffix(rawNamespaceIdentity) === `_${namespaceMatch[1]}`
    ) {
      serverCandidates.push({ serverName, namespaceCollision: true });
    }
  }

  for (const candidate of serverCandidates) {
    for (const toolCollision of [false, true]) {
      if (
        codexToolName(candidate.serverName, proxyToolName, {
          namespaceCollision: candidate.namespaceCollision,
          toolCollision,
        }) === hookToolName
      ) {
        return "derived";
      }
    }
  }

  const sanitizedProxyName = sanitizeCodexToolNamePart(proxyToolName);
  const hookToolWithoutHash = parsed.upstreamToolName.replace(HASH_SUFFIX, "");
  if (
    sanitizedProxyName === hookToolWithoutHash ||
    (hookToolName.length === MAX_TOOL_NAME_LENGTH &&
      sanitizedProxyName.startsWith(hookToolWithoutHash))
  ) {
    return "loose";
  }

  return null;
}

function fitWithHash(
  namespace: string,
  toolName: string,
  rawIdentity: string,
): string {
  const suffix = hashSuffix(rawIdentity);
  const maxToolLength = MAX_TOOL_NAME_LENGTH - namespace.length;
  if (maxToolLength >= suffix.length) {
    const prefixLength = maxToolLength - suffix.length;
    return `${namespace}${toolName.slice(0, prefixLength)}${suffix}`;
  }

  const maxNamespaceLength = MAX_TOOL_NAME_LENGTH - suffix.length;
  return `${namespace.slice(0, maxNamespaceLength)}${suffix}`;
}

function hashSuffix(value: string): string {
  const hash = createHash("sha1").update(value).digest("hex");
  return `_${hash.slice(0, HASH_LENGTH)}`;
}
