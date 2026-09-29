// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

// Runtime-neutral: no Node-only imports, so correlation can also run in a
// browser or a Worker. The one hash it needs is implemented below.
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
  return `_${sha1Hex(value).slice(0, HASH_LENGTH)}`;
}

/**
 * SHA-1 of a string's UTF-8 bytes, as lowercase hex. Codex derives collision
 * suffixes from SHA-1, so this must match it byte for byte; it is not used
 * for anything security-related. Synchronous and dependency-free, unlike
 * node:crypto (Node only) or crypto.subtle (async).
 */
export function sha1Hex(value: string): string {
  const bytes = new TextEncoder().encode(value);
  const bitLength = bytes.length * 8;
  // Message, a 0x80 byte, zero padding, then the 64-bit length: a multiple of 64.
  const padded = new Uint8Array((((bytes.length + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000));
  view.setUint32(padded.length - 4, bitLength >>> 0);

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const w = new Uint32Array(80);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4);
    for (let i = 16; i < 80; i++) {
      // Non-null: indexes 0..79 of an 80-word array.
      const x = w[i - 3]! ^ w[i - 8]! ^ w[i - 14]! ^ w[i - 16]!;
      w[i] = (x << 1) | (x >>> 31);
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      const [f, k] =
        i < 20 ? [(b & c) | (~b & d), 0x5a827999]
        : i < 40 ? [b ^ c ^ d, 0x6ed9eba1]
        : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc]
        : [b ^ c ^ d, 0xca62c1d6];
      const t = (((a << 5) | (a >>> 27)) + f + e + k + w[i]!) >>> 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = t;
    }
    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }
  return [h0, h1, h2, h3, h4].map((h) => (h >>> 0).toString(16).padStart(8, "0")).join("");
}
