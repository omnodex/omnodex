// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * How the local dashboard names sessions and their sources. Pure functions
 * shared by the page and by the conformance tests, which check them against
 * the same fixtures the hosted dashboard reads.
 */

import type { SessionRow } from "@omnodex/projection";

/** Colour family for an interceptor badge; the page maps it to CSS tokens. */
export type SourceTone = "cyan" | "mint" | "purple" | "orange" | "blue" | "slate";

export function interceptorTone(interceptor: string | null | undefined): SourceTone {
  switch (interceptor) {
    case "mcp-proxy": return "cyan";
    case "claude-code-hook": return "mint";
    case "codex-hook": return "purple";
    case "antigravity-hook": return "orange";
    case "cowork-desktop": return "blue";
    default: return "slate";
  }
}

export function interceptorLabel(interceptor: string | null | undefined): string {
  switch (interceptor) {
    case "mcp-proxy": return "MCP Proxy";
    case "claude-code-hook": return "Claude Code";
    case "codex-hook": return "Codex";
    case "antigravity-hook": return "Antigravity";
    case "cowork-desktop": return "Cowork";
    default: return interceptor || "unknown";
  }
}

const PLATFORM_LABELS: Readonly<Record<string, string>> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  cowork: "Cowork",
  antigravity: "Antigravity",
  web: "Web",
  copilot: "Copilot",
};

type LabelledSession = Pick<SessionRow, "interceptor" | "platform" | "mcp_client_name">;

/**
 * The runtime a session ran in: its platform when the interceptor recorded
 * one, else its interceptor. Proxy sessions read "<Platform> via MCP Proxy",
 * then "<client> via MCP Proxy", then "MCP Proxy". A Claude Code hook session
 * in platform "cowork" is a Cowork cloud task.
 */
export function runtimeLabel(s: LabelledSession | null | undefined): string {
  if (!s) return "unknown";
  const platform = s.platform ? (PLATFORM_LABELS[s.platform] ?? s.platform) : null;
  if (s.interceptor === "mcp-proxy") {
    if (platform) return `${platform} via MCP Proxy`;
    return s.mcp_client_name ? `${s.mcp_client_name} via MCP Proxy` : "MCP Proxy";
  }
  if (s.interceptor === "claude-code-hook" && s.platform === "cowork") return "Cowork Cloud";
  return platform ?? interceptorLabel(s.interceptor);
}

/** Short names for the interceptors that observed one merged call. */
export function sourcesLabel(sources: readonly string[]): string {
  return sources.map((src) => (src === "mcp-proxy" ? "MCP Proxy" : `${interceptorLabel(src)} hook`)).join(" + ");
}

/** A session id short enough for a list: "sess_" ids keep 17 characters, others 12. */
export function shortSessionId(sessionId: string | null | undefined): string {
  if (!sessionId) return "";
  return sessionId.startsWith("sess_") ? sessionId.slice(0, 17) : sessionId.slice(0, 12);
}

/** The last segment of a project path, on either path style. */
export function projectName(projectPath: string | null | undefined): string | null {
  if (!projectPath) return null;
  const parts = projectPath.replace(/\\/g, "/").split("/").filter(Boolean);
  return parts.length > 0 ? parts[parts.length - 1]! : null;
}

export function displayStatus(status: string | null | undefined): string {
  if (status === "in_progress") return "Active";
  if (!status) return "Unknown";
  return status.charAt(0).toUpperCase() + status.slice(1);
}

/** Tool calls plus file reads and writes: sessions with none are not listed. */
export function totalEvents(s: Pick<SessionRow, "tool_call_count" | "file_read_count" | "file_write_count">): number {
  return (s.tool_call_count || 0) + (s.file_read_count || 0) + (s.file_write_count || 0);
}
