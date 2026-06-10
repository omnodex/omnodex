// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * outbound_call condition evaluator.
 *
 * Detects whether a tool.invoked event represents an outbound HTTP call to
 * an external host. Acts as a boolean guard: returns one empty MatchContext
 * when the event looks outbound, or nothing when it does not.
 *
 * Detection logic:
 *   1. If URL parameters are present, use them exclusively:
 *      outbound iff at least one URL resolves to a non-localhost host.
 *      This prevents false positives when a "fetch" tool calls localhost.
 *   2. If no URL parameters, fall back to heuristics:
 *      a. Tool name contains "fetch", "http", or "request".
 *      b. Bash command contains curl, wget, http, or httpie.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { MatchContext } from "../types.js";

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

const URL_RE = /https?:\/\/([^/\s"'\\]+)/g;

function extractUrls(paramStr: string): string[] {
  const hosts: string[] = [];
  let m: RegExpExecArray | null;
  URL_RE.lastIndex = 0;
  while ((m = URL_RE.exec(paramStr)) !== null) {
    const host = m[1]?.toLowerCase().split(":")[0] ?? "";
    hosts.push(host);
  }
  return hosts;
}

/**
 * Returns true if the event looks like an outbound HTTP call to an external host.
 */
export function isOutboundCall(event: ToolInvokedEvent): boolean {
  const paramStr = JSON.stringify(event.parameters);
  const urlHosts = extractUrls(paramStr);

  // If URL parameters are present, let the URL decide.
  // Outbound only if at least one URL targets a non-localhost host.
  if (urlHosts.length > 0) {
    return urlHosts.some((host) => !LOCALHOST_HOSTS.has(host));
  }

  // No URL parameters — fall back to tool name and bash command heuristics.
  const name = event.tool_name.toLowerCase();

  if (name.includes("fetch") || name.includes("http") || name.includes("request")) {
    return true;
  }

  if (name === "bash" && typeof event.parameters["command"] === "string") {
    if (/\b(curl|wget|httpie?)\b/.test(event.parameters["command"] as string)) {
      return true;
    }
  }

  return false;
}

/**
 * Evaluate an outbound_call condition against a tool.invoked event.
 *
 * Returns a single empty partial context when the call is outbound (so
 * the engine treats this as "condition matched, no additional template
 * variables contributed"), or an empty array when it is not.
 */
export function evaluateOutboundCall(
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  return isOutboundCall(event) ? [{}] : [];
}
