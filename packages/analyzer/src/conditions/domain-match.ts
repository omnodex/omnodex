// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * domain_match condition evaluator.
 *
 * Matches when a URL found in the event parameters targets a domain in (or
 * not in) a supplied list. Supports exact hostname matching and wildcard
 * subdomain matching: "chase.com" matches both "chase.com" and any subdomain
 * ("online.chase.com", "secure.chase.com", etc.).
 *
 * URL extraction covers:
 *   - All string values in event.parameters (JSON-serialized)
 *   - Bash command strings: curl, wget, and http(ie) invocations
 *
 * For in_list: yields one MatchContext per hostname that matches a listed domain.
 * For not_in_list: yields one MatchContext per external hostname that does NOT
 *   match any listed domain (localhost/loopback addresses are always excluded).
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { DomainMatchCondition, MatchContext } from "../types.js";

// ---------------------------------------------------------------------------
// Domain extraction
// ---------------------------------------------------------------------------

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/**
 * Regex to extract http/https URLs from a string.
 * Capture group 1 is the host (and optional port).
 */
const URL_RE = /https?:\/\/([^/\s"'\\]+)/g;

/**
 * Extract unique external hostnames from a tool.invoked event.
 *
 * Returns lowercase hostnames with port stripped (e.g. "online.chase.com").
 * Localhost addresses are excluded. Order reflects first-seen in serialized params.
 */
export function extractDomains(event: ToolInvokedEvent): string[] {
  const paramStr = JSON.stringify(event.parameters);
  const seen = new Set<string>();
  const domains: string[] = [];

  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_RE.exec(paramStr)) !== null) {
    const host = (m[1] ?? "").toLowerCase().split(":")[0];
    if (host && !LOCALHOST_HOSTS.has(host) && !seen.has(host)) {
      seen.add(host);
      domains.push(host);
    }
  }

  return domains;
}

// ---------------------------------------------------------------------------
// Domain matching
// ---------------------------------------------------------------------------

/**
 * Returns true if the hostname matches the candidate domain.
 *
 * "chase.com" matches:
 *   - exact: "chase.com"
 *   - subdomain: "online.chase.com", "secure.chase.com"
 *
 * "chase.com" does NOT match "notchase.com" (suffix-only guard).
 */
function domainMatches(hostname: string, candidate: string): boolean {
  const c = candidate.toLowerCase();
  return hostname === c || hostname.endsWith("." + c);
}

/**
 * Returns true if the hostname is in the domains list.
 */
function isInDomainList(hostname: string, domains: string[]): boolean {
  return domains.some((d) => domainMatches(hostname, d));
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate a domain_match condition against a tool.invoked event.
 *
 * For in_list:
 *   Returns one partial MatchContext (with matched_domain) per hostname that
 *   matches a listed domain. Empty array if no match.
 *
 * For not_in_list:
 *   Returns one partial MatchContext per external hostname that does NOT appear
 *   in the list. Empty array if all external hosts are in the list (or there
 *   are no external hosts).
 */
export function evaluateDomainMatch(
  condition: DomainMatchCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const hosts = extractDomains(event);
  const matched: Partial<MatchContext>[] = [];

  for (const host of hosts) {
    const inList = isInDomainList(host, condition.domains);
    if (condition.match === "in_list" && inList) {
      matched.push({ matched_domain: host });
    } else if (condition.match === "not_in_list" && !inList) {
      matched.push({ matched_domain: host });
    }
  }

  return matched;
}
