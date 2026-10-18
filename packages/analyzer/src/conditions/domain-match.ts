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
 * Hosts come from the call's destinations (../action.ts): URLs in a command
 * that runs or in a non-writing tool's parameters, and the arguments of
 * network programs. A URL in content written to a script or config file
 * (a staged target) still matches, reported as written rather than run, one
 * severity lower: code that will call the host later is worth knowing about.
 *
 * For in_list: yields one MatchContext per hostname that matches a listed domain.
 * For not_in_list: yields one MatchContext per external hostname that does NOT
 *   match any listed domain (localhost/loopback addresses are always excluded).
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { normalizeAction, urlDestinations } from "../action.js";
import type { DomainMatchCondition, MatchContext } from "../types.js";
import { extractStagedContent } from "./scope.js";

// ---------------------------------------------------------------------------
// Domain extraction
// ---------------------------------------------------------------------------

const LOCALHOST_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/**
 * Unique external hostnames a tool.invoked event reaches.
 *
 * Returns lowercase hostnames without port (e.g. "online.chase.com").
 * Localhost addresses are excluded. Order reflects first appearance.
 */
export function extractDomains(event: ToolInvokedEvent): string[] {
  const domains: string[] = [];
  for (const d of normalizeAction(event).destinations) {
    if (!LOCALHOST_HOSTS.has(d.host) && !domains.includes(d.host)) domains.push(d.host);
  }
  return domains;
}

/** External hostnames in URLs written into script and config files, by file. */
function stagedDomains(event: ToolInvokedEvent): { host: string; path: string }[] {
  const out: { host: string; path: string }[] = [];
  for (const { path, text } of extractStagedContent(event)) {
    for (const d of urlDestinations(text)) {
      if (!LOCALHOST_HOSTS.has(d.host) && !out.some((o) => o.host === d.host)) out.push({ host: d.host, path });
    }
  }
  return out;
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
  const select = (host: string): boolean => {
    const inList = isInDomainList(host, condition.domains);
    return condition.match === "in_list" ? inList : !inList;
  };

  const matched: Partial<MatchContext>[] = [];
  for (const host of extractDomains(event)) {
    if (select(host)) matched.push({ matched_domain: host });
  }
  // Only for in_list: "a host not in the list" is about where a call goes,
  // and a URL written into a file goes nowhere yet.
  if (matched.length === 0 && condition.match === "in_list") {
    for (const { host, path } of stagedDomains(event)) {
      if (select(host)) matched.push({ matched_domain: host, staged_path: path });
    }
  }
  return matched;
}
