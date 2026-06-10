// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * ip_destination condition evaluator.
 *
 * Detects outbound calls to raw IPv4 addresses and classifies them by
 * whether the destination falls within a known cloud provider CIDR range.
 *
 * Two-tier design:
 *   "in_known_cidr"     -- probably legit cloud traffic via a bare IP,
 *                          which is slightly unusual but not immediately
 *                          alarming. Yields MEDIUM-severity findings.
 *   "not_in_known_cidr" -- unknown destination IP; possible C2 callback,
 *                          data exfiltration, or attacker-controlled host.
 *                          Yields HIGH-severity findings.
 *
 * IP extraction covers URL hostnames (http://1.2.3.4/...) and bare IP
 * arguments to curl/wget in bash command parameters.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import type { IpDestinationCondition, MatchContext } from "../types.js";

// ---------------------------------------------------------------------------
// CIDR matching
// ---------------------------------------------------------------------------

function ipToUint32(ip: string): number {
  const parts = ip.split(".").map(Number);
  return (
    (((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>>
    0)
  );
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash === -1) return ip === cidr;
  const base = cidr.slice(0, slash);
  const prefixLen = parseInt(cidr.slice(slash + 1), 10);
  // A /0 CIDR matches everything; avoid undefined shift behaviour.
  const mask = prefixLen === 0 ? 0 : (~((1 << (32 - prefixLen)) - 1)) >>> 0;
  return (ipToUint32(ip) & mask) === (ipToUint32(base) & mask);
}

export function isInKnownCidrs(ip: string, cidrs: string[]): boolean {
  return cidrs.some((cidr) => isIpInCidr(ip, cidr));
}

// ---------------------------------------------------------------------------
// IP extraction
// ---------------------------------------------------------------------------

// Matches bare IPv4 addresses; handles port suffix (e.g. 52.1.2.3:8080).
const IPV4_RE = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?\b/g;

// These IPs are never external destinations.
const SKIP_IPS = new Set([
  "0.0.0.0",
  "127.0.0.1",
  "255.255.255.255",
  "192.168.0.1",   // common gateway -- too noisy to flag
]);

/**
 * Extract raw IPv4 addresses from the JSON-serialized event parameters.
 * Covers URL hostnames, curl/wget arguments, and any bare IP string.
 * Returns a deduplicated list.
 */
export function extractRawIps(event: ToolInvokedEvent): string[] {
  const paramStr = JSON.stringify(event.parameters);
  const seen = new Set<string>();
  IPV4_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IPV4_RE.exec(paramStr)) !== null) {
    const ip = m[1]!;
    if (!SKIP_IPS.has(ip) && !seen.has(ip)) {
      seen.add(ip);
    }
  }
  return [...seen];
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

/**
 * Evaluate an ip_destination condition against a tool.invoked event.
 *
 * Returns one partial MatchContext per IP that satisfies the condition's
 * `match` criterion, or an empty array if no qualifying IPs are found.
 */
export function evaluateIpDestination(
  condition: IpDestinationCondition,
  event: ToolInvokedEvent,
): Partial<MatchContext>[] {
  const ips = extractRawIps(event);
  if (ips.length === 0) return [];

  const results: Partial<MatchContext>[] = [];
  for (const ip of ips) {
    const inKnown = isInKnownCidrs(ip, condition.known_cidrs);
    if (condition.match === "in_known_cidr" && inKnown) {
      results.push({ matched_ip: ip, ip_classification: "cloud provider" });
    } else if (condition.match === "not_in_known_cidr" && !inKnown) {
      results.push({ matched_ip: ip, ip_classification: "unknown host" });
    }
  }
  return results;
}
