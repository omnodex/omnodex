// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * ip_destination condition evaluator.
 *
 * Detects calls that name raw IPv4 or IPv6 addresses and classifies them by
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
 * Only what the call reaches counts: IP hosts among the call's destinations
 * (URLs, including one nested in another's query, and the arguments of
 * network programs), and bare IPv4 literals in a command that runs. An
 * address in content written to a file, or in a search pattern, is not a
 * destination. Loopback addresses are never outbound. This is what the call
 * names, read from its parameters, not observed network traffic.
 *
 * An address outside the known ranges is labeled by its class: a private
 * network or link-local address, a cloud metadata service, or an unknown
 * public host.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { classifyHost, normalizeAction, type IpClass } from "../action.js";
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

/** An IPv6 address as a 128-bit number, or null when it does not parse. */
function ipv6ToBigInt(ip: string): bigint | null {
  let text = ip.toLowerCase();
  // A trailing dotted IPv4 part (::ffff:1.2.3.4) becomes two groups.
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(text);
  if (v4) {
    const n = ipToUint32(v4[1]!);
    text = text.slice(0, v4.index) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

function isIpv6InCidr(ip: string, base: string, prefixLen: number): boolean {
  const a = ipv6ToBigInt(ip);
  const b = ipv6ToBigInt(base);
  if (a === null || b === null) return false;
  const shift = BigInt(128 - prefixLen);
  return a >> shift === b >> shift;
}

function isIpInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  if (slash === -1) return ip === cidr;
  const base = cidr.slice(0, slash);
  const prefixLen = parseInt(cidr.slice(slash + 1), 10);
  // Each family matches only its own ranges.
  const v6 = ip.includes(":");
  if (v6 !== base.includes(":")) return false;
  if (v6) return isIpv6InCidr(ip, base, prefixLen);
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
 * The raw IP addresses a tool call reaches: IPv4 and IPv6 destinations of
 * the normalized action, plus bare IPv4 literals in a command that runs.
 * Bare IPv6 is read only from URLs and network program arguments, as text
 * such as a time (12:30:45) or a MAC address looks too much like it.
 * Returns a deduplicated list.
 */
export function extractRawIps(event: ToolInvokedEvent): string[] {
  const action = normalizeAction(event);
  const seen = new Set<string>();
  const add = (ip: string): void => {
    if (SKIP_IPS.has(ip) || classifyHost(ip) === "loopback") return;
    seen.add(ip);
  };
  for (const d of action.destinations) {
    if (d.ip !== undefined) add(d.host);
  }
  if (action.exec !== null) {
    IPV4_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = IPV4_RE.exec(action.exec)) !== null) {
      const ip = m[1]!;
      if (ip.split(".").every((o) => Number(o) <= 255)) add(ip);
    }
  }
  return [...seen];
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

/** How an address outside the known ranges is described. */
const CLASS_LABELS: Record<IpClass, string> = {
  public: "unknown host",
  private: "private network address",
  "link-local": "link-local address",
  metadata: "cloud metadata service",
  loopback: "loopback address",
};

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
      results.push({ matched_ip: ip, ip_classification: CLASS_LABELS[classifyHost(ip) ?? "public"] });
    }
  }
  return results;
}
