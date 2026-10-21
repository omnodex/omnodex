// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_OUTBOUND_KNOWN_IP, RULE_OUTBOUND_UNKNOWN_IP
 *
 * Two rules that together provide tiered detection for calls that name raw
 * IPv4 or IPv6 addresses instead of hostnames, including an address nested
 * in another URL's query (redirect and proxy parameters). They read what
 * the call names, not observed traffic.
 *
 * RULE_OUTBOUND_KNOWN_IP (MEDIUM)
 *   Fires when the destination IP falls within a known major cloud provider
 *   CIDR range (AWS, GCP, Azure, Cloudflare, Fastly). Using a bare IP to
 *   reach cloud infrastructure is unusual -- legitimate SDKs use hostnames --
 *   but could be a misconfigured client rather than an attack.
 *
 * RULE_OUTBOUND_UNKNOWN_IP (HIGH)
 *   Fires when the destination IP is outside all known CIDR ranges. This is
 *   the stronger signal: the agent is contacting an unrecognized host, which
 *   may indicate C2 callback, prompt injection exfiltration, or supply chain
 *   compromise. Private network, link-local and metadata addresses fire
 *   here too, labeled by their class, as reaching into an internal network
 *   is as notable as reaching an unknown public host.
 *
 * Design note: embedding CIDR ranges as data keeps rules serializable and
 * diff-able. The list covers representative stable blocks -- not exhaustive
 * provider space -- so that it stays maintainable without a live feed.
 * Unknown-IP findings (HIGH) appear for IPs outside this list; operators
 * should treat them as "investigate", not definitive compromise.
 *
 * Sources:
 *   AWS:        https://ip-ranges.amazonaws.com/ip-ranges.json
 *   GCP:        https://www.gstatic.com/ipranges/cloud.json
 *   Azure:      https://www.microsoft.com/en-us/download/details.aspx?id=56519
 *   Cloudflare: https://www.cloudflare.com/ips/
 *   Fastly:     https://api.fastly.com/public-ip-list
 *   Google:     https://www.gstatic.com/ipranges/goog.json
 *
 * Azure publishes its ranges only as a dated download, so its IPv6 space is
 * not listed; an Azure IPv6 address reads as unknown.
 *
 * Tier:     community
 * Severity: MEDIUM (known CIDRs) / HIGH (unknown CIDRs)
 */

import type { RuleDefinition } from "../../types.js";

/**
 * Representative stable CIDR blocks for major cloud and CDN providers.
 * IPv4 updated as of Q1 2026, IPv6 as of October 2026. Covers primary compute and CDN ranges but is not
 * exhaustive -- providers publish full machine-readable lists linked above.
 */
const KNOWN_CLOUD_CIDRS: string[] = [
  // AWS EC2 and managed services (primary compute blocks)
  "3.0.0.0/8",
  "13.32.0.0/12",
  "18.0.0.0/8",
  "34.192.0.0/10",
  "44.192.0.0/11",
  "52.0.0.0/8",
  "54.0.0.0/8",
  "99.77.0.0/18",
  "107.20.0.0/14",
  "174.129.0.0/16",

  // GCP Compute Engine and managed services
  "34.64.0.0/10",
  "35.184.0.0/13",
  "104.154.0.0/15",
  "104.196.0.0/14",
  "130.211.0.0/22",
  "142.250.0.0/15",
  "172.217.0.0/16",
  "216.58.192.0/19",

  // Azure Virtual Machines and PaaS
  "13.64.0.0/11",
  "20.0.0.0/8",
  "40.64.0.0/10",
  "51.0.0.0/11",
  "52.224.0.0/11",
  "65.52.0.0/14",
  "104.40.0.0/13",
  "168.61.0.0/16",

  // Cloudflare CDN and Workers
  "1.0.0.0/24",
  "1.1.1.0/24",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "104.16.0.0/12",
  "162.158.0.0/15",
  "172.64.0.0/13",
  "173.245.48.0/20",
  "188.114.96.0/20",
  "190.93.240.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",

  // Fastly CDN
  "23.235.32.0/20",
  "43.249.72.0/22",
  "103.244.50.0/24",
  "151.101.0.0/16",
  "157.52.64.0/18",
  "172.111.64.0/18",
  "185.31.16.0/22",
  "199.27.72.0/21",
  "199.232.0.0/16",

  // IPv6, checked October 2026. AWS: the allocations that hold its regional
  // EC2 blocks. Google: Cloud and Google front ends. Cloudflare and Fastly:
  // their full published lists.
  "2600:1f00::/24",
  "2406:da00::/24",
  "2a05:d000::/24",
  "2600:1900::/28",
  "2001:4860::/32",
  "2607:f8b0::/32",
  "2a00:1450::/32",
  "2404:6800::/32",
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
  "2a04:4e40::/32",
  "2a04:4e42::/31",
  "2a04:4e44::/32",
];

export const RULE_OUTBOUND_KNOWN_IP: RuleDefinition = {
  rule_id: "RULE_OUTBOUND_KNOWN_IP",
  version: "1.1.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "ip_destination",
      match: "in_known_cidr",
      known_cidrs: KNOWN_CLOUD_CIDRS,
    },
  ],
  severity: "MEDIUM",
  category: "unexpected_network_destination",
  description_template:
    "{{tool_name}} names raw IP {{matched_ip}} ({{ip_classification}} range) as a destination. Legitimate clients should use hostnames.",
};

export const RULE_OUTBOUND_UNKNOWN_IP: RuleDefinition = {
  rule_id: "RULE_OUTBOUND_UNKNOWN_IP",
  version: "1.1.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "ip_destination",
      match: "not_in_known_cidr",
      known_cidrs: KNOWN_CLOUD_CIDRS,
    },
  ],
  severity: "HIGH",
  category: "unexpected_network_destination",
  description_template:
    "{{tool_name}} names raw IP {{matched_ip}} ({{ip_classification}}) as a destination, outside all known cloud provider ranges.",
};
