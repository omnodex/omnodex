// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_OUTBOUND_KNOWN_IP, RULE_OUTBOUND_UNKNOWN_IP
 *
 * Two rules that together provide tiered detection for outbound calls to
 * raw IPv4 addresses instead of hostnames.
 *
 * RULE_OUTBOUND_KNOWN_IP (MEDIUM)
 *   Fires when the destination IP falls within a known major cloud provider
 *   CIDR range (AWS, GCP, Azure, Cloudflare, Fastly). Using a bare IP to
 *   reach cloud infrastructure is unusual -- legitimate SDKs use hostnames --
 *   but could be a misconfigured client rather than an attack.
 *
 * RULE_OUTBOUND_UNKNOWN_IP (HIGH)
 *   Fires when the destination IP is outside all known CIDR ranges. This is
 *   the stronger signal: the agent is contacting an unrecognised host, which
 *   may indicate C2 callback, prompt injection exfiltration, or supply chain
 *   compromise.
 *
 * Design note: embedding CIDR ranges as data keeps rules serialisable and
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
 *
 * Tier:     community
 * Severity: MEDIUM (known CIDRs) / HIGH (unknown CIDRs)
 */

import type { RuleDefinition } from "../../types.js";

/**
 * Representative stable CIDR blocks for major cloud and CDN providers.
 * Updated as of Q1 2026. Covers primary compute and CDN ranges but is not
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
];

export const RULE_OUTBOUND_KNOWN_IP: RuleDefinition = {
  rule_id: "RULE_OUTBOUND_KNOWN_IP",
  version: "1.0.0",
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
    "Outbound call to raw IP {{matched_ip}} ({{ip_classification}} range) via {{tool_name}}. Legitimate clients should use hostnames.",
};

export const RULE_OUTBOUND_UNKNOWN_IP: RuleDefinition = {
  rule_id: "RULE_OUTBOUND_UNKNOWN_IP",
  version: "1.0.0",
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
    "Outbound call to raw IP {{matched_ip}} ({{ip_classification}}) via {{tool_name}}. Destination is outside all known cloud provider ranges.",
};
