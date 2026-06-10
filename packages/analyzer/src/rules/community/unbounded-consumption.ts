// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Unbounded consumption detection rules (OWASP LLM10).
 *
 * Detects runaway agent loops, recursive tool call storms, and resource
 * exhaustion patterns by tracking tool call frequency within sliding time
 * windows.
 *
 * RULE_UNBOUNDED_CONSUMPTION_BURST (MEDIUM)
 *   Fires when 50+ tool calls occur within a 60-second window.
 *   Typical legitimate sessions rarely exceed 30 calls/minute even during
 *   active coding. 50/60s indicates a likely loop or runaway automation.
 *
 * RULE_UNBOUNDED_CONSUMPTION_SUSTAINED (HIGH)
 *   Fires when 200+ tool calls occur within a 5-minute window.
 *   A sustained high rate over 5 minutes is almost certainly a runaway
 *   agent rather than a brief burst of legitimate activity.
 *
 * Thresholds are embedded in the rule definitions but designed to be
 * overridable via the Pro-tier rule customization system when it ships.
 *
 * Source:
 *   OWASP Top 10 for LLM Applications 2025, LLM10: Unbounded Consumption.
 *
 * Tier:     community
 * Category: unbounded_consumption
 */

import type { RuleDefinition } from "../../types.js";

/**
 * Short burst detection: 50 tool calls in 60 seconds.
 *
 * Catches: tight infinite loops, recursive tool chains without termination,
 * prompt injection causing rapid-fire tool invocation.
 *
 * Severity MEDIUM because a brief burst may be a legitimate bulk operation
 * (e.g., reading 50 files in sequence). The sustained rule (HIGH) catches
 * patterns that persist beyond what any legitimate workflow would produce.
 */
export const RULE_UNBOUNDED_CONSUMPTION_BURST: RuleDefinition = {
  rule_id: "RULE_UNBOUNDED_CONSUMPTION_BURST",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "rate_threshold",
      window_seconds: 60,
      threshold: 50,
    },
  ],
  severity: "MEDIUM",
  category: "unbounded_consumption",
  description_template:
    "Unusual tool call burst detected: {{rate_count}} calls in {{rate_window}}s. " +
    "This may indicate a runaway agent loop or recursive automation.",
};

/**
 * Sustained overload detection: 200 tool calls in 5 minutes.
 *
 * Catches: slower loops that stay just under the burst threshold but
 * accumulate dangerous volume, multi-step recursive chains, agent storms
 * from prompt injection that sustain over time.
 *
 * Severity HIGH because 200 calls in 5 minutes (40/min sustained) far
 * exceeds any normal interactive or automated workflow pattern.
 */
export const RULE_UNBOUNDED_CONSUMPTION_SUSTAINED: RuleDefinition = {
  rule_id: "RULE_UNBOUNDED_CONSUMPTION_SUSTAINED",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "rate_threshold",
      window_seconds: 300,
      threshold: 200,
    },
  ],
  severity: "HIGH",
  category: "unbounded_consumption",
  description_template:
    "Sustained high tool call rate: {{rate_count}} calls in {{rate_window}}s. " +
    "Strong indicator of a runaway agent loop or resource exhaustion attack.",
};
