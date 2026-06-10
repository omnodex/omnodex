// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * detectRisks -- the main entry point for batch risk detection.
 *
 * Runs all active rules against every tool.invoked event in a session's
 * event log slice, deduplicates against already-recorded risk.detected
 * events, and returns new RiskDetectedEvent objects ready to be appended
 * to the log. Idempotent: re-running against the same log produces zero
 * new events once all risks have been recorded.
 *
 * This is the batch interface. For streaming detection, see the streaming
 * detect loop in @omnodex/cli/src/streaming.ts.
 */

import type { RiskDetectedEvent, TraceEvent } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";
import type { DetectionResult } from "./types.js";
import { RuleEngine } from "./engine.js";
import { RuleRegistry } from "./registry.js";

/**
 * Scan all events for a single session, detect new risks, and return
 * RiskDetectedEvent objects to be appended to the event log.
 *
 * @param events      All events for the session in log order.
 * @param newEventId  Factory that returns unique event IDs (UUID v4 etc.).
 * @param registry    Optional RuleRegistry. Defaults to the standard registry
 *                    with community rules active.
 */
export function detectRisks(
  events: TraceEvent[],
  newEventId: () => string,
  registry: RuleRegistry = new RuleRegistry(),
): DetectionResult {
  const sessionId = events[0]?.session_id ?? "unknown";

  // Build a set of (rule_id, related_event_id) pairs that already exist in
  // the log so we can skip re-emitting them.
  const existing = new Set<string>();
  for (const e of events) {
    if (e.event_type === "risk.detected") {
      existing.add(`${e.rule_id}::${e.related_event_id}`);
    }
  }

  const engine = new RuleEngine(registry.getRules());
  const newEvents: RiskDetectedEvent[] = [];
  let skipped = 0;

  for (const event of events) {
    if (event.event_type !== "tool.invoked") continue;

    const findings = engine.evaluate(event);

    for (const finding of findings) {
      const dedupKey = `${finding.rule_id}::${event.tool_call_id}`;

      if (existing.has(dedupKey)) {
        skipped++;
        continue;
      }
      // Mark as seen so intra-run duplicates are also suppressed.
      existing.add(dedupKey);

      const now = new Date().toISOString();
      newEvents.push({
        schema_version: SCHEMA_VERSION,
        event_id: newEventId(),
        session_id: event.session_id,
        occurred_at: now,
        recorded_at: now,
        interceptor: "analyzer",
        event_type: "risk.detected",
        severity: finding.severity,
        category: finding.category,
        description: finding.description,
        related_event_id: event.tool_call_id,
        rule_id: finding.rule_id,
      });
    }
  }

  return { sessionId, newEvents, skipped };
}
