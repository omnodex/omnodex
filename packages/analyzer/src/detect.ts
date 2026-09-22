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

import type { TraceEvent } from "@omnodex/shared";
import type { DetectionResult } from "./types.js";
import { createEvaluator } from "./evaluator.js";
import { RuleRegistry } from "./registry.js";
import type { MachineState } from "./machine-state.js";

/**
 * Scan all events for a single session, detect new risks, and return
 * RiskDetectedEvent objects to be appended to the event log.
 *
 * @param events      All events for the session in log order.
 * @param newEventId  Factory that returns unique event IDs (UUID v4 etc.).
 * @param registry    Optional RuleRegistry. Defaults to the standard registry
 *                    with community rules active.
 * @param opts        machineState: persistent state for machine-scope rules,
 *                    shared across the sessions of one run.
 */
export function detectRisks(
  events: TraceEvent[],
  newEventId: () => string,
  registry: RuleRegistry = new RuleRegistry(),
  opts: { machineState?: MachineState } = {},
): DetectionResult {
  const sessionId = events[0]?.session_id ?? "unknown";
  const evaluator = createEvaluator({
    host: "batch",
    registry,
    newEventId,
    machineState: opts.machineState,
  });

  // Findings already in the log come after the calls they describe, so they
  // are all seeded before any call is judged.
  for (const e of events) {
    if (e.event_type === "risk.detected") evaluator.evaluate(e);
  }

  const newEvents = [];
  for (const e of events) {
    if (e.event_type === "session.started" || e.event_type === "tool.invoked") {
      newEvents.push(...evaluator.evaluate(e));
    }
  }

  return { sessionId, newEvents, skipped: evaluator.stats().skipped };
}
