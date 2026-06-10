// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/feature-extractor -- metrics extraction
 *
 * Reads the SQLite read model and produces the anonymized metrics,
 * timing distributions, and risk summaries that populate a FeatureBatch.
 * No raw tool names, file paths, or credentials appear in the output.
 */

import type {
  ReadModelStore,
  RiskEventRow,
} from "@omnodex/projection";
import type { FeatureBatch, RiskSeverity } from "@omnodex/shared";
import { importHmacKey, hmacBatch } from "./hasher.js";

export interface ExtractionInput {
  /** Session ID to extract features from. */
  sessionId: string;
  /** Opaque customer ID from license validation. */
  customerId: string;
  /** HMAC salt (hex-encoded). From license response or local fallback. */
  hmacSaltHex: string;
}

/**
 * Extract anonymized features from a single session in the read model.
 * Returns null if the session does not exist.
 */
export async function extractSessionFeatures(
  store: ReadModelStore,
  input: ExtractionInput,
): Promise<FeatureBatch | null> {
  const session = await store.getSession(input.sessionId);
  if (!session) return null;

  const toolCalls = await store.listToolCalls(input.sessionId);
  const riskEvents = await store.listRiskEvents(input.sessionId);
  const fileEvents = await store.listFileEvents(input.sessionId);

  // Metrics
  const eventCount =
    toolCalls.length + riskEvents.length + fileEvents.length + 2; // +2 for session start/end
  const toolCallCount = toolCalls.length;
  const uniqueTools = new Set(toolCalls.map((tc) => tc.tool_name));
  const uniqueServers = new Set(toolCalls.map((tc) => tc.mcp_server));

  // Timing distributions
  const durations = toolCalls
    .map((tc) => tc.duration_ms)
    .filter((d): d is number => d !== null && d > 0)
    .sort((a, b) => a - b);

  const timing = computeTimingStats(durations);

  // Risk summary
  const riskSummary = computeRiskSummary(riskEvents);

  // HMAC-hashed identifiers
  const hmacKey = await importHmacKey(input.hmacSaltHex);
  const hashedToolNames = await hmacBatch(
    hmacKey,
    toolCalls.map((tc) => tc.tool_name),
  );
  const hashedServers = await hmacBatch(
    hmacKey,
    toolCalls.map((tc) => tc.mcp_server),
  );

  // Session hash (HMAC of raw session_id)
  const [sessionHash] = await hmacBatch(hmacKey, [input.sessionId]);

  const batchId = generateBatchId();

  return {
    batch_id: batchId,
    customer_id: input.customerId,
    session_hash: sessionHash,
    timestamp: new Date().toISOString(),
    metrics: {
      event_count: eventCount,
      tool_call_count: toolCallCount,
      unique_tool_count: uniqueTools.size,
      unique_mcp_server_count: uniqueServers.size,
      duration_ms: session.duration_ms ?? 0,
      risk_score: session.risk_score,
    },
    timing,
    risk_summary: riskSummary,
    hashed_identifiers: {
      tool_names: hashedToolNames,
      mcp_servers: hashedServers,
    },
  };
}

function computeTimingStats(durations: number[]): FeatureBatch["timing"] {
  if (durations.length === 0) {
    return {
      mean_tool_duration_ms: 0,
      median_tool_duration_ms: 0,
      p95_tool_duration_ms: 0,
    };
  }

  const sum = durations.reduce((a, b) => a + b, 0);
  const mean = sum / durations.length;

  const mid = Math.floor(durations.length / 2);
  const median =
    durations.length % 2 === 0
      ? (durations[mid - 1] + durations[mid]) / 2
      : durations[mid];

  const p95Idx = Math.min(
    Math.ceil(durations.length * 0.95) - 1,
    durations.length - 1,
  );
  const p95 = durations[p95Idx];

  return {
    mean_tool_duration_ms: Math.round(mean * 100) / 100,
    median_tool_duration_ms: median,
    p95_tool_duration_ms: p95,
  };
}

function computeRiskSummary(
  riskEvents: RiskEventRow[],
): FeatureBatch["risk_summary"] {
  const bySeverity: Record<RiskSeverity, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };
  const byCategory: Record<string, number> = {};
  const ruleIdsFired = new Set<string>();

  for (const re of riskEvents) {
    bySeverity[re.severity] = (bySeverity[re.severity] ?? 0) + 1;
    byCategory[re.category] = (byCategory[re.category] ?? 0) + 1;
    ruleIdsFired.add(re.rule_id);
  }

  return {
    by_severity: bySeverity,
    by_category: byCategory,
    rule_ids_fired: [...ruleIdsFired],
  };
}

function generateBatchId(): string {
  // Dependency-free UUID-like ID
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return (
    "fb_" +
    hex.slice(0, 8) +
    "-" +
    hex.slice(8, 12) +
    "-" +
    hex.slice(12, 16) +
    "-" +
    hex.slice(16, 20) +
    "-" +
    hex.slice(20)
  );
}
