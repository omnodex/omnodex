// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Evidence for findings on a sequence of calls: each call's role, a one-line
 * summary of what it did, and where the last one went.
 *
 * Summaries are built from the normalized action (what a call reads,
 * writes, stages and reaches), never from the command text, because a
 * command can carry the credential the finding is about.
 */

import type {
  EvidenceDestination,
  EvidenceRole,
  EvidenceStep,
  FindingEvidence,
  ToolInvokedEvent,
} from "@omnodex/shared";
import { normalizeAction, shellWords, type StagingOp } from "./action.js";
import type { MatchContext, RuleDefinition } from "./types.js";

const STAGING_VERB: Readonly<Record<StagingOp, string>> = {
  archive: "Archived",
  encode: "Encoded",
  encrypt: "Encrypted",
  clipboard: "Copied to the clipboard",
};

/** The external host a call reaches, if any. */
export function evidenceDestination(event: ToolInvokedEvent): EvidenceDestination | undefined {
  const action = normalizeAction(event);
  if (!action.outbound) return undefined;
  const d = action.destinations.find((x) => x.ipClass !== "loopback");
  if (!d) return undefined;
  return {
    host: d.host,
    ...(d.scheme ? { scheme: d.scheme } : {}),
    ...(d.port !== undefined ? { port: d.port } : {}),
    ...(d.ipClass ? { ip_class: d.ipClass } : {}),
    ...(d.ip ? { raw_ip: true } : {}),
  };
}

/**
 * One line on what a call did. A sink is described by where it went first,
 * any other step by what it staged first, since that is what links it to
 * the next step.
 */
export function summarizeCall(
  event: ToolInvokedEvent,
  role: EvidenceRole,
  context: Partial<MatchContext> = {},
): string {
  const action = normalizeAction(event);
  const network = (): string | null => {
    if (!action.outbound) return null;
    const host = evidenceDestination(event)?.host;
    return host ? `Network call to ${host}` : "Network call to an external endpoint";
  };
  const staging = (): string | null => {
    const step = action.staging[0];
    if (!step) return null;
    return `${STAGING_VERB[step.op]} with ${step.program}${step.output ? ` to ${step.output}` : ""}`;
  };

  const first = role === "sink" ? network() ?? staging() : staging() ?? network();
  if (first) return first;

  const written = action.kinds.has("write") ? (context.matched_path ?? action.writes[0]) : undefined;
  if (written) return `Wrote ${written}`;
  const read = context.matched_path ?? action.paths[0];
  if (read) return `Read ${read}`;
  if (action.exec) {
    const program = shellWords(action.exec)[0];
    if (program) return `Ran ${program}`;
  }
  return `Called ${event.tool_name}`;
}

function labelsOf(context: Partial<MatchContext>): string[] | undefined {
  const labels = [
    context.matched_label,
    ...(context.credential_types ?? []),
    context.matched_domain,
  ].filter((l): l is string => !!l);
  return labels.length ? [...new Set(labels)] : undefined;
}

function step(event: ToolInvokedEvent, role: EvidenceRole, context: Partial<MatchContext>): EvidenceStep {
  const labels = labelsOf(context);
  return {
    tool_call_id: event.tool_call_id,
    role,
    summary: summarizeCall(event, role, context),
    ...(labels ? { labels } : {}),
    interceptor: event.interceptor,
  };
}

/**
 * Evidence for a finding whose context names earlier steps, or undefined
 * for a single-event finding. The current event is the last step.
 */
export function buildEvidence(
  rule: RuleDefinition,
  event: ToolInvokedEvent,
  context: MatchContext,
): FindingEvidence | undefined {
  const earlier = context.sequence_steps;
  if (!earlier?.length) return undefined;
  const { sequence_steps: _, sequence_role: role = "sink", sequence_credential: credential, ...own } = context;
  const destination = evidenceDestination(event);
  return {
    steps: [
      ...earlier.map((s) => step(s.event, s.role, s.context)),
      step(event, role, own),
    ],
    ...(destination ? { destination } : {}),
    ...(credential ? { credential } : {}),
    ...(rule.benign_note ? { benign_note: rule.benign_note } : {}),
  };
}
