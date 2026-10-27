// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * remembered_secret condition evaluator.
 *
 * Matches an outbound call that carries a value this machine earlier saw as
 * a secret (see ../known-secrets.ts), wherever it sits in the call: the
 * point is the send that has no header or `token=` around it. It does not
 * match when every external host the call reaches is the secret's own
 * provider or a host the secret was already sent to with its context, when
 * the secret's first sighting is this call or a later one, or when the
 * entry has expired. It only reads the machine state: the evaluator
 * remembers a call's secrets after all rules have judged it, so the call
 * that first shows a secret never matches on it.
 *
 * Without remembered secrets in the context (a bare engine, no evaluator)
 * there is no history to compare against, and the condition never matches.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { isCredentialProvider, normalizeAction } from "../action.js";
import { secretCandidates } from "../known-secrets.js";
import type { EvaluationContext, MatchContext } from "../types.js";

export function evaluateRememberedSecret(
  event: ToolInvokedEvent,
  context: EvaluationContext,
): Partial<MatchContext>[] {
  const state = context.secretState;
  if (!state) return [];
  const action = normalizeAction(event);
  if (!action.outbound) return [];
  const hosts = [...new Set(action.destinations.filter((d) => d.ipClass !== "loopback").map((d) => d.host.toLowerCase()))];
  if (hosts.length === 0) return [];

  const types = new Set<string>();
  let firstSeen = "";
  let destination = "";
  for (const candidate of secretCandidates(event.parameters)) {
    const secret = state.recallSecret(candidate, event.occurred_at);
    if (!secret || secret.firstSeen >= event.occurred_at) continue;
    const foreign = hosts.find((h) => !secret.hosts.includes(h) && !isCredentialProvider(secret.type, h));
    if (!foreign) continue;
    types.add(secret.type);
    if (!firstSeen || secret.firstSeen < firstSeen) firstSeen = secret.firstSeen;
    destination ||= foreign;
  }
  if (types.size === 0) return [];
  return [{
    credential_types: [...types],
    remembered_since: firstSeen.slice(0, 10),
    matched_destination: destination,
  }];
}
