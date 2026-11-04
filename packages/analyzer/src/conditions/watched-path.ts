// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * watched_path condition evaluator: the call changes, moves or deletes a
 * path the user chose to watch. Reading one never matches. A call made before
 * the watch was added never matches, so a background pass over old events
 * does not report them.
 *
 * Only what the call itself names can be seen. A script run later, or another
 * process, changes a file without any of this noticing.
 */

import type { ToolInvokedEvent } from "@omnodex/shared";
import { watchHits } from "../policy.js";
import type { EvaluationContext, MatchContext } from "../types.js";

export function evaluateWatchedPath(event: ToolInvokedEvent, context: EvaluationContext): Partial<MatchContext>[] {
  const out: Partial<MatchContext>[] = [];
  for (const entry of context.watches ?? []) {
    if (entry.created_at && event.occurred_at < entry.created_at) continue;
    const hits = watchHits(entry, event, { home: context.home, projectRoots: context.workspaceRoots });
    if (hits[0] !== undefined) out.push({ matched_path: hits[0] });
  }
  return out;
}
