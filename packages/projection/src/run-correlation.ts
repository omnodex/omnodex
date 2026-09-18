// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Drives correlateToolCalls over a read model store and writes the results
 * back onto the rows.
 *
 * A pass, not a projection step. The projector sees one event at a time and
 * cannot know that a call it is applying will be seen again by the proxy a
 * second later, in a different session. So correlation runs after a replay,
 * over the whole model, where both halves are already present.
 *
 * Idempotent: running it twice produces the same rows, and a run after new
 * events have arrived picks up pairs the previous run could not see.
 */

import { correlateToolCalls, type CorrelateOptions, type Correlation } from "./correlate.js";
import type { ReadModelStore } from "./read-model.js";

export interface CorrelationSummary {
  /** Pairs found in this pass. */
  correlations: Correlation[];
  /** Rows whose correlation_id or mcp_server changed. */
  rowsUpdated: number;
}

/**
 * Correlate every tool call in the store and record what was found.
 *
 * Both rows of a pair keep their place; they gain a shared correlation_id.
 * The hook's row also takes the proxy's upstream server name, because the
 * hook could only ever see the proxy itself: a call the agent recorded
 * against "omnodex" actually went to "filesystem", and the latter is what a
 * reader of the dashboard, or a rule about which servers a session touched,
 * needs to see.
 */
export async function runCorrelation(
  store: ReadModelStore,
  options: CorrelateOptions = {},
): Promise<CorrelationSummary> {
  const [sessions, toolCalls] = await Promise.all([
    store.listSessions(),
    store.listAllToolCalls(),
  ]);

  const correlations = correlateToolCalls({ sessions, toolCalls }, options);
  const byId = new Map(toolCalls.map((row) => [row.tool_call_id, row]));

  let rowsUpdated = 0;

  for (const c of correlations) {
    const hook = byId.get(c.hook_tool_call_id);
    const proxy = byId.get(c.proxy_tool_call_id);

    if (hook && (hook.correlation_id !== c.correlation_id || hook.mcp_server !== c.upstream_mcp_server)) {
      await store.patchToolCall(c.hook_tool_call_id, {
        correlation_id: c.correlation_id,
        mcp_server: c.upstream_mcp_server,
      });
      rowsUpdated++;
    }

    if (proxy && proxy.correlation_id !== c.correlation_id) {
      await store.patchToolCall(c.proxy_tool_call_id, {
        correlation_id: c.correlation_id,
      });
      rowsUpdated++;
    }
  }

  return { correlations, rowsUpdated };
}
