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

import { splitMcpToolName } from "@omnodex/shared";
import { correlateToolCalls, type CorrelateOptions, type Correlation } from "./correlate.js";
import type { ReadModelStore, SessionRow, ToolCallRow } from "./read-model.js";

export interface CorrelationSummary {
  /** Pairs found in this pass. */
  correlations: Correlation[];
  /** Rows whose correlation_id or mcp_server changed. */
  rowsUpdated: number;
  /** Sessions whose mcp_servers list changed. */
  sessionsUpdated: number;
  /** Findings that gained their pair's correlation_id. */
  risksUpdated: number;
}

/**
 * Correlate every tool call in the store and record what was found.
 *
 * Both rows of a pair keep their place; they gain a shared correlation_id,
 * and so does every finding raised against either of them.
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

  const sessionsUpdated = await reconcileSessionServers(store, sessions, toolCalls, correlations);

  // Findings follow their calls: the hook and the proxy can each judge the
  // same routed call, and the shared id lets readers count it once.
  let risksUpdated = 0;
  for (const c of correlations) {
    risksUpdated += await store.setRiskCorrelation(
      [c.hook_tool_call_id, c.proxy_tool_call_id],
      c.correlation_id,
    );
  }

  return { correlations, rowsUpdated, sessionsUpdated, risksUpdated };
}

/**
 * Bring each hook session's mcp_servers in line with where its calls went.
 *
 * The projector adds a call's server to the session as it applies the event,
 * and for a routed call that server is the name the agent registered the
 * proxy under ("omnodex"), because that is all the hook can see. Once the
 * call is correlated its row names the upstream instead, so the session
 * should too: the upstream is added, and the registration name is removed
 * unless some call in the session still stands under it (a proxy tool that
 * is never routed, such as omnodex_status, or a call that found no pair).
 *
 * The registration name is read from the hook's tool_name rather than its
 * mcp_server, which a previous pass has already rewritten. That keeps this
 * idempotent: a second pass computes the same list and writes nothing.
 */
async function reconcileSessionServers(
  store: ReadModelStore,
  sessions: SessionRow[],
  toolCalls: ToolCallRow[],
  correlations: Correlation[],
): Promise<number> {
  const byId = new Map(toolCalls.map((row) => [row.tool_call_id, row]));
  const serverOf = new Map(toolCalls.map((row) => [row.tool_call_id, row.mcp_server]));

  // Per hook session: registration names its routed calls came through, and
  // the upstreams they reached.
  const routed = new Map<string, { registrations: Set<string>; upstreams: string[] }>();
  for (const c of correlations) {
    const hook = byId.get(c.hook_tool_call_id);
    if (!hook) continue;
    const sessionId = hook.session_id;
    serverOf.set(c.hook_tool_call_id, c.upstream_mcp_server);

    let entry = routed.get(sessionId);
    if (!entry) {
      entry = { registrations: new Set(), upstreams: [] };
      routed.set(sessionId, entry);
    }
    const registration = splitMcpToolName(hook.tool_name)?.mcpServer;
    if (registration && registration !== c.upstream_mcp_server) {
      entry.registrations.add(registration);
    }
    if (!entry.upstreams.includes(c.upstream_mcp_server)) {
      entry.upstreams.push(c.upstream_mcp_server);
    }
  }
  if (routed.size === 0) return 0;

  // Servers each session's calls stand under after this pass.
  const serversInUse = new Map<string, Set<string>>();
  for (const row of toolCalls) {
    let used = serversInUse.get(row.session_id);
    if (!used) {
      used = new Set();
      serversInUse.set(row.session_id, used);
    }
    used.add(serverOf.get(row.tool_call_id) ?? row.mcp_server);
  }

  let sessionsUpdated = 0;
  for (const session of sessions) {
    const entry = routed.get(session.session_id);
    if (!entry) continue;
    const used = serversInUse.get(session.session_id) ?? new Set<string>();

    const next = session.mcp_servers.filter(
      (name) => !entry.registrations.has(name) || used.has(name),
    );
    for (const upstream of entry.upstreams) {
      if (!next.includes(upstream)) next.push(upstream);
    }

    if (!sameList(next, session.mcp_servers)) {
      await store.patchSession(session.session_id, { mcp_servers: next });
      sessionsUpdated++;
    }
  }
  return sessionsUpdated;
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}
