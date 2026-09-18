// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Correlating the two observations of one tool call.
 *
 * When an agent's MCP traffic is routed through the Omnodex proxy, a single
 * call is seen twice: once by the platform hook, before the call leaves the
 * agent, and once by the proxy, as it forwards the call upstream. Both write
 * a `tool.invoked` event, and nothing about the two events says they describe
 * the same thing:
 *
 *   hook   tool_name mcp__omnodex__filesystem__read_text_file
 *          mcp_server omnodex        session <the agent's>
 *   proxy  tool_name filesystem__read_text_file
 *          mcp_server filesystem     session <the proxy's own uuid>
 *
 * The tool_call_ids differ (the hook carries the platform's, the proxy mints
 * its own), the session ids are unrelated (the proxy never learns the agent's),
 * and the clocks differ (the hook's timestamp is the shim subprocess's, taken
 * before the call is forwarded at all).
 *
 * This runs over the read model, never at write time. The append-only log
 * keeps both events exactly as they were observed; only the derived view
 * decides they were one call. That ordering matters because correlation is a
 * judgement that improves with hindsight, and a log that has already applied
 * one cannot be re-judged.
 *
 * ## What identifies a pair
 *
 * Three things have to agree.
 *
 * **The tool name.** The proxy composes `<server>__<tool>`; the platform
 * composes `mcp__<server>__<whatever the proxy offered>`. So the proxy's
 * tool_name is a suffix of the hook's, after a `__`. This is deliberately not
 * a per-platform rule: it holds for any prefixing scheme, and assumes only
 * that the platform passes characters through rather than rewriting them.
 * That assumption is measured for Claude Code, and recorded in
 * `hooks-provider/test/fixtures/tool-name-mapping.json`.
 *
 * **The arguments.** The proxy forwards the agent's arguments unchanged, so
 * the two parameter objects are normally identical. They are not always
 * comparable by value: an upstream configured with `redact_parameters` has
 * its values replaced before the proxy records them, while the hook still
 * holds the originals. The key set survives redaction, so the shape is
 * compared always and the values only when neither side was redacted. This
 * is the part that separates two calls to the same tool in the same window.
 *
 * **The time.** The hook fires first, necessarily: PreToolUse runs before the
 * call reaches the proxy. So a candidate proxy call must start at or after
 * the hook's, within a window. The window is generous because the hook's
 * clock is a subprocess's; a measured pair on a WSL checkout was 1.4s apart.
 *
 * ## What it does not do
 *
 * It does not dedup. Both rows stay in the read model, and both stay in the
 * log; they simply carry the same `correlation_id`, so a consumer can show
 * one call with two sources and count it once. Dropping one would lose
 * whichever attribution it was carrying, and the proxy's upstream server name
 * is the better one precisely because the hook cannot see it.
 */

import type { SessionRow, ToolCallRow } from "./read-model.js";

/**
 * How long after a hook's tool.invoked a proxy tool.invoked may start and
 * still be considered the same call. Wide on purpose: the hook timestamp
 * comes from the shim subprocess, so this covers process startup, not just
 * the hop to the proxy.
 */
export const DEFAULT_WINDOW_MS = 10_000;

export interface CorrelateOptions {
  /** Override the matching window. Defaults to DEFAULT_WINDOW_MS. */
  windowMs?: number;
}

/** One matched pair, and what the derived model should record for it. */
export interface Correlation {
  /** Stable id shared by both rows. Derived from the hook's tool_call_id. */
  correlation_id: string;
  /** The hook's row. */
  hook_tool_call_id: string;
  /** The proxy's row. */
  proxy_tool_call_id: string;
  /**
   * The upstream server that actually served the call, which only the proxy
   * knows. The hook can at best name the proxy itself.
   */
  upstream_mcp_server: string;
}

/** A tool call with the session context correlation needs. */
export interface CorrelationInput {
  sessions: SessionRow[];
  /** Every tool call in the read model, from every session. */
  toolCalls: ToolCallRow[];
}

/**
 * Match hook-observed tool calls against proxy-observed ones.
 *
 * Deterministic and order-independent: candidates are considered oldest
 * first and each row is claimed at most once, so two identical calls in quick
 * succession pair up in the order they happened rather than both racing for
 * the same partner.
 */
export function correlateToolCalls(
  input: CorrelationInput,
  options: CorrelateOptions = {},
): Correlation[] {
  const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;

  const interceptorOf = new Map(
    input.sessions.map((s) => [s.session_id, s.interceptor as string]),
  );
  const isProxyRow = (row: ToolCallRow): boolean =>
    (row.interceptor ?? interceptorOf.get(row.session_id)) === "mcp-proxy";

  const proxyRows: ToolCallRow[] = [];
  const hookRows: ToolCallRow[] = [];
  for (const row of input.toolCalls) {
    (isProxyRow(row) ? proxyRows : hookRows).push(row);
  }
  if (proxyRows.length === 0 || hookRows.length === 0) return [];

  // Index the proxy side by tool name: the suffix test is the cheap filter,
  // and a proxy tool_name is exactly the suffix a hook name would carry.
  const byToolName = new Map<string, ToolCallRow[]>();
  for (const row of proxyRows) {
    const bucket = byToolName.get(row.tool_name);
    if (bucket) bucket.push(row);
    else byToolName.set(row.tool_name, [row]);
  }
  for (const bucket of byToolName.values()) {
    bucket.sort((a, b) => a.started_at.localeCompare(b.started_at));
  }

  const claimed = new Set<string>();
  const out: Correlation[] = [];

  const orderedHooks = [...hookRows].sort((a, b) =>
    a.started_at.localeCompare(b.started_at),
  );

  for (const hook of orderedHooks) {
    const suffix = upstreamSuffix(hook.tool_name);
    if (suffix === null) continue;

    const candidates = byToolName.get(suffix);
    if (!candidates) continue;

    const hookStart = Date.parse(hook.started_at);
    if (Number.isNaN(hookStart)) continue;

    for (const proxy of candidates) {
      if (claimed.has(proxy.tool_call_id)) continue;

      const proxyStart = Date.parse(proxy.started_at);
      if (Number.isNaN(proxyStart)) continue;
      // The hook necessarily fires first, so a proxy call that started before
      // it belongs to some earlier hook call, not this one.
      if (proxyStart < hookStart) continue;
      if (proxyStart - hookStart > windowMs) break; // sorted: later ones too

      if (!parametersMatch(hook.parameters_json, proxy.parameters_json)) continue;

      claimed.add(proxy.tool_call_id);
      out.push({
        correlation_id: hook.tool_call_id,
        hook_tool_call_id: hook.tool_call_id,
        proxy_tool_call_id: proxy.tool_call_id,
        upstream_mcp_server: proxy.mcp_server,
      });
      break;
    }
  }

  return out;
}

/**
 * The part of an agent tool name that a proxy would have offered, or null if
 * this is not a call the proxy could have served.
 *
 * `mcp__omnodex__filesystem__read_text_file` yields
 * `filesystem__read_text_file`: everything after the first `__` that follows
 * the `mcp__` prefix. A built-in tool such as `Bash` yields null, and so does
 * a direct MCP tool with no second `__`, since the proxy always adds one for
 * its upstream prefix.
 */
export function upstreamSuffix(toolName: string): string | null {
  if (!toolName.startsWith("mcp__")) return null;
  const rest = toolName.slice("mcp__".length);
  const sep = rest.indexOf("__");
  if (sep <= 0) return null;
  const suffix = rest.slice(sep + 2);
  return suffix.length > 0 ? suffix : null;
}

const REDACTED_SENTINEL = "[REDACTED]";

/**
 * Whether two recorded parameter objects could be the same call's arguments.
 *
 * Compares values when both sides carry real ones, and falls back to the key
 * set when either was redacted by the proxy's `redact_parameters`. The
 * fallback is weaker, which is the honest trade: without it, redaction would
 * switch correlation off entirely for the upstreams most worth watching.
 */
function parametersMatch(hookJson: string, proxyJson: string): boolean {
  if (hookJson === proxyJson) return true;

  let hook: unknown;
  let proxy: unknown;
  try {
    hook = JSON.parse(hookJson);
    proxy = JSON.parse(proxyJson);
  } catch {
    return false;
  }

  if (!isPlainObject(hook) || !isPlainObject(proxy)) return false;

  const hookKeys = Object.keys(hook).sort();
  const proxyKeys = Object.keys(proxy).sort();
  if (hookKeys.length !== proxyKeys.length) return false;
  for (let i = 0; i < hookKeys.length; i++) {
    if (hookKeys[i] !== proxyKeys[i]) return false;
  }

  if (isRedacted(proxy) || isRedacted(hook)) return true;

  // Same keys, different values, neither redacted: two different calls to the
  // same tool.
  return false;
}

/** Every value replaced by the proxy's redaction sentinel. */
function isRedacted(params: Record<string, unknown>): boolean {
  const values = Object.values(params);
  return values.length > 0 && values.every((v) => v === REDACTED_SENTINEL);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
