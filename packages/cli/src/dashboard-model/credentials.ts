// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

/**
 * The credential ledger: credentials that appear in the tool calls a user
 * is looking at, masked for display. Uses the analyzer's credential patterns
 * and value checks, so the ledger and the credential rules agree on what a
 * credential is. Values never leave the page.
 */

import { CREDENTIAL_PATTERNS, findCredentials } from "@omnodex/analyzer";
import type { CollapsedToolCallRow } from "@omnodex/projection";

export interface LedgerEntry {
  /** The analyzer's type label, such as "bearer" or "github-pat". */
  type: string;
  /** The value, masked: the first 8 and last 4 characters. */
  masked: string;
  tool: string;
  server: string;
  toolCallId: string;
}

/** Keeps the first 8 and last 4 characters of a long value. */
export function maskCredential(value: string): string {
  return value.length <= 8 ? value : `${value.slice(0, 8)}...${value.slice(-4)}`;
}

/** One entry per distinct credential per call, in call order. */
export function credentialLedger(toolCalls: readonly CollapsedToolCallRow[]): LedgerEntry[] {
  const entries: LedgerEntry[] = [];
  const seen = new Set<string>();
  for (const tc of toolCalls) {
    for (const { type, value } of findCredentials(tc.parameters_json || "{}", CREDENTIAL_PATTERNS)) {
      const key = `${type}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push({ type, masked: maskCredential(value), tool: tc.tool_name, server: tc.mcp_server, toolCallId: tc.tool_call_id });
    }
  }
  return entries;
}
