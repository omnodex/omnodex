// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

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

/** One place a credential was used. */
export interface CredentialUse {
  toolCallId: string;
  sessionId: string;
  tool: string;
  server: string;
  at: string;
}

/** One credential, with every call it appeared in, newest first. */
export interface CredentialGroup {
  /** Stable key for the credential within this page; never the raw value. */
  key: string;
  type: string;
  masked: string;
  uses: CredentialUse[];
  firstSeen: string;
  lastSeen: string;
}

/**
 * The ledger grouped by credential rather than by sighting: how many calls
 * carried each one, where, and when it was first and last seen. Groups are
 * ordered by most recent use.
 */
export function groupedLedger(toolCalls: readonly CollapsedToolCallRow[]): CredentialGroup[] {
  const groups = new Map<string, CredentialGroup>();
  let n = 0;
  const ids = new Map<string, string>();
  for (const tc of toolCalls) {
    const seenInCall = new Set<string>();
    for (const { type, value } of findCredentials(tc.parameters_json || "{}", CREDENTIAL_PATTERNS)) {
      const identity = `${type}\u0000${value}`;
      if (seenInCall.has(identity)) continue;
      seenInCall.add(identity);
      let key = ids.get(identity);
      if (!key) {
        key = `cred-${++n}`;
        ids.set(identity, key);
      }
      const use: CredentialUse = { toolCallId: tc.tool_call_id, sessionId: tc.session_id, tool: tc.tool_name, server: tc.mcp_server, at: tc.started_at };
      const g = groups.get(key);
      if (g) {
        g.uses.push(use);
        if (use.at < g.firstSeen) g.firstSeen = use.at;
        if (use.at > g.lastSeen) g.lastSeen = use.at;
      } else {
        groups.set(key, { key, type, masked: maskCredential(value), uses: [use], firstSeen: use.at, lastSeen: use.at });
      }
    }
  }
  const list = [...groups.values()];
  for (const g of list) g.uses.sort((a, b) => b.at.localeCompare(a.at));
  return list.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
}
