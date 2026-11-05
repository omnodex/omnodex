// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * What the local dashboard page and its server say to each other about
 * actions on a finding. Types only, so the page can import them.
 */

import type { PolicyEntry, RiskSeverity } from "@omnodex/shared";

export type PolicyAction = "block" | "hold" | "allow" | "mute" | "severity";
export type TargetKind = "rule" | "path" | "destination" | "command" | "tool";
export type PolicyScope = "machine" | "account";

export interface TargetChoice {
  kind: TargetKind;
  /** Editable: a path, host or command start. Empty for the whole rule. */
  value: string;
  /** The server, for a tool target. */
  server?: string;
}

export interface DraftRequest {
  session_id: string;
  rule_id: string;
  related_event_id: string;
  action: PolicyAction;
  /** The new severity, for the severity action. */
  severity?: RiskSeverity;
  target?: TargetChoice;
  /** Only in the finding's project, not everywhere. */
  here?: boolean;
  scope: PolicyScope;
}

export type SaveBlock = "loosens" | "account" | "pro" | "no-change";

export interface Draft {
  /** The targets the finding's call offers, the first being the whole rule. */
  choices: TargetChoice[];
  /** The finding's project folder, when it has one. */
  project?: string;
  /** The rule's severity before any entry changed it. */
  own_severity: RiskSeverity;
  /** Whether this machine's plan includes block and hold. */
  guardrails: boolean;
  /** Present when the request describes a valid entry. */
  entry?: PolicyEntry;
  summary?: string;
  /** The `omnodex policy add` command that makes it. */
  command?: string;
  /** Present for the whole account: the hosted Policies page with the entry in its fragment. */
  hosted_url?: string;
  /** Why this dashboard will not save it, or absent when it will. */
  save_blocked?: SaveBlock;
  preview?: Preview;
  error?: string;
}

export interface Preview {
  days: number;
  /** Findings the entry decides something for. */
  reach: number;
  muted: number;
  unmuted: number;
  raised: number;
  lowered: number;
}
