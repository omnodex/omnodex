// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Which verdict a finding gets: the user's policy entries, then the rule's
 * own hint.
 *
 * The entries come from the user's file (its `policy` list, and the older
 * per-rule, per-severity and exception keys read as entries), the account's
 * policy when one has been pulled, and the repository's shared policy file,
 * which can only tighten. evaluatePolicy (../policy.ts) decides between
 * them; this adds the rule's hint beneath them and the platform's home
 * folder for ~ in paths.
 *
 * When no entry sets a verdict, the rule's blocking_hint applies once the
 * rule carries a safe_alternative, and alert_only otherwise. The verdict
 * also carries the candidate: what the rule's hint would do if it were in
 * force. Shadow mode records candidates, which is how a rule earns a
 * safe_alternative and a default hint.
 */

import os from "node:os";
import {
  policyEntries,
  type BlockingVerdict,
  type EnforcementConfig,
  type EnforcementException,
  type EnforcementTarget,
  type PolicyEntry,
  type RiskSeverity,
  type SafeAlternative,
  type ToolInvokedEvent,
} from "@omnodex/shared";
import { evaluatePolicy, targetMatches } from "../policy.js";

/**
 * Where a verdict came from, for status output and the would-block record:
 * "rule-hint", "default", or "<scope>-<kind>" for an entry, where scope is
 * user, project, account or repo, and kind is rule, category, severity,
 * exception (a target that loosens) or target (a target that tightens).
 */
export type VerdictSource = string;

export interface Verdict {
  rule_id: string;
  /** What enforcement does to the call. */
  action: BlockingVerdict;
  /** What the rule's hint would do if it were in force, for shadow mode. */
  candidate: BlockingVerdict;
  source: VerdictSource;
  /** Set when an entry mutes the finding: it stays out of default views. */
  muted: boolean;
  /** The severity an entry gives the finding, when one sets it. */
  severity?: RiskSeverity;
  /** The entry that decided the action, when one did. */
  entry?: PolicyEntry;
  safe_alternative?: SafeAlternative;
  /** The finding's description, carried through for the block reason. */
  description?: string;
}

/** The parts of a rule definition the chain reads. */
export interface VerdictRule {
  rule_id: string;
  severity: RiskSeverity;
  category?: string;
  blocking_hint?: BlockingVerdict;
  safe_alternative?: SafeAlternative;
}

/**
 * The configuration the chain reads, already loaded.
 *
 * `user` is the user's enforcement section, per-project sections included.
 * `userProject` is a section already chosen for the project this call is
 * in, rooted at `projectRoot`. `repo` is the shared policy file in the
 * repository, which can only tighten. `account` is the account's policy.
 */
export interface VerdictConfig {
  user?: EnforcementConfig;
  userProject?: EnforcementConfig;
  repo?: EnforcementConfig;
  account?: readonly PolicyEntry[];
  /** The project root, for exception paths given relative to it. */
  projectRoot?: string;
}

export interface ResolveVerdictInput {
  rule: VerdictRule;
  /** The call the finding is about. Without it, only entries with no target (or a credential target) can match. */
  call?: ToolInvokedEvent;
  config?: VerdictConfig;
  description?: string;
  /** The finding's credential fingerprints, for credential targets. */
  credential_fingerprints?: readonly string[];
}

const STRENGTH: Readonly<Record<BlockingVerdict, number>> = { alert_only: 0, confirm: 1, deny: 2 };

/** Stands in for the project of a userProject section given without its root. */
const THIS_PROJECT = ".";

/** The stricter of two verdicts. */
export function stricter(a: BlockingVerdict, b: BlockingVerdict): BlockingVerdict {
  return STRENGTH[b] > STRENGTH[a] ? b : a;
}

/** Whether a verdict holds the call (deny or confirm). */
export function blocks(v: BlockingVerdict): boolean {
  return v !== "alert_only";
}

/** The machine's own entries for a loaded configuration. */
export function machineEntries(config: VerdictConfig): PolicyEntry[] {
  const out = config.user ? policyEntries(config.user) : [];
  if (config.userProject) out.push(...policyEntries(config.userProject, config.projectRoot ?? THIS_PROJECT));
  return out;
}

export function resolveVerdict(input: ResolveVerdictInput): Verdict {
  const { rule, call, description } = input;
  const config = input.config ?? {};
  const hint = rule.blocking_hint ?? "alert_only";
  // A hint that would hold a call is in force only once the rule can tell
  // the agent what to do instead.
  const hintInForce = !blocks(hint) || rule.safe_alternative !== undefined;
  const result = evaluatePolicy({
    finding: {
      rule_id: rule.rule_id,
      severity: rule.severity,
      ...(rule.category !== undefined ? { category: rule.category } : {}),
      ...(input.credential_fingerprints ? { credential_fingerprints: input.credential_fingerprints } : {}),
    },
    call,
    machine: machineEntries(config),
    account: config.account,
    repo: config.repo ? policyEntries(config.repo) : undefined,
    projectRoots: [config.projectRoot ?? THIS_PROJECT],
    home: os.homedir(),
    defaultVerdict: hintInForce ? hint : "alert_only",
  });
  const decided = result.decided.verdict;
  return {
    rule_id: rule.rule_id,
    action: result.verdict,
    candidate: hint,
    source: decided?.source ?? (rule.blocking_hint ? "rule-hint" : "default"),
    muted: result.muted,
    ...(result.decided.severity ? { severity: result.severity } : {}),
    ...(decided ? { entry: decided.entry } : {}),
    ...(rule.safe_alternative ? { safe_alternative: rule.safe_alternative } : {}),
    ...(description !== undefined ? { description } : {}),
  };
}

// ---------------------------------------------------------------------------
// Exception targets
// ---------------------------------------------------------------------------

/**
 * Whether an exception covers a call. An exception without a target covers
 * every call. With a target, everything of that kind the call touches must
 * be covered, so allowing one path never allows a call that also reads
 * another, and allowing `npm test` never allows `npm test && curl ...`.
 */
export function exceptionMatches(e: EnforcementException, call: ToolInvokedEvent | undefined, base?: string): boolean {
  if (!e.target) return true;
  if (!call) return false;
  return targetCovers(e.target, call, base);
}

export function targetCovers(target: EnforcementTarget, call: ToolInvokedEvent, base?: string): boolean {
  const [key] = Object.keys(target) as (keyof EnforcementTarget)[];
  if (!key || target[key] === undefined) return false;
  return targetMatches({ [key]: target[key] } as never, { call }, "all", { base, home: os.homedir() });
}
