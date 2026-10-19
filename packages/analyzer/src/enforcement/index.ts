// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Enforcement: from a finding to what happens to the call.
 *
 * resolveVerdict gives each finding a verdict from the user's and the
 * project's overrides and the rule's own hint. Shadow mode records them on
 * the findings; in guardrails mode the paid guardrails module (module.ts)
 * turns them into the decision the agent host acts on.
 */

export {
  resolveVerdict,
  exceptionMatches,
  targetCovers,
  stricter,
  blocks,
} from "./resolve-verdict.js";
export type { Verdict, VerdictRule, VerdictConfig, VerdictSource, ResolveVerdictInput } from "./resolve-verdict.js";
export {
  loadGuardrailsModule,
  describeGuardrails,
  canonicalModuleManifest,
  modulePath,
  licensedModuleKey,
  GUARDRAILS_INTERFACE,
  GUARDRAILS_DIR,
  CURRENT_MODULE_FILE,
  GUARDRAILS_KEY_ENV,
  GUARDRAILS_PUBLIC_KEY_ENV,
} from "./module.js";
export type {
  EnforcementHost,
  GuardrailsInput,
  GuardrailsDecision,
  GuardrailsModule,
  GuardrailsLoad,
  ModuleManifest,
  SealedModule,
  ModuleSkipReason,
} from "./module.js";
export { loadEnforcement, readUserEnforcement, findRepoPolicy, userProjectSection, USER_CONFIG_FILE } from "./config.js";
export type { LoadedEnforcement, LoadEnforcementOptions } from "./config.js";
export { annotateFindings, enforcementRecord, verdictFor } from "./annotate.js";
export type { AnnotateOptions } from "./annotate.js";
export { appendRuleSignals, signalLines, RULE_SIGNALS_LOG } from "./signals.js";
export type { RuleSignalKind, RuleSignalLine } from "./signals.js";
export { enforceCaptured, enforceAndCount } from "./enforce.js";
export type { EnforceOptions, EnforceResult } from "./enforce.js";
