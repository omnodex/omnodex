// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/analyzer -- public API.
 *
 * Primary entry point:
 *   detectRisks(events, newEventId)  -- batch risk detection for a session
 *
 * For custom use (e.g. streaming detection or custom integrations):
 *   RuleEngine       -- evaluate rules against individual events
 *   RuleRegistry     -- manage active rule sets (community + advanced)
 *   COMMUNITY_RULES  -- the bundled open-source rule definitions
 *
 * Types (re-exported for consumers that need them):
 *   RuleDefinition, Condition, RiskFinding, DetectionResult, MatchContext
 *   PathMatchCondition, CredentialMatchCondition, OutboundCallCondition
 */

// Core detection function
export { detectRisks } from "./detect.js";

// Engine and registry (used by the streaming detect loop and custom integrations)
export { RuleEngine } from "./engine.js";
export { RuleRegistry } from "./registry.js";

// Rule definitions
export { COMMUNITY_RULES, CREDENTIAL_PATTERNS } from "./rules/index.js";

// Types
export type {
  RuleDefinition,
  Condition,
  PathMatchCondition,
  PathPattern,
  CredentialMatchCondition,
  CredentialPattern,
  OutboundCallCondition,
  MatchContext,
  RiskFinding,
  DetectionResult,
} from "./types.js";

// Condition utilities (exported for the streaming detect loop and custom interceptor authors)
export {
  extractPaths,
  findCredentialTypes,
  isOutboundCall,
} from "./conditions/index.js";
