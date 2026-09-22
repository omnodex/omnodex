// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/analyzer -- public API.
 *
 * Primary entry points:
 *   createEvaluator({ host, newEventId }) -- judge events one at a time
 *   detectRisks(events, newEventId)       -- batch risk detection for a session
 *   detectEventLogs({ roots })            -- detection over event logs on disk
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

// Detection over event logs on disk (omnodex detect, background pass)
export {
  detectEventLogs,
  runBackgroundDetect,
  DETECT_STATE_FILE,
} from "./detect-log.js";
export type {
  DetectLogOptions,
  DetectLogResult,
  SessionDetectReport,
} from "./detect-log.js";

// The evaluator: the one place risk.detected events are made. Hot paths
// import it from "@omnodex/analyzer/evaluator" instead of this index.
export {
  createEvaluator,
  classifyRule,
  loadRegistry,
  HOST_CLASSES,
} from "./evaluator.js";
export { createWorkspaceResolver, gitRoots, configuredRoots } from "./workspace.js";
export { openMachineState, memoryMachineState, KNOWN_MCP_SERVERS_FILE } from "./machine-state.js";
export type { MachineState, SeenResult } from "./machine-state.js";
export type { WorkspaceRootsFn } from "./workspace.js";
export type {
  Evaluator,
  EvaluatorHost,
  EvaluatorOptions,
  EvaluatorStats,
  EvaluationClass,
} from "./evaluator.js";

// Engine and registry (custom integrations)
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
  CredentialScope,
  OutboundCallCondition,
  SequenceCondition,
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
