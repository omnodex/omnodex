// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Rule registry index.
 *
 * COMMUNITY_RULES is the set of rules that ship open-source and are always
 * active. To add a new community rule:
 *
 *   1. Create a new file in rules/community/<rule-name>.ts
 *   2. Export a RuleDefinition constant following the existing pattern
 *   3. Import and add it to COMMUNITY_RULES below
 *   4. Add unit tests in test/rules/<rule-name>.test.mjs
 *
 * Advanced rules (Pro/Enterprise tier) are distributed encrypted from the
 * Omnodex license server. See RuleRegistry.loadAdvancedRules() for the
 * the integration point.
 */

import type { RuleDefinition } from "../types.js";
import { RULE_SENSITIVE_PATH_READ } from "./community/sensitive-path-read.js";
import { RULE_CREDENTIAL_IN_PARAMS } from "./community/credential-in-params.js";
import { RULE_CREDENTIAL_EXFIL } from "./community/credential-exfil.js";
import {
  RULE_WALLET_CLI_DETECTED,
  RULE_PRIVATE_KEY_MATERIAL,
  RULE_MNEMONIC_PHRASE,
} from "./community/wallet-generation.js";
import {
  RULE_OUTBOUND_KNOWN_IP,
  RULE_OUTBOUND_UNKNOWN_IP,
} from "./community/unexpected-network.js";
import {
  RULE_SUPPLY_CHAIN_TOOL_SHADOW,
  RULE_SUPPLY_CHAIN_NEW_MCP_SERVER,
  RULE_SUPPLY_CHAIN_SKILL_MANIPULATION,
  RULE_SUPPLY_CHAIN_DEP_CONFUSION,
  RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE,
  RULE_SUPPLY_CHAIN_MCP_URL_MUTATION,
  RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE,
  RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS,
} from "./community/supply-chain.js";
import { RULE_INPUT_VALIDATION_SQL_INJECTION } from "./community/input-validation.js";
import {
  RULE_UNBOUNDED_CONSUMPTION_BURST,
  RULE_UNBOUNDED_CONSUMPTION_SUSTAINED,
} from "./community/unbounded-consumption.js";
import {
  RULE_THREAT_DESTRUCTIVE_COMMAND,
  RULE_THREAT_ENCODED_PAYLOAD,
  RULE_THREAT_REVERSE_SHELL,
  RULE_THREAT_IMDS_ACCESS,
  RULE_THREAT_CREDENTIAL_ARCHIVE,
  RULE_THREAT_SSH_TUNNEL,
  RULE_THREAT_AUDIT_TRAIL_DESTRUCTION,
  RULE_THREAT_PACKAGE_PUBLISH,
} from "./community/threat-commands.js";
import {
  RULE_PERSISTENCE_SHELL_STARTUP,
  RULE_PERSISTENCE_GIT_HOOKS,
} from "./community/persistence.js";
import { RULE_CROSS_AGENT_AUTH_ACCESS } from "./community/cross-agent.js";
import {
  RULE_SANDBOX_DISABLE_SETTINGS_WRITE,
  RULE_SANDBOX_DISABLE_BASH,
} from "./community/sandbox-disable.js";
import {
  RULE_SELF_PROTECTION_CONFIG_WRITE,
  RULE_SELF_PROTECTION_BASH,
} from "./community/self-protection.js";
import { RULE_SUPPLY_CHAIN_IOC_DOMAIN } from "./community/supply-chain.js";
import { RULE_THREAT_API_BASE_URL_OVERRIDE } from "./community/threat-commands.js";
import { RULE_CWD_BOUNDARY_WRITE } from "./community/cwd-boundary.js";

export { RULE_SENSITIVE_PATH_READ } from "./community/sensitive-path-read.js";
export {
  RULE_CREDENTIAL_IN_PARAMS,
  CREDENTIAL_PATTERNS,
} from "./community/credential-in-params.js";
export { RULE_CREDENTIAL_EXFIL } from "./community/credential-exfil.js";
export {
  RULE_WALLET_CLI_DETECTED,
  RULE_PRIVATE_KEY_MATERIAL,
  RULE_MNEMONIC_PHRASE,
} from "./community/wallet-generation.js";
export {
  RULE_OUTBOUND_KNOWN_IP,
  RULE_OUTBOUND_UNKNOWN_IP,
} from "./community/unexpected-network.js";
export {
  RULE_SUPPLY_CHAIN_TOOL_SHADOW,
  RULE_SUPPLY_CHAIN_NEW_MCP_SERVER,
  RULE_SUPPLY_CHAIN_SKILL_MANIPULATION,
  RULE_SUPPLY_CHAIN_DEP_CONFUSION,
  RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE,
  RULE_SUPPLY_CHAIN_MCP_URL_MUTATION,
  RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE,
  RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS,
} from "./community/supply-chain.js";
export { RULE_INPUT_VALIDATION_SQL_INJECTION } from "./community/input-validation.js";
export {
  RULE_UNBOUNDED_CONSUMPTION_BURST,
  RULE_UNBOUNDED_CONSUMPTION_SUSTAINED,
} from "./community/unbounded-consumption.js";
export {
  RULE_THREAT_DESTRUCTIVE_COMMAND,
  RULE_THREAT_ENCODED_PAYLOAD,
  RULE_THREAT_REVERSE_SHELL,
  RULE_THREAT_IMDS_ACCESS,
  RULE_THREAT_CREDENTIAL_ARCHIVE,
  RULE_THREAT_SSH_TUNNEL,
  RULE_THREAT_AUDIT_TRAIL_DESTRUCTION,
  RULE_THREAT_PACKAGE_PUBLISH,
} from "./community/threat-commands.js";
export {
  RULE_PERSISTENCE_SHELL_STARTUP,
  RULE_PERSISTENCE_GIT_HOOKS,
} from "./community/persistence.js";
export { RULE_CROSS_AGENT_AUTH_ACCESS } from "./community/cross-agent.js";
export {
  RULE_SANDBOX_DISABLE_SETTINGS_WRITE,
  RULE_SANDBOX_DISABLE_BASH,
} from "./community/sandbox-disable.js";
export {
  RULE_SELF_PROTECTION_CONFIG_WRITE,
  RULE_SELF_PROTECTION_BASH,
} from "./community/self-protection.js";
export { RULE_SUPPLY_CHAIN_IOC_DOMAIN } from "./community/supply-chain.js";
export { RULE_THREAT_API_BASE_URL_OVERRIDE } from "./community/threat-commands.js";
export { RULE_CWD_BOUNDARY_WRITE } from "./community/cwd-boundary.js";

/** All community-tier rules. Extend this array when adding new rules. */
export const COMMUNITY_RULES: RuleDefinition[] = [
  RULE_SENSITIVE_PATH_READ,
  RULE_CREDENTIAL_IN_PARAMS,
  RULE_CREDENTIAL_EXFIL,
  RULE_WALLET_CLI_DETECTED,
  RULE_PRIVATE_KEY_MATERIAL,
  RULE_MNEMONIC_PHRASE,
  RULE_OUTBOUND_KNOWN_IP,
  RULE_OUTBOUND_UNKNOWN_IP,
  RULE_SUPPLY_CHAIN_TOOL_SHADOW,
  RULE_SUPPLY_CHAIN_NEW_MCP_SERVER,
  RULE_SUPPLY_CHAIN_SKILL_MANIPULATION,
  RULE_SUPPLY_CHAIN_DEP_CONFUSION,
  RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE,
  RULE_SUPPLY_CHAIN_MCP_URL_MUTATION,
  RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE,
  RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS,
  RULE_INPUT_VALIDATION_SQL_INJECTION,
  RULE_UNBOUNDED_CONSUMPTION_BURST,
  RULE_UNBOUNDED_CONSUMPTION_SUSTAINED,
  // Threat command detection
  RULE_THREAT_DESTRUCTIVE_COMMAND,
  RULE_THREAT_ENCODED_PAYLOAD,
  RULE_THREAT_REVERSE_SHELL,
  RULE_THREAT_IMDS_ACCESS,
  RULE_THREAT_CREDENTIAL_ARCHIVE,
  RULE_THREAT_SSH_TUNNEL,
  RULE_THREAT_AUDIT_TRAIL_DESTRUCTION,
  RULE_THREAT_PACKAGE_PUBLISH,
  // Persistence detection
  RULE_PERSISTENCE_SHELL_STARTUP,
  RULE_PERSISTENCE_GIT_HOOKS,
  // Cross-agent security
  RULE_CROSS_AGENT_AUTH_ACCESS,
  // Sandbox disable detection
  RULE_SANDBOX_DISABLE_SETTINGS_WRITE,
  RULE_SANDBOX_DISABLE_BASH,
  // IOC domain detection
  RULE_SUPPLY_CHAIN_IOC_DOMAIN,
  // Self-protection
  RULE_SELF_PROTECTION_CONFIG_WRITE,
  RULE_SELF_PROTECTION_BASH,
  // API base URL override
  RULE_THREAT_API_BASE_URL_OVERRIDE,
  // Working-directory boundary
  RULE_CWD_BOUNDARY_WRITE,
];
