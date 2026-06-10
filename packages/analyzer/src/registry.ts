// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RuleRegistry -- manages the active set of rules for a detection run.
 *
 * Community rules are always loaded and always active. Advanced rules
 * (Pro/Enterprise tier) are delivered encrypted from the Omnodex license
 * server; loading them requires a valid subscription token. The integration
 * point is loadAdvancedRules(), which is currently stubbed with a detailed
 * comment describing the expected integration.
 *
 * Tier enforcement design:
 *   The registry deliberately separates rule loading from rule evaluation.
 *   The RuleEngine only sees whatever getRules() returns. When advanced rules
 *   are loaded, they join the same pool and flow through the same engine --
 *   no engine changes are needed to support them. The tier field on each
 *   RuleDefinition is metadata for audit and display, not a runtime gate.
 *
 */

import type { RuleDefinition } from "./types.js";
import { COMMUNITY_RULES } from "./rules/index.js";

export class RuleRegistry {
  private readonly rules: RuleDefinition[];

  /**
   * @param initialRules  Defaults to COMMUNITY_RULES. Pass a custom list
   *                      to override (useful in tests).
   */
  constructor(initialRules: RuleDefinition[] = COMMUNITY_RULES) {
    this.rules = [...initialRules];
  }

  /** All active rules (community + any loaded advanced rules). */
  getRules(): RuleDefinition[] {
    return [...this.rules];
  }

  /** Community-tier rules only. */
  getCommunityRules(): RuleDefinition[] {
    return this.rules.filter((r) => r.tier === "community");
  }

  /** Advanced-tier rules currently loaded (empty until loadAdvancedRules() succeeds). */
  getAdvancedRules(): RuleDefinition[] {
    return this.rules.filter((r) => r.tier === "advanced");
  }

  /**
   * Load advanced rules for a subscribed customer.
   *
   * Not yet implemented. Requires a valid Pro or Enterprise subscription and
   * a running license server.
   */
  async loadAdvancedRules(_licenseToken: string): Promise<void> {
    // Not yet implemented -- will integrate with the Omnodex license server.
    throw new Error(
      "Advanced rules require a Pro or Enterprise subscription. " +
        "Visit omnodex.com to learn about available plans.",
    );
  }
}
