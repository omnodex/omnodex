// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What this machine says about the advanced-tier findings it holds back.
 * Shared by the local dashboard and the CLI, so both say the same thing.
 */

export function advancedFindingsText(count: number, entitled: boolean): string {
  const findings = count === 1 ? "1 more finding" : `${count} more findings`;
  return entitled
    ? `${findings} from the advanced rules. Open your Omnodex dashboard to see them.`
    : `${findings} from the advanced rules, available with Omnodex Pro.`;
}
