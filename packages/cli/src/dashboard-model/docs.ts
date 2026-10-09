// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/** Documentation base URL, independent of the dashboard and API hosts. */
export const DEFAULT_DOCS_HOST = "https://docs.omnodex.com/";

/** A fixed per-rule route. The docs site owns mapping and unknown-rule fallback. */
export function riskLibraryUrl(ruleId: string): string {
  // Arbitrary/custom rule text must remain one path segment. Empty IDs and
  // dot segments go to the index rather than navigating outside the library.
  const route = !ruleId.trim() || ruleId === "." || ruleId === ".."
    ? "risk-library/rule-index/"
    : "risk-library/rule/" + encodeURIComponent(ruleId);
  return new URL(route, DEFAULT_DOCS_HOST).href;
}
