// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * Where the local dashboard sends people with feedback. The page makes no
 * network call of its own: "Send feedback" opens the person's mail app.
 */

/** The one place the feedback address is set. */
export const FEEDBACK_EMAIL = "support@omnodex.com";

/**
 * A mailto link with the CLI version and platform in the subject, so a
 * reply can start from the right build. Nothing from the event log goes in.
 */
export function feedbackMailto(version: string | null, platform: string | null): string {
  const bare = version?.replace(/^v/, "") ?? null;
  // The repository's package.json says 0.0.0; releases stamp the real version.
  const build = !bare ? null : bare === "0.0.0" ? "source build" : `v${bare}`;
  const parts = ["Omnodex local dashboard feedback", build, platform || null].filter(Boolean);
  const subject = parts.join(", ");
  const body = "What happened, or what would you like to see?\n\n";
  return `mailto:${FEEDBACK_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
