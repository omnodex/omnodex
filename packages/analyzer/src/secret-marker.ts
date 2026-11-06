// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The marker a masked credential is recorded as:
 *
 *   [omnodex:secret:<type>:<hint>:<fingerprint>]
 *
 * Kept apart from the masking so the credential matcher can read markers
 * without importing the patterns it is part of.
 */

/** The text every marker begins with. */
export const SECRET_MARKER_PREFIX = "[omnodex:secret:";

const MARKER = /\[omnodex:secret:([a-z0-9-]+):([A-Za-z0-9_.-]{0,9}):([0-9a-f]{16})\]/g;

/** A parsed marker. */
export interface SecretMarker {
  type: string;
  /** The kept characters of the value, such as "ghp_...wxyz" (or "" for a short one). */
  hint: string;
  fingerprint: string;
}

/** The markers in a text, in order. */
export function findSecretMarkers(text: string): (SecretMarker & { marker: string })[] {
  const out: (SecretMarker & { marker: string })[] = [];
  for (const m of text.matchAll(MARKER)) {
    out.push({ marker: m[0], type: m[1]!, hint: m[2]!, fingerprint: m[3]! });
  }
  return out;
}

/** The marker in a value, or undefined when it is not one. */
export function parseSecretMarker(value: string): SecretMarker | undefined {
  const m = new RegExp(MARKER.source).exec(value);
  return m ? { type: m[1]!, hint: m[2]!, fingerprint: m[3]! } : undefined;
}

function safe(part: string): string {
  return part.replace(/[^A-Za-z0-9_-]/g, "_");
}

/**
 * The characters kept from a value: 4 from each end of a long one, 4 from
 * the start of a medium one, none of a short one. The ends are joined by ".", which a hint never otherwise holds.
 */
export function secretHint(value: string): string {
  if (value.length >= 24) return `${safe(value.slice(0, 4))}.${safe(value.slice(-4))}`;
  if (value.length >= 12) return safe(value.slice(0, 4));
  return "";
}

/** A hint as shown: `abcd...wxyz`, `abcd...` or `...`. */
export function displayHint(hint: string): string {
  if (hint.length === 9 && hint[4] === ".") return `${hint.slice(0, 4)}...${hint.slice(5)}`;
  return hint ? `${hint}...` : "...";
}

/** A marker for a value. */
export function secretMarker(type: string, value: string, fingerprint: (value: string) => string): string {
  return `${SECRET_MARKER_PREFIX}${type}:${secretHint(value)}:${fingerprint(value)}]`;
}
