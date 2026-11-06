// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Masking of credentials at capture.
 *
 * A credential an agent uses is recorded as a marker, never in full:
 *
 *   [omnodex:secret:<type>:<hint>:<fingerprint>]
 *
 * `type` is the analyzer's label ("github-pat", "bearer"), `hint` is a few
 * characters from the ends of a long value (nothing for a short one), and
 * `fingerprint` is the machine's keyed credential fingerprint, so the same
 * credential still groups across calls without being recoverable. The rules
 * judge the call as captured, before it is masked, and the markers read as
 * credentials of the same type afterwards (see findCredentials), so a pass
 * over a masked log reports the same types.
 *
 * Browser-safe: the fingerprint function is passed in.
 */

import type { TraceEvent } from "@omnodex/shared";
import { findCredentials } from "./conditions/credential-match.js";
import { CREDENTIAL_PATTERNS } from "./rules/community/credential-in-params.js";
import { SECRET_MARKER_PREFIX, secretMarker } from "./secret-marker.js";

/** Replace every credential in a text with its marker. */
export function maskSecretsInText(text: string, fingerprint: (value: string) => string): string {
  const found = findCredentials(text, CREDENTIAL_PATTERNS).filter((c) => !c.value.includes(SECRET_MARKER_PREFIX));
  if (found.length === 0) return text;
  // Longest first, so a value that contains a shorter one is replaced whole.
  found.sort((a, b) => b.value.length - a.value.length);
  let out = text;
  for (const { type, value } of found) {
    out = out.split(value).join(secretMarker(type, value, fingerprint));
  }
  return out;
}

/** A key's value, masked in place, for an event's parameters. */
function maskParameters(parameters: Record<string, unknown>, fingerprint: (value: string) => string): Record<string, unknown> {
  const json = JSON.stringify(parameters);
  const masked = maskSecretsInText(json, fingerprint);
  return masked === json ? parameters : (JSON.parse(masked) as Record<string, unknown>);
}

/**
 * The event as it is written: a tool call's parameters with every
 * credential masked. Other events, and calls without credentials, come back
 * as they are. If masking fails, the parameters are dropped rather than
 * written, so a failure never leaks the value.
 */
export function maskEventSecrets<T extends TraceEvent>(event: T, fingerprint: (value: string) => string): T {
  const e = event as T & { parameters?: Record<string, unknown> };
  if (event.event_type !== "tool.invoked" || !e.parameters || typeof e.parameters !== "object") return event;
  try {
    const parameters = maskParameters(e.parameters, fingerprint);
    return parameters === e.parameters ? event : { ...e, parameters };
  } catch {
    return { ...e, parameters: { _omnodex_masking_failed: true } };
  }
}
