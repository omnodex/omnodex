// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_CREDENTIAL_EXFIL_REMEMBERED
 *
 * Fires when an outbound call carries a value this machine earlier saw as a
 * secret, with no context around it now. RULE_CREDENTIAL_EXFIL reads the
 * context (a vendor format, a header, `token=`); a key sent as a bare string
 * in a request body has none, but it is the same value.
 *
 * Compound condition (AND):
 *   1. outbound_call -- the tool is making an HTTP request to an external host
 *   2. remembered_secret -- a value in the parameters matches a secret seen
 *      earlier in a call's parameters (see known-secrets.ts)
 *
 * A secret sent to its own provider, or to a host it was already sent to
 * with its context, does not count. Loopback never counts. Machine-scoped
 * and call-side only: a key whose first appearance in a call is the
 * exfiltration is not matched, and results are not read.
 *
 * Tier:     community
 * Severity: HIGH. The value matched something this machine saw used as a
 * secret, but nothing shows the send is unwanted, and deploy-platform secret
 * APIs are a legitimate shape for it. Kept apart from RULE_CREDENTIAL_EXFIL
 * (CRITICAL) so it can be muted or reclassified on its own.
 */

import type { RuleDefinition } from "../../types.js";
import { SECRET_SIGHTING_PATTERNS } from "./unrecognized-secret.js";

export const RULE_CREDENTIAL_EXFIL_REMEMBERED: RuleDefinition = {
  rule_id: "RULE_CREDENTIAL_EXFIL_REMEMBERED",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    { type: "outbound_call" },
    { type: "remembered_secret", patterns: SECRET_SIGHTING_PATTERNS },
  ],
  severity: "HIGH",
  category: "credential_exfiltration",
  description_template:
    "A value this machine saw used as a credential ({{credential_types}}, first seen {{remembered_since}}) was sent to {{matched_destination}} via {{tool_name}} without that context.",
};
