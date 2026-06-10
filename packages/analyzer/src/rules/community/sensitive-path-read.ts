// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_SENSITIVE_PATH_READ
 *
 * Fires when a tool reads (or likely reads) from a sensitive system path --
 * credential files, SSH keys, /etc system files, cloud provider config, etc.
 * One risk finding is emitted per matched path.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_SENSITIVE_PATH_READ: RuleDefinition = {
  rule_id: "RULE_SENSITIVE_PATH_READ",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "path_match",
      patterns: [
        { regex: "^/etc/passwd$",                   label: "/etc/passwd" },
        { regex: "^/etc/shadow$",                   label: "/etc/shadow" },
        { regex: "^/etc/sudoers",                   label: "/etc/sudoers" },
        { regex: "^/etc/ssh/",                      label: "/etc/ssh/ config" },
        { regex: "^/root/",                         label: "/root/ directory" },
        // More-specific SSH key patterns before the general .ssh directory pattern
        { regex: "id_rsa",                          label: "SSH private key" },
        { regex: "id_ed25519",                      label: "SSH private key" },
        { regex: "[/\\\\]\\.ssh[/\\\\]",            label: ".ssh directory" },
        { regex: "[/\\\\]\\.env$",                  label: ".env file" },
        { regex: "[/\\\\]\\.env\\.[^/\\\\]+$",      label: ".env file" },
        { regex: "[/\\\\]\\.aws[/\\\\]credentials", label: "AWS credentials" },
        { regex: "[/\\\\]\\.gcloud[/\\\\]",         label: "GCloud config" },
        { regex: "[/\\\\]\\.kube[/\\\\]config",     label: "Kubernetes config" },
        { regex: "\\.pem$",                         label: "PEM private key" },
      ],
    },
  ],
  severity: "HIGH",
  category: "sensitive_path_read",
  description_template:
    "Session accessed {{matched_label}} ({{matched_path}}), a sensitive system path.",
};
