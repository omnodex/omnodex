// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What Copilot reads for a preToolUse decision. The guardrails module answers
 * in the VS Code compatible shape (`hookSpecificOutput`), which is what a
 * PascalCase registration gets; the same decision is repeated at the top
 * level, the shape the CLI reference documents, so either reader finds it.
 */
export function copilotDecision(output: Record<string, unknown> | null): Record<string, unknown> | undefined {
  if (!output) return undefined;
  const specific = output.hookSpecificOutput as Record<string, unknown> | undefined;
  if (specific && typeof specific.permissionDecision === "string") {
    return {
      ...output,
      permissionDecision: specific.permissionDecision,
      ...(typeof specific.permissionDecisionReason === "string" ? { permissionDecisionReason: specific.permissionDecisionReason } : {}),
    };
  }
  return output;
}
