// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * What the OpenCode plugin reads from the shim: `{ decision: "deny", reason }`
 * for a call to stop, and nothing for a call that runs. The plugin turns a
 * deny into a thrown error, which is how OpenCode blocks a tool call, and the
 * reason is what the agent reads. OpenCode's before-hook cannot ask the user,
 * so a confirm verdict arrives as a deny whose reason tells the agent to ask.
 *
 * The guardrails module answers in this shape for OpenCode; anything else it
 * returns still stops the call, with no reason.
 */
export function opencodeDecision(output: Record<string, unknown> | null): Record<string, unknown> | undefined {
  if (!output) return undefined;
  const reason = typeof output.reason === "string" && output.reason ? output.reason : undefined;
  return { decision: "deny", ...(reason ? { reason } : {}) };
}
