// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * Why an install should not start the dashboard sign-in, or null when it
 * may: --no-connect, or no terminal to answer it. The device flow waits for
 * someone to approve a code, so a script or an agent running the install
 * would sit there until the code expired.
 */
export function skipConnectReason(args: readonly string[], stdinIsTTY: boolean | undefined): string | null {
  if (args.includes("--no-connect")) return "--no-connect";
  if (!stdinIsTTY) return "not running in a terminal";
  return null;
}
