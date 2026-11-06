// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * platforms.ts
 *
 * The one list of agent platforms the CLI knows. A platform listed here is
 * recognized by `omnodex install`, hook scope, the launcher and the
 * dashboard labels. `PLATFORM_AVAILABLE` says whether its provider has
 * shipped: an unavailable platform is a valid target that reports it is not
 * yet supported, and is skipped by detection and by loops that act on every
 * platform. A platform's provider flips its own entry when it lands.
 */

export type Platform = "claude-code" | "codex" | "antigravity" | "copilot" | "cursor" | "opencode";

export const PLATFORMS: readonly Platform[] = ["claude-code", "codex", "antigravity", "copilot", "cursor", "opencode"];

export const PLATFORM_LABELS: Record<Platform, string> = {
  "claude-code": "Claude Code",
  codex: "Codex",
  antigravity: "Antigravity",
  copilot: "GitHub Copilot",
  cursor: "Cursor",
  opencode: "OpenCode",
};

/** Whether the platform's provider has shipped. One line per platform. */
export const PLATFORM_AVAILABLE: Record<Platform, boolean> = {
  "claude-code": true,
  codex: true,
  antigravity: true,
  copilot: false,
  cursor: false,
  opencode: false,
};

export const isPlatform = (name: string): name is Platform => (PLATFORMS as readonly string[]).includes(name);

export const isPlatformAvailable = (platform: Platform): boolean => PLATFORM_AVAILABLE[platform];

/** Platforms whose provider has shipped, in stable order. */
export const availablePlatforms = (): Platform[] => PLATFORMS.filter(isPlatformAvailable);

/** The message for a target that is recognized but not built yet. */
export const notYetSupported = (platform: Platform): string =>
  `${PLATFORM_LABELS[platform]} support is not available yet in this release`;
