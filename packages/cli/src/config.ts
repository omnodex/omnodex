// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Dashboard configuration.
 *
 * Resolves the list of OMNODEX_HOME roots the dashboard should tail.
 * Sources (in priority order, all merged):
 *
 *   1. CLI --roots flag (highest priority, ad-hoc use)
 *   2. ~/.omnodex/config.json  dashboard.roots  array
 *   3. $OMNODEX_HOME  (if set and different from $HOME/.omnodex)
 *   4. $HOME/.omnodex  (always included as the default root)
 *
 * Duplicate roots are deduplicated. Roots that don't exist on disk are
 * kept in the list (they may appear later) but logged as warnings.
 */

import * as os from "node:os";
import * as path from "node:path";
import { promises as fs } from "node:fs";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Shape of ~/.omnodex/config.json (only the fields we care about). */
export interface OmnodexConfig {
  dashboard?: {
    roots?: string[];
  };
}

/** Resolved set of roots the dashboard should tail. */
export interface ResolvedRoots {
  /** Primary root (first in list, used for the SQLite DB location). */
  primary: string;
  /** All roots to tail, deduplicated. Always includes primary. */
  all: string[];
}

// ---------------------------------------------------------------------------
// Config file loading
// ---------------------------------------------------------------------------

/**
 * Attempt to load ~/.omnodex/config.json. Returns an empty config on
 * any error (missing file, malformed JSON, wrong shape).
 */
export async function loadDashboardConfig(
  omnodexHome?: string,
): Promise<OmnodexConfig> {
  const home = omnodexHome ?? path.join(os.homedir(), ".omnodex");
  const configPath = path.join(home, "config.json");
  try {
    const raw = await fs.readFile(configPath, "utf8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    // Minimal validation: dashboard.roots must be an array of strings if present.
    if (parsed.dashboard && typeof parsed.dashboard === "object") {
      const dash = parsed.dashboard as Record<string, unknown>;
      if (dash.roots !== undefined) {
        if (
          !Array.isArray(dash.roots) ||
          !dash.roots.every((r: unknown) => typeof r === "string")
        ) {
          console.warn(
            `[config] dashboard.roots in ${configPath} must be an array of strings -- ignoring`,
          );
          return {};
        }
      }
    }
    return parsed as OmnodexConfig;
  } catch (err: unknown) {
    // If the file doesn't exist, create a default one so users can discover it.
    if (isNoEnt(err)) {
      const defaultConfig: OmnodexConfig = {
        dashboard: {
          roots: [],
        },
      };
      try {
        await fs.mkdir(home, { recursive: true });
        await fs.writeFile(
          configPath,
          JSON.stringify(defaultConfig, null, 2) + "\n",
          { flag: "wx" }, // fail if created by another process in the meantime
        );
        console.log(`[config] created ${configPath}`);
      } catch {
        // Race or permission issue -- not fatal.
      }
    }
    // Missing file or parse error -- not an error, just no config.
    return {};
  }
}

function isNoEnt(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { code?: string }).code === "ENOENT"
  );
}

// ---------------------------------------------------------------------------
// Root resolution
// ---------------------------------------------------------------------------

/**
 * Resolve the full list of event log roots the dashboard should tail.
 *
 * @param cliRoots - Roots passed via --roots CLI flag (optional).
 */
export async function resolveRoots(cliRoots?: string[]): Promise<ResolvedRoots> {
  const defaultHome = path.join(os.homedir(), ".omnodex");
  const envHome = process.env.OMNODEX_HOME;

  // Start with the default home.
  const roots: string[] = [defaultHome];

  // Add OMNODEX_HOME if set and different.
  if (envHome && path.resolve(envHome) !== path.resolve(defaultHome)) {
    roots.push(path.resolve(envHome));
  }

  // Add roots from config file.
  const config = await loadDashboardConfig(envHome ?? defaultHome);
  if (config.dashboard?.roots) {
    for (const r of config.dashboard.roots) {
      roots.push(path.resolve(r));
    }
  }

  // CLI --roots override: these are added on top (not replacing).
  if (cliRoots && cliRoots.length > 0) {
    for (const r of cliRoots) {
      roots.push(path.resolve(r));
    }
  }

  // Deduplicate by resolved path.
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const r of roots) {
    const resolved = path.resolve(r);
    if (!seen.has(resolved)) {
      seen.add(resolved);
      unique.push(resolved);
    }
  }

  // Warn about roots that don't exist yet (not an error -- they may appear).
  for (const r of unique) {
    try {
      await fs.access(path.join(r, "event-log"));
    } catch {
      console.warn(`[config] root ${r} has no event-log directory (will poll until it appears)`);
    }
  }

  return {
    primary: unique[0],
    all: unique,
  };
}

/**
 * Parse --roots flag from CLI args.
 * Supports: --roots /path1 /path2  (space-separated until next flag or end)
 */
export function parseRootsFlag(args: string[]): {
  roots: string[] | undefined;
  rest: string[];
} {
  const idx = args.indexOf("--roots");
  if (idx === -1) return { roots: undefined, rest: args };

  const roots: string[] = [];
  const rest = args.slice(0, idx);
  let i = idx + 1;
  while (i < args.length && !args[i].startsWith("--")) {
    roots.push(args[i]);
    i++;
  }
  // Collect remaining args after the roots values.
  rest.push(...args.slice(i));

  return { roots: roots.length > 0 ? roots : undefined, rest };
}
