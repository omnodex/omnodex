// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * registry.ts
 *
 * Installation registry for Omnodex hook installations.
 * Tracks which targets are installed in which projects, their versions,
 * and whether they use the stable launcher pattern (FS-012) or legacy
 * absolute paths.
 *
 * Stored at ~/.omnodex/installations.json.
 */

import { promises as fs, readFileSync } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import type { LauncherPlatform } from "./launcher-template.js";

export interface Installation {
  /** Target platform (e.g. "claude-code", "codex", "antigravity") */
  target: LauncherPlatform;
  /** Absolute path to the project where hooks are installed */
  projectPath: string;
  /** Which settings file was used (e.g. "settings.local.json", "hooks.json") */
  settingsFile: string;
  /** ISO timestamp of when the installation was performed */
  installedAt: string;
  /** Omnodex version at install time */
  installedVersion: string;
  /** Whether this installation uses the stable launcher (FS-012) or legacy absolute paths */
  usesLauncher: boolean;
  /** Path to the launcher script (if usesLauncher is true) */
  launcherPath?: string;
}

interface RegistryFile {
  version: 1;
  installations: Installation[];
}

function registryPath(): string {
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  return path.join(home, "installations.json");
}

async function readRegistry(): Promise<RegistryFile> {
  try {
    const raw = await fs.readFile(registryPath(), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && parsed.version === 1 && Array.isArray(parsed.installations)) {
      return parsed as RegistryFile;
    }
  } catch {
    // File doesn't exist or is invalid — start fresh
  }
  return { version: 1, installations: [] };
}

async function writeRegistry(registry: RegistryFile): Promise<void> {
  const dest = registryPath();
  await fs.mkdir(path.dirname(dest), { recursive: true });
  await fs.writeFile(dest, JSON.stringify(registry, null, 2) + "\n", "utf8");
}

/**
 * Add or update an installation record.
 * If an installation for the same target + projectPath already exists,
 * it is replaced (idempotent install).
 */
export async function addInstallation(install: Installation): Promise<void> {
  const registry = await readRegistry();
  // Remove any existing entry for the same target + project
  registry.installations = registry.installations.filter(
    (i) =>
      !(
        i.target === install.target &&
        normalizePath(i.projectPath) === normalizePath(install.projectPath)
      ),
  );
  registry.installations.push(install);
  await writeRegistry(registry);
}

/**
 * Remove an installation record by target + projectPath.
 * Returns true if an entry was found and removed.
 */
export async function removeInstallation(
  target: LauncherPlatform,
  projectPath: string,
): Promise<boolean> {
  const registry = await readRegistry();
  const before = registry.installations.length;
  registry.installations = registry.installations.filter(
    (i) =>
      !(
        i.target === target &&
        normalizePath(i.projectPath) === normalizePath(projectPath)
      ),
  );
  if (registry.installations.length < before) {
    await writeRegistry(registry);
    return true;
  }
  return false;
}

/**
 * List all registered installations.
 */
export async function listInstallations(): Promise<Installation[]> {
  const registry = await readRegistry();
  return registry.installations;
}

/**
 * Find installations matching a target and/or project path.
 */
export async function findInstallations(opts?: {
  target?: LauncherPlatform;
  projectPath?: string;
}): Promise<Installation[]> {
  const registry = await readRegistry();
  return registry.installations.filter((i) => {
    if (opts?.target && i.target !== opts.target) return false;
    if (
      opts?.projectPath &&
      normalizePath(i.projectPath) !== normalizePath(opts.projectPath)
    )
      return false;
    return true;
  });
}

/**
 * Find installations that use legacy absolute paths (pre-FS-012).
 * These need to be re-installed to switch to the stable launcher pattern.
 */
export async function findStaleInstallations(): Promise<Installation[]> {
  const registry = await readRegistry();
  return registry.installations.filter((i) => !i.usesLauncher);
}

/**
 * Get the current Omnodex version from the CLI package.json.
 * Falls back to "0.0.0-dev" if the version can't be determined.
 */
export function getInstalledVersion(): string {
  try {
    // Walk up from this file to find the CLI package.json
    let dir = path.dirname(new URL(import.meta.url).pathname);
    // On Windows, URL.pathname has a leading "/" before the drive letter
    if (process.platform === "win32" && dir.startsWith("/")) {
      dir = dir.slice(1);
    }
    for (let i = 0; i < 5; i++) {
      try {
        const pkgPath = path.join(dir, "package.json");
        const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
        if (pkg.name === "@omnodex/cli" || pkg.name === "omnodex") {
          return pkg.version || "0.0.0-dev";
        }
      } catch {
        // Not found at this level, walk up
      }
      dir = path.dirname(dir);
    }
  } catch {
    // Fallback
  }
  return "0.0.0-dev";
}

/**
 * Normalize a path for comparison (resolve, lowercase on Windows).
 */
function normalizePath(p: string): string {
  const resolved = path.resolve(p);
  if (process.platform === "win32") {
    return resolved.toLowerCase();
  }
  return resolved;
}
