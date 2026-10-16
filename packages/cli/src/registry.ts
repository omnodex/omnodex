// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * registry.ts
 *
 * Installation registry: what Omnodex has installed on this machine.
 * Each entry is one component (hooks, plugin or MCP config) for one
 * target platform, at project scope (written into a project) or user
 * scope (installed once for the user, such as a plugin).
 *
 * Stored at ~/.omnodex/installations.json. Version 1 files, which only
 * recorded project hooks, are migrated on read.
 */

import { promises as fs, readFileSync } from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";
import type { LauncherPlatform } from "./launcher-template.js";

/** What was installed. */
export type InstallComponent = "hooks" | "plugin" | "mcp";

/** Where it was installed: into one project, or once for the user. */
export type InstallScope = "project" | "user";

export interface Installation {
  /** Target platform (e.g. "claude-code", "codex", "antigravity") */
  target: LauncherPlatform;
  /** What was installed */
  component: InstallComponent;
  /** Project scope is tied to projectPath; user scope has no project */
  scope: InstallScope;
  /** Absolute path to the project (project scope only) */
  projectPath?: string;
  /** Which file was written (e.g. "settings.local.json", "hooks.json") */
  settingsFile: string;
  /** ISO timestamp of when the installation was performed */
  installedAt: string;
  /** Omnodex version at install time */
  installedVersion: string;
  /** Whether this installation uses the stable launcher or legacy absolute paths */
  usesLauncher: boolean;
  /** Path to the launcher script (if usesLauncher is true) */
  launcherPath?: string;
  /** Plugin entries: where the installed copy lives */
  pluginPath?: string;
  /** Plugin entries: the installed plugin version */
  pluginVersion?: string;
  /** Plugin entries: true when the user chose a version other than the pinned one */
  pluginOverride?: boolean;
}

const REGISTRY_VERSION = 2;

interface RegistryFile {
  version: number;
  installations: Installation[];
  /**
   * Entries this version cannot interpret (written by a newer CLI, or
   * damaged). Kept and written back unchanged so nothing is lost.
   */
  unrecognized: unknown[];
}

const COMPONENTS: readonly string[] = ["hooks", "plugin", "mcp"];
const SCOPES: readonly string[] = ["project", "user"];

function registryPath(): string {
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  return path.join(home, "installations.json");
}

/**
 * Interpret one stored entry, upgrading version 1 entries (project hooks,
 * or an Antigravity MCP config recorded under its settings file).
 * Returns null for anything that cannot be read safely.
 */
export function normalizeEntry(raw: unknown): Installation | null {
  if (!raw || typeof raw !== "object") return null;
  const e = raw as Record<string, unknown>;
  if (typeof e.target !== "string" || typeof e.settingsFile !== "string") return null;

  const component = e.component ?? (e.settingsFile === "mcp_config.json" ? "mcp" : "hooks");
  const scope = e.scope ?? "project";
  if (typeof component !== "string" || !COMPONENTS.includes(component)) return null;
  if (typeof scope !== "string" || !SCOPES.includes(scope)) return null;
  if (scope === "project" && typeof e.projectPath !== "string") return null;

  return {
    ...(e as object),
    component,
    scope,
  } as Installation;
}

async function readRegistry(): Promise<RegistryFile> {
  try {
    const raw = await fs.readFile(registryPath(), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.version === "number" && Array.isArray(parsed.installations)) {
      const installations: Installation[] = [];
      const unrecognized: unknown[] = Array.isArray(parsed.unrecognized) ? [...parsed.unrecognized] : [];
      for (const entry of parsed.installations) {
        const normalized = normalizeEntry(entry);
        if (normalized) installations.push(normalized);
        else unrecognized.push(entry);
      }
      return { version: REGISTRY_VERSION, installations, unrecognized };
    }
  } catch {
    // File doesn't exist or is invalid — start fresh
  }
  return { version: REGISTRY_VERSION, installations: [], unrecognized: [] };
}

async function writeRegistry(registry: RegistryFile): Promise<void> {
  const dest = registryPath();
  await fs.mkdir(path.dirname(dest), { recursive: true });
  const out: Record<string, unknown> = {
    version: REGISTRY_VERSION,
    installations: registry.installations,
  };
  if (registry.unrecognized.length > 0) out.unrecognized = registry.unrecognized;
  await fs.writeFile(dest, JSON.stringify(out, null, 2) + "\n", "utf8");
}

/** True when two entries describe the same component in the same place. */
function sameSlot(
  a: Pick<Installation, "target" | "component" | "scope" | "projectPath">,
  b: Pick<Installation, "target" | "component" | "scope" | "projectPath">,
): boolean {
  if (a.target !== b.target || a.component !== b.component || a.scope !== b.scope) return false;
  if (a.scope === "user") return true;
  return samePath(a.projectPath, b.projectPath);
}

/**
 * Add or update an installation record.
 * An existing entry for the same target, component and place (project, or
 * user scope) is replaced, so repeated installs keep one entry.
 */
export async function addInstallation(install: Installation): Promise<void> {
  const entry = normalizeEntry(install);
  if (!entry) throw new Error(`invalid installation record for ${install.target}`);
  const registry = await readRegistry();
  registry.installations = registry.installations.filter((i) => !sameSlot(i, entry));
  registry.installations.push(entry);
  await writeRegistry(registry);
}

/**
 * Remove an installation record. Pass a projectPath for a project-scope
 * entry, or omit it (with scope "user") for a user-scope one.
 * Returns true if an entry was found and removed.
 */
export async function removeInstallation(
  target: LauncherPlatform,
  projectPath: string | undefined,
  component: InstallComponent = "hooks",
): Promise<boolean> {
  const registry = await readRegistry();
  const before = registry.installations.length;
  const slot = {
    target,
    component,
    scope: (projectPath === undefined ? "user" : "project") as InstallScope,
    projectPath,
  };
  registry.installations = registry.installations.filter((i) => !sameSlot(i, slot));
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
 * Find installations matching a target, component, scope and/or project path.
 */
export async function findInstallations(opts?: {
  target?: LauncherPlatform;
  component?: InstallComponent;
  scope?: InstallScope;
  projectPath?: string;
}): Promise<Installation[]> {
  const registry = await readRegistry();
  return registry.installations.filter((i) => {
    if (opts?.target && i.target !== opts.target) return false;
    if (opts?.component && i.component !== opts.component) return false;
    if (opts?.scope && i.scope !== opts.scope) return false;
    if (opts?.projectPath && !samePath(i.projectPath, opts.projectPath)) return false;
    return true;
  });
}

/**
 * Find installations that use legacy absolute paths (from before the stable launcher).
 * These need to be re-installed to switch to the stable launcher pattern.
 */
export async function findStaleInstallations(): Promise<Installation[]> {
  const registry = await readRegistry();
  // Plugins have no hook launcher, so only hooks and MCP entries can be stale.
  return registry.installations.filter((i) => i.component !== "plugin" && !i.usesLauncher);
}

/**
 * Get the current Omnodex version from the CLI package.json.
 * Falls back to "0.0.0-dev" if the version can't be determined.
 */
export function getInstalledVersion(): string {
  try {
    // Walk up from this file to find the CLI package.json
    let dir = path.dirname(fileURLToPath(import.meta.url));
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

function samePath(a: string | undefined, b: string | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return normalizePath(a) === normalizePath(b);
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
