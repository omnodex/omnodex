// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * update.ts
 *
 * Update checking and self-update for the Omnodex CLI.
 *
 * Two mechanisms:
 *
 * 1. Background update check — spawns a detached child process on every CLI
 *    invocation (except `update` itself) that queries the npm registry and
 *    caches the result for 24h. On the *next* invocation, a one-liner is
 *    printed if an update is available. Fully non-blocking.
 *
 * 2. `omnodex update` command — checks for updates, runs npm install -g,
 *    refreshes stable launchers, and reports the result.
 */

import { promises as fs, statSync, readFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import * as path from "node:path";
import * as os from "node:os";
import * as https from "node:https";
import { getInstalledVersion } from "./registry.js";
import { writeAllLaunchers } from "./launcher-template.js";

const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

export type InstallMethod = "npm" | "source" | "unknown";

interface SourceInstallInfo {
  /** Absolute path to the git repo root */
  repoRoot: string;
  /** Current git branch */
  branch: string;
  /** Current git short SHA */
  sha: string;
  /** Whether there are uncommitted changes */
  dirty: boolean;
}

/**
 * Detect whether the CLI is running from an npm global install or a source checkout.
 * Walks up from this file looking for a .git directory that contains the omnodex repo.
 */
export function detectInstallMethod(): InstallMethod {
  try {
    let dir = path.dirname(new URL(import.meta.url).pathname);
    // On Windows, pathname starts with /C:/... — normalize it
    if (process.platform === "win32" && dir.startsWith("/")) {
      dir = dir.slice(1);
    }
    for (let i = 0; i < 10; i++) {
      try {
        const gitDir = path.join(dir, ".git");
        const stat = statSync(gitDir);
        if (stat.isDirectory()) {
          // Verify it's the omnodex repo by checking for packages/cli
          const cliPkg = path.join(dir, "packages", "cli", "package.json");
          try {
            const pkg = JSON.parse(readFileSync(cliPkg, "utf8"));
            if (pkg.name === "@omnodex/cli" || pkg.name === "omnodex") {
              return "source";
            }
          } catch { /* not our repo */ }
        }
      } catch { /* no .git here */ }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch { /* fallback */ }

  // If installed version is 0.0.0, it's likely source even if we can't find .git
  // (e.g. running from dist/ outside the repo tree after a build)
  const version = getInstalledVersion();
  if (version === "0.0.0") return "source";

  // Check if we're inside node_modules (npm install)
  try {
    const thisFile = new URL(import.meta.url).pathname;
    if (thisFile.includes("node_modules")) return "npm";
  } catch { /* fallback */ }

  return "unknown";
}

/**
 * Get info about the source install (git branch, SHA, dirty state).
 * Returns null if not a source install or git info unavailable.
 */
export function getSourceInstallInfo(): SourceInstallInfo | null {
  try {
    let dir = path.dirname(new URL(import.meta.url).pathname);
    if (process.platform === "win32" && dir.startsWith("/")) {
      dir = dir.slice(1);
    }
    // Find the repo root
    for (let i = 0; i < 10; i++) {
      try {
        const gitDir = path.join(dir, ".git");
        statSync(gitDir);

        // Get branch
        const branchResult = spawnSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
          cwd: dir, encoding: "utf8", timeout: 5000,
        });
        const branch = branchResult.status === 0 ? branchResult.stdout.trim() : "unknown";

        // Get SHA
        const shaResult = spawnSync("git", ["rev-parse", "--short", "HEAD"], {
          cwd: dir, encoding: "utf8", timeout: 5000,
        });
        const sha = shaResult.status === 0 ? shaResult.stdout.trim() : "unknown";

        // Check dirty state
        const dirtyResult = spawnSync("git", ["status", "--porcelain"], {
          cwd: dir, encoding: "utf8", timeout: 5000,
        });
        const dirty = dirtyResult.status === 0 && dirtyResult.stdout.trim().length > 0;

        return { repoRoot: dir, branch, sha, dirty };
      } catch { /* no .git here */ }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch { /* fallback */ }
  return null;
}

/**
 * Run `git pull && npm install && npm run build` for source installs.
 * Returns true on success, false on failure.
 */
async function runSourceUpdate(info: SourceInstallInfo): Promise<boolean> {
  const { repoRoot, branch, dirty } = info;

  if (dirty) {
    console.warn("[update] WARNING: you have uncommitted changes in the repo.");
    console.warn("[update]          git pull may fail or create merge conflicts.");
    console.warn("[update]          consider committing or stashing first.\n");
  }

  // Step 1: git pull
  console.log(`[update] running: git pull (branch: ${branch})`);
  const pullResult = spawnSync("git", ["pull", "--ff-only"], {
    cwd: repoRoot, stdio: "inherit", timeout: 30000,
  });
  if (pullResult.status !== 0) {
    console.error("\n[update] git pull failed.");
    if (dirty) {
      console.error("[update] try: git stash && git pull && git stash pop");
    }
    return false;
  }

  // Step 2: npm install (in case dependencies changed)
  console.log("\n[update] running: npm install");
  const installResult = spawnSync("npm", ["install"], {
    cwd: repoRoot, stdio: "inherit", shell: true, timeout: 120000,
  });
  if (installResult.status !== 0) {
    console.error("\n[update] npm install failed.");
    return false;
  }

  // Step 3: npm run build
  console.log("\n[update] running: npm run build");
  const buildResult = spawnSync("npm", ["run", "build"], {
    cwd: repoRoot, stdio: "inherit", shell: true, timeout: 120000,
  });
  if (buildResult.status !== 0) {
    console.error("\n[update] build failed.");
    return false;
  }

  return true;
}

const NPM_REGISTRY_URL = "https://registry.npmjs.org/omnodex/latest";
const RELEASES_URL = "https://github.com/omnodex/omnodex/releases";

interface UpdateCheckCache {
  /** ISO timestamp of the last check */
  lastCheck: string;
  /** Latest version found on npm */
  latestVersion: string;
  /** Whether the check succeeded */
  success: boolean;
}

function updateCheckPath(): string {
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  return path.join(home, "update-check.json");
}

/**
 * Read the cached update check result.
 * Returns null if the cache doesn't exist or is invalid.
 */
async function readUpdateCache(): Promise<UpdateCheckCache | null> {
  try {
    const raw = await fs.readFile(updateCheckPath(), "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && parsed.lastCheck && parsed.latestVersion) {
      return parsed as UpdateCheckCache;
    }
  } catch {
    // No cache
  }
  return null;
}

/**
 * Write the update check cache.
 */
async function writeUpdateCache(cache: UpdateCheckCache): Promise<void> {
  const dest = updateCheckPath();
  await fs.mkdir(path.dirname(dest), { recursive: true });
  await fs.writeFile(dest, JSON.stringify(cache, null, 2) + "\n", "utf8");
}

/**
 * Fetch the latest version from the npm registry.
 * Returns null on failure (network error, timeout, etc.).
 */
export function fetchLatestVersion(): Promise<string | null> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(null), 10000);

    const req = https.get(NPM_REGISTRY_URL, { timeout: 8000 }, (res) => {
      if (res.statusCode !== 200) {
        clearTimeout(timeout);
        res.resume();
        resolve(null);
        return;
      }
      let data = "";
      res.on("data", (chunk: Buffer) => {
        data += chunk.toString();
      });
      res.on("end", () => {
        clearTimeout(timeout);
        try {
          const parsed = JSON.parse(data);
          resolve(parsed.version || null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on("error", () => {
      clearTimeout(timeout);
      resolve(null);
    });
    req.on("timeout", () => {
      req.destroy();
      clearTimeout(timeout);
      resolve(null);
    });
  });
}

/**
 * Compare two semver strings. Returns:
 *   -1 if a < b
 *    0 if a === b
 *    1 if a > b
 */
export function compareSemver(a: string, b: string): -1 | 0 | 1 {
  const pa = a.replace(/^v/, "").split(".").map(Number);
  const pb = b.replace(/^v/, "").split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}

/**
 * Print an update notification if one is available.
 * Called on every CLI invocation (reads from cache, non-blocking).
 * Returns true if an update notification was printed.
 */
export async function printUpdateNotification(): Promise<boolean> {
  // Opt-out via env var
  if (process.env.OMNODEX_NO_UPDATE_CHECK === "1") return false;

  try {
    const method = detectInstallMethod();

    // Source installs: show git info instead of npm update notification
    if (method === "source") {
      const info = getSourceInstallInfo();
      if (info) {
        // Check if there are upstream changes
        const fetchResult = spawnSync("git", ["fetch", "--dry-run"], {
          cwd: info.repoRoot, encoding: "utf8", timeout: 8000,
        });
        // git fetch --dry-run outputs to stderr when there are changes
        if (fetchResult.status === 0 && fetchResult.stderr && fetchResult.stderr.trim()) {
          console.error(`\n  Omnodex source updates available (${info.branch} @ ${info.sha})`);
          console.error(`  Run \`omnodex update\` to pull and rebuild.\n`);
          return true;
        }
      }
      return false;
    }

    const cache = await readUpdateCache();
    if (!cache || !cache.success) return false;

    const installed = getInstalledVersion();
    if (installed === "0.0.0-dev") return false; // dev build, skip

    if (compareSemver(installed, cache.latestVersion) < 0) {
      console.error(
        `\n  Omnodex update available: ${installed} → ${cache.latestVersion}`,
      );
      console.error(`  Run \`omnodex update\` to upgrade.\n`);
      return true;
    }
  } catch {
    // Silently ignore errors in the notification path
  }
  return false;
}

/**
 * Spawn a background (detached) process that checks npm for updates
 * and writes the result to the cache file. Called on every CLI invocation.
 * Does nothing if the cache is fresh (< 24h old) or if opt-out is set.
 */
export async function scheduleBackgroundCheck(): Promise<void> {
  if (process.env.OMNODEX_NO_UPDATE_CHECK === "1") return;

  try {
    const cache = await readUpdateCache();
    if (cache && cache.lastCheck) {
      const lastCheck = new Date(cache.lastCheck).getTime();
      if (Date.now() - lastCheck < CHECK_INTERVAL_MS) return;
    }
  } catch {
    // No cache or unreadable — proceed with check
  }

  // Spawn a detached Node process that does the actual check.
  // This script runs independently and exits quickly.
  const checkScript = `
    const https = require("node:https");
    const fs = require("node:fs");
    const path = require("node:path");
    const os = require("node:os");

    const url = ${JSON.stringify(NPM_REGISTRY_URL)};
    const cachePath = ${JSON.stringify(updateCheckPath())};

    const req = https.get(url, { timeout: 8000 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); process.exit(0); }
      let data = "";
      res.on("data", (c) => { data += c; });
      res.on("end", () => {
        try {
          const version = JSON.parse(data).version;
          if (version) {
            const dir = path.dirname(cachePath);
            fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(cachePath, JSON.stringify({
              lastCheck: new Date().toISOString(),
              latestVersion: version,
              success: true,
            }, null, 2) + "\\n");
          }
        } catch (e) {}
        process.exit(0);
      });
    });
    req.on("error", () => process.exit(0));
    req.on("timeout", () => { req.destroy(); process.exit(0); });
  `;

  try {
    const child = spawn(process.execPath, ["-e", checkScript], {
      detached: true,
      stdio: "ignore",
    });
    child.unref();
  } catch {
    // Can't spawn — not critical
  }
}

/**
 * Run the `omnodex update` command.
 *
 * @param opts.check - If true, only check for updates (dry run)
 * @param opts.refreshLaunchers - If true, only refresh launchers (no npm install)
 */
export async function runUpdate(opts: {
  check?: boolean;
  refreshLaunchers?: boolean;
}): Promise<void> {
  const installed = getInstalledVersion();
  const method = detectInstallMethod();

  if (method === "source") {
    const info = getSourceInstallInfo();
    console.log(`[update] install method: source`);
    if (info) {
      console.log(`[update] repo:           ${info.repoRoot}`);
      console.log(`[update] branch:         ${info.branch}`);
      console.log(`[update] commit:         ${info.sha}${info.dirty ? " (modified)" : ""}`);
    }
  } else {
    console.log(`[update] installed version: ${installed}`);
    console.log(`[update] install method: ${method}`);
  }

  if (opts.refreshLaunchers) {
    console.log("[update] refreshing stable hook launchers...");
    const paths = await writeAllLaunchers();
    for (const [platform, p] of Object.entries(paths)) {
      console.log(`  ${platform}: ${p}`);
    }
    console.log("[update] launchers refreshed.");
    return;
  }

  // Source install: git pull + rebuild
  if (method === "source") {
    const info = getSourceInstallInfo();
    if (!info) {
      console.error("[update] could not locate the source repo. Update manually:");
      console.error("  cd <repo-root> && git pull && npm install && npm run build");
      process.exit(1);
    }

    if (opts.check) {
      // Fetch remote refs to see if there are updates
      console.log("[update] checking for upstream changes...");
      const fetchResult = spawnSync("git", ["fetch"], {
        cwd: info.repoRoot, stdio: "inherit", timeout: 15000,
      });
      if (fetchResult.status !== 0) {
        console.error("[update] git fetch failed. Check your network connection.");
        process.exit(1);
      }
      const logResult = spawnSync(
        "git", ["log", `HEAD..origin/${info.branch}`, "--oneline"],
        { cwd: info.repoRoot, encoding: "utf8", timeout: 5000 },
      );
      if (logResult.status === 0 && logResult.stdout.trim()) {
        const commits = logResult.stdout.trim().split("\n");
        console.log(`\n[update] ${commits.length} new commit(s) available on ${info.branch}:\n`);
        for (const line of commits.slice(0, 10)) {
          console.log(`  ${line}`);
        }
        if (commits.length > 10) {
          console.log(`  ... and ${commits.length - 10} more`);
        }
        console.log(`\n  Run \`omnodex update\` (without --check) to pull and rebuild.`);
      } else {
        console.log("[update] already up to date.");
      }
      return;
    }

    const success = await runSourceUpdate(info);
    if (!success) {
      process.exit(1);
    }

    // Refresh launchers with the rebuilt package
    console.log("\n[update] refreshing stable hook launchers...");
    const launcherPaths = await writeAllLaunchers();
    for (const [platform, p] of Object.entries(launcherPaths)) {
      console.log(`  ${platform}: ${p}`);
    }

    // Show new commit info
    const newInfo = getSourceInstallInfo();
    if (newInfo) {
      console.log(`\n[update] done. Now at ${newInfo.branch} @ ${newInfo.sha}`);
    } else {
      console.log("\n[update] done.");
    }
    console.log("[update] no need to re-run \`omnodex install\` — launchers resolve the new shims automatically.");
    return;
  }

  // npm install path
  console.log("[update] checking npm registry...");
  const latest = await fetchLatestVersion();

  if (!latest) {
    console.error(
      "[update] could not reach npm registry. Check your network connection.",
    );
    process.exit(1);
  }

  console.log(`[update] latest version: ${latest}`);

  if (compareSemver(installed, latest) >= 0) {
    console.log("[update] already up to date.");
    // Refresh launchers anyway in case format changed
    await writeAllLaunchers();
    return;
  }

  console.log(`[update] update available: ${installed} → ${latest}`);
  console.log(`[update] release notes: ${RELEASES_URL}`);

  if (opts.check) {
    console.log(
      `\n  Run \`omnodex update\` (without --check) to install the update.`,
    );
    return;
  }

  // Attempt npm install
  console.log(`\n[update] running: npm install -g omnodex@${latest}`);
  const result = spawnSync("npm", ["install", "-g", `omnodex@${latest}`], {
    stdio: "inherit",
    shell: true,
  });

  if (result.status !== 0) {
    // Check if it's a permissions error
    console.error("\n[update] npm install failed.");
    if (
      result.status === 243 ||
      result.status === 1 /* EACCES is often exit 1 */
    ) {
      console.error("[update] this may be a permissions issue. Try:");
      console.error(`\n  sudo npm install -g omnodex@${latest}`);
      console.error(
        "  omnodex update --refresh-launchers   # after the install completes\n",
      );
    }
    process.exit(1);
  }

  console.log(`\n[update] updated to ${latest}`);

  // Refresh launchers with the new package
  console.log("[update] refreshing stable hook launchers...");
  const paths = await writeAllLaunchers();
  for (const [platform, p] of Object.entries(paths)) {
    console.log(`  ${platform}: ${p}`);
  }

  // Update the cache so we don't nag on the next invocation
  await writeUpdateCache({
    lastCheck: new Date().toISOString(),
    latestVersion: latest,
    success: true,
  });

  console.log("\n[update] done. All hook installations will use the updated code.");
  console.log("[update] no need to re-run \`omnodex install\` — launchers resolve the new shims automatically.");
}
