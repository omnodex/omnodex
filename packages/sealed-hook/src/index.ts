// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The sealed hook, as a function: one hook call in, what to print out.
 * The bin wraps this with stdin, stdout and exit handling.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  handleHookPayload,
  ingestDir,
  makeCurlPoster,
  postWithFetch,
  withFallback,
  type Poster,
} from "@omnodex/hooks-provider";
import { providerSetup } from "./adapters.js";
import { HOST_MARKER_FILE, isSealedProvider, loadSealedConfig, shouldCapture, type SealedProvider } from "./config.js";

export * from "./config.js";
export { providerSetup } from "./adapters.js";

export interface RunOptions {
  provider: string | undefined;
  /** Antigravity's event name argument. */
  eventName?: string;
  stdin: string;
  env: Record<string, string | undefined>;
  /** Spool and state location; defaults to ~/.omnodex. */
  home?: string;
  post?: Poster;
  now?: () => number;
}

function usable(value: string | undefined): value is string {
  // Hosts that do not expand ${VAR} pass the placeholder through literally.
  return typeof value === "string" && value.length > 0 && !value.startsWith("${");
}

/**
 * The Omnodex home a hook call reads settings from: OMNODEX_HOME when it is an
 * absolute path, else ~/.omnodex. A relative value would be read from the
 * project directory.
 */
export function sealedHome(env: Record<string, string | undefined>): string {
  const named = env.OMNODEX_HOME;
  return usable(named) && path.isAbsolute(named) ? named : path.join(os.homedir(), ".omnodex");
}

/**
 * Handles one hook call and returns the text to print. Never throws, and
 * captures nothing unless the provider is known, the host passes its gate and
 * the settings are complete.
 */
export async function runSealedHook(options: RunOptions): Promise<string> {
  const provider: SealedProvider | undefined = isSealedProvider(options.provider) ? options.provider : undefined;
  if (!provider) return "";
  const setup = providerSetup(provider, options.eventName);
  const quiet = setup ? setup.stdout(options.eventName) : "{}";
  try {
    const home = options.home ?? sealedHome(options.env);
    if (!setup || !shouldCapture(provider, options.env, fs.existsSync(path.join(home, HOST_MARKER_FILE)))) return quiet;

    let payload: unknown;
    try {
      payload = JSON.parse(options.stdin);
    } catch {
      return quiet;
    }
    if (!payload || typeof payload !== "object") return quiet;

    const dirs = [options.env.CLAUDE_PROJECT_DIR, (payload as { cwd?: unknown }).cwd, process.cwd()].filter(
      (d): d is string => typeof d === "string" && d.length > 0,
    );
    const config = await loadSealedConfig(options.env, { home, projectDirs: dirs });
    if (!config) return quiet;

    await handleHookPayload(payload as { hook_event_name?: unknown }, config, {
      home,
      post: options.post ?? withFallback(postWithFetch, makeCurlPoster(ingestDir(home))),
      now: options.now,
      adapter: setup.adapter,
      platform: setup.platform,
    });
    return quiet;
  } catch {
    return quiet;
  }
}
