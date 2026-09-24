#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * container-hook
 *
 * Hook command for the Cowork plugin, bundled into a single file that ships
 * inside the plugin. It captures only in a cloud-hosted agent container and
 * only when the plugin carries a valid ingest.json; everywhere else, such as
 * local Claude Code with the same plugin synced in, it exits at once, since
 * the local hooks and proxy already capture there.
 *
 * Contract: reads one JSON payload from stdin, prints nothing, always exits 0.
 *
 * Environment:
 *   CLAUDE_PLUGIN_ROOT  plugin directory holding ingest.json (defaults to the
 *                       parent of this script's directory)
 *   OMNODEX_HOME        spool location, defaults to ~/.omnodex
 */

import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import {
  handleHookPayload,
  ingestDir,
  isCloudContainer,
  loadIngestConfig,
  makeCurlPoster,
  postWithFetch,
  withFallback,
} from "../container-hook.js";

const MAX_STDIN_BYTES = 5 * 1024 * 1024;

function usable(value: string | undefined): value is string {
  // Hosts that do not expand ${VAR} pass the placeholder through literally.
  return typeof value === "string" && value.length > 0 && !value.startsWith("${");
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= MAX_STDIN_BYTES) chunks.push(c);
    });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => resolve(""));
  });
}

async function main(): Promise<void> {
  const pluginRoot = usable(process.env.CLAUDE_PLUGIN_ROOT)
    ? process.env.CLAUDE_PLUGIN_ROOT
    : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const config = await loadIngestConfig(pluginRoot);
  if (!config) return;
  if (!config.force && !isCloudContainer()) return;

  const raw = await readStdin();
  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    return;
  }
  if (!payload || typeof payload !== "object") return;

  const home = usable(process.env.OMNODEX_HOME) ? process.env.OMNODEX_HOME : path.join(os.homedir(), ".omnodex");
  await handleHookPayload(payload as { hook_event_name?: unknown }, config, {
    home,
    post: withFallback(postWithFetch, makeCurlPoster(ingestDir(home))),
  });
}

main()
  .catch(() => undefined)
  .finally(() => process.exit(0));
