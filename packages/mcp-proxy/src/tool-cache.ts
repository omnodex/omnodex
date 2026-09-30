// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- tool-cache
 *
 * Remembers each upstream's tool list between proxy runs, so the proxy can
 * list an upstream's tools before that upstream has finished starting.
 *
 * Agent clients read the tool list once, when they connect, and ignore
 * notifications/tools/list_changed. An upstream that starts slower than the
 * discovery window (a cold `npx -y` on Windows can take 15 seconds or more)
 * would otherwise be missing for the whole session. With a cached list the
 * tools are listed at once, and a call to one waits for its upstream.
 *
 * One small JSON file per upstream, named by a hash of that upstream's
 * config entry, so editing the entry (command, args, URL, env) starts it
 * fresh and removing it leaves nothing that is read again. Only tool
 * definitions are stored, never environment values or credentials.
 * Every failure to read or write is ignored: the cache only ever saves time.
 */

import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { UpstreamServer } from "./config.js";

/** Lists larger than this are not written; no real upstream comes close. */
const MAX_CACHE_BYTES = 1_000_000;

export interface ToolListCache {
  /** The upstream's tools as it last listed them, or undefined. */
  load(server: UpstreamServer): Tool[] | undefined;
  /** Records the upstream's tools as it listed them just now. */
  save(server: UpstreamServer, tools: Tool[]): void;
}

interface CacheFile {
  version: 1;
  server: string;
  saved_at: string;
  tools: Tool[];
}

/** Stable key for one upstream's config entry. */
export function upstreamCacheKey(server: UpstreamServer): string {
  return createHash("sha256").update(JSON.stringify(server)).digest("hex").slice(0, 32);
}

/** A cache kept as files in dir, created on first write. */
export function createToolListCache(dir: string): ToolListCache {
  const fileFor = (server: UpstreamServer) => path.join(dir, `${upstreamCacheKey(server)}.json`);
  return {
    load(server) {
      try {
        const parsed = JSON.parse(fs.readFileSync(fileFor(server), "utf8")) as Partial<CacheFile>;
        if (parsed.version !== 1 || !Array.isArray(parsed.tools)) return undefined;
        const tools = parsed.tools.filter(
          (t): t is Tool => typeof t?.name === "string" && typeof t.inputSchema === "object"
        );
        return tools.length > 0 ? tools : undefined;
      } catch {
        return undefined;
      }
    },
    save(server, tools) {
      const file = fileFor(server);
      const body: CacheFile = {
        version: 1,
        server: server.name,
        saved_at: new Date().toISOString(),
        tools,
      };
      const text = JSON.stringify(body);
      if (text.length > MAX_CACHE_BYTES) return;
      // Written under a unique name and renamed, so a proxy for another agent
      // reading the same upstream's entry never sees half a file.
      const temp = `${file}.${randomUUID()}.tmp`;
      try {
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(temp, text);
        fs.renameSync(temp, file);
      } catch {
        try {
          fs.rmSync(temp, { force: true });
        } catch {
          // Nothing more to do.
        }
      }
    },
  };
}
