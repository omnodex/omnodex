// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- server-observation
 *
 * Fingerprints of what an upstream MCP server looked like when it listed its
 * tools, so a later change to the server can be noticed: a new version, an
 * edited config entry, a tool added or removed, or a tool whose description
 * or input schema changed. The fingerprints go into server.observed events;
 * the analyzer compares them.
 *
 * Every fingerprint is a SHA-256 hash, cut to 32 hex characters, of
 * canonical JSON (object keys sorted), so key order and whitespace do not
 * change it. The config fingerprint takes the names of environment
 * variables and headers, never their values.
 *
 * The full tool lists are kept on this machine (snapshot files named by
 * their list fingerprint), so a change can be shown before and after
 * without putting descriptions in the event. Every failure to read or write
 * a file is ignored: observing a server never affects proxying it.
 */

import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { UpstreamServer } from "./config.js";
import type { ServerObservation } from "./core/events.js";

export type { ServerObservation };

/** JSON with object keys sorted at every level. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

export function fingerprint(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex").slice(0, 32);
}

/**
 * The parts of a config entry that decide what runs or what is reached.
 * Environment and header values are left out: they can hold credentials,
 * and a rotated token is not a different server.
 */
export function configFingerprint(server: UpstreamServer): string {
  if (server.transport === "stdio") {
    return fingerprint({
      transport: "stdio",
      command: server.command,
      args: server.args ?? [],
      cwd: server.cwd ?? null,
      env: Object.keys(server.env ?? {}).sort(),
    });
  }
  return fingerprint({
    transport: "http",
    url: server.url,
    headers: Object.keys(server.http_headers ?? {}).sort(),
    env_headers: Object.keys(server.env_http_headers ?? {}).sort(),
    bearer: server.bearer_token_env_var ?? null,
  });
}

/** A tool's fingerprint: its name, description and input schema. */
export function toolFingerprint(tool: Tool): string {
  return fingerprint({ name: tool.name, description: tool.description ?? null, inputSchema: tool.inputSchema });
}

/** The fingerprints of a tool list, sorted by name, and of the list as a whole. */
export function toolFingerprints(tools: Tool[]): Pick<ServerObservation, "tools" | "toolListFingerprint"> {
  const entries = tools
    .map((t) => ({ name: t.name, fingerprint: toolFingerprint(t) }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { tools: entries, toolListFingerprint: fingerprint(entries.map((e) => e.fingerprint)) };
}

// ---------------------------------------------------------------------------
// Installed version (npx)
// ---------------------------------------------------------------------------

/** npx flags that take the next word as their value. */
const NPX_VALUE_FLAGS = new Set(["-p", "--package", "-c", "--call", "--cache", "--registry", "--userconfig"]);

/**
 * The package an npx command runs, without its version: the --package
 * value when given, otherwise the first argument that is not a flag.
 * Undefined when the command is not npx.
 */
export function npxPackageName(command: string, args: readonly string[]): string | undefined {
  // Either separator: a config written on Windows can be read anywhere.
  const program = command.replace(/^.*[\\/]/, "").replace(/\.(cmd|exe)$/i, "").toLowerCase();
  if (program !== "npx") return undefined;
  let spec: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "-p" || a === "--package") {
      spec = args[i + 1];
      break;
    }
    if (a.startsWith("--package=")) {
      spec = a.slice("--package=".length);
      break;
    }
    if (a.startsWith("-")) {
      if (NPX_VALUE_FLAGS.has(a)) i++;
      continue;
    }
    spec = a;
    break;
  }
  if (!spec) return undefined;
  // @scope/name@version or name@version; a scope's leading @ is not a version.
  const at = spec.lastIndexOf("@");
  return at > 0 ? spec.slice(0, at) : spec;
}

/** Where npx keeps the packages it installs. */
function npxCacheDir(): string {
  const cache = process.env.npm_config_cache;
  if (cache) return path.join(cache, "_npx");
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, "npm-cache", "_npx");
  }
  return path.join(os.homedir(), ".npm", "_npx");
}

/**
 * Best effort: the version of the package an npx upstream runs, read from
 * the most recently installed copy in the npx cache. Undefined when the
 * upstream is not npx or the package cannot be found.
 */
export function npxInstalledVersion(server: UpstreamServer, cacheDir = npxCacheDir()): string | undefined {
  if (server.transport !== "stdio") return undefined;
  const name = npxPackageName(server.command, server.args ?? []);
  if (!name) return undefined;
  try {
    let newest: { mtime: number; version: string } | undefined;
    for (const dir of fs.readdirSync(cacheDir)) {
      const manifest = path.join(cacheDir, dir, "node_modules", ...name.split("/"), "package.json");
      try {
        const stat = fs.statSync(manifest);
        if (newest && stat.mtimeMs <= newest.mtime) continue;
        const version = (JSON.parse(fs.readFileSync(manifest, "utf8")) as { version?: unknown }).version;
        if (typeof version === "string") newest = { mtime: stat.mtimeMs, version };
      } catch {
        // Not in this cache entry.
      }
    }
    return newest?.version;
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Observation and snapshots
// ---------------------------------------------------------------------------

export function observeServer(fields: {
  server: UpstreamServer;
  trigger: ServerObservation["trigger"];
  tools: Tool[];
  reported?: { name?: string; version?: string };
  installedVersion?: string;
}): ServerObservation {
  const { server } = fields;
  return {
    server: server.name,
    transport: server.transport,
    trigger: fields.trigger,
    configFingerprint: configFingerprint(server),
    ...(fields.reported?.name
      ? { reported: { name: fields.reported.name, ...(fields.reported.version ? { version: fields.reported.version } : {}) } }
      : {}),
    ...(fields.installedVersion ? { installedVersion: fields.installedVersion } : {}),
    ...toolFingerprints(fields.tools),
  };
}

/** Snapshot files kept; the oldest are removed past this. */
const MAX_SNAPSHOTS = 200;

export interface ToolListSnapshots {
  /** Keeps a tool list under its list fingerprint, if not already kept. */
  save(toolListFingerprint: string, server: string, tools: Tool[]): void;
  /** The tool list kept under a fingerprint, or undefined. */
  load(toolListFingerprint: string): Tool[] | undefined;
}

/** Snapshots kept as one JSON file per list fingerprint in dir. */
export function createToolListSnapshots(dir: string): ToolListSnapshots {
  const fileFor = (fp: string) => path.join(dir, `${fp.replace(/[^0-9a-f]/gi, "")}.json`);
  return {
    save(fp, server, tools) {
      try {
        const file = fileFor(fp);
        if (fs.existsSync(file)) return;
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(file, JSON.stringify({ version: 1, server, saved_at: new Date().toISOString(), tools }));
        prune(dir);
      } catch {
        // Snapshots only serve a later view; never let them fail a proxy.
      }
    },
    load(fp) {
      try {
        const parsed = JSON.parse(fs.readFileSync(fileFor(fp), "utf8")) as { tools?: unknown };
        return Array.isArray(parsed.tools) ? (parsed.tools as Tool[]) : undefined;
      } catch {
        return undefined;
      }
    },
  };
}

function prune(dir: string): void {
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
  if (files.length <= MAX_SNAPSHOTS) return;
  const byAge = files
    .map((f) => ({ f, mtime: fs.statSync(path.join(dir, f)).mtimeMs }))
    .sort((a, b) => a.mtime - b.mtime);
  for (const { f } of byAge.slice(0, files.length - MAX_SNAPSHOTS)) {
    fs.rmSync(path.join(dir, f), { force: true });
  }
}
