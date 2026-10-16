// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * plugins.ts
 *
 * Installs each agent's Omnodex plugin (its MCP proxy) from
 * downloads.omnodex.com: pick the version (the pin in plugin-pins.ts unless
 * the user asks for another), download and verify it, unpack it where the
 * agent looks for plugins, and register it with the agent's own CLI when
 * that CLI is on PATH.
 *
 *   Claude Code   ~/.omnodex/plugins/claude-marketplace/ as a local
 *                 marketplace, then `claude plugin install --scope user`
 *   Codex         $CODEX_HOME/plugins/omnodex-codex/, an entry in the
 *                 personal marketplace ~/.agents/plugins/marketplace.json,
 *                 then `codex plugin add`
 *   Antigravity   ~/.gemini/config/plugins/omnodex-antigravity/, which the
 *                 app, IDE and `agy` all load, then the bundle's configure.js
 *
 * Bundles are zip archives; a small reader below unpacks them, so nothing
 * depends on an unzip tool being installed.
 */

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { inflateRawSync } from "node:zlib";
import type { LauncherPlatform } from "./launcher-template.js";
import { PLUGIN_PINS, type PluginPin } from "./plugin-pins.js";
import { findOnPath } from "./surfaces.js";

export type PluginPlatform = keyof typeof PLUGIN_PINS;

/** Each surface's plugin: the downloads platform and the plugin's name. */
export const SURFACE_PLUGIN: Record<LauncherPlatform, { platform: PluginPlatform; name: string; manifest: string }> = {
  "claude-code": { platform: "cowork", name: "omnodex-cowork", manifest: ".claude-plugin/plugin.json" },
  codex: { platform: "codex", name: "omnodex-codex", manifest: ".codex-plugin/plugin.json" },
  antigravity: { platform: "antigravity", name: "omnodex-antigravity", manifest: ".antigravity-plugin/plugin.json" },
};

/** Marketplace name Omnodex uses where it creates one. */
export const LOCAL_MARKETPLACE = "omnodex-local";

export function downloadsBaseUrl(env: NodeJS.ProcessEnv = process.env): string {
  return (env.OMNODEX_DOWNLOADS_URL || "https://downloads.omnodex.com").replace(/\/+$/, "");
}

const bundleFile = (platform: PluginPlatform) => `omnodex-${platform}.plugin`;
const sha256Hex = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const SHA256 = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// Zip archives
// ---------------------------------------------------------------------------

export interface ZipEntry {
  name: string;
  /** null for a directory entry */
  data: Buffer | null;
}

/** Reads a zip archive (stored or deflated entries). */
export function readZip(buf: Buffer): ZipEntry[] {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a zip archive");
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("damaged zip central directory");
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const nameLength = buf.readUInt16LE(p + 28);
    const extraLength = buf.readUInt16LE(p + 30);
    const commentLength = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLength);
    p += 46 + nameLength + extraLength + commentLength;

    if (name.endsWith("/")) {
      entries.push({ name, data: null });
      continue;
    }
    if (buf.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`damaged zip entry ${name}`);
    const start = localOffset + 30 + buf.readUInt16LE(localOffset + 26) + buf.readUInt16LE(localOffset + 28);
    const raw = buf.subarray(start, start + compressedSize);
    if (method === 0) entries.push({ name, data: Buffer.from(raw) });
    else if (method === 8) entries.push({ name, data: inflateRawSync(raw) });
    else throw new Error(`zip entry ${name} uses unsupported compression method ${method}`);
  }
  return entries;
}

/** Unpacks a zip archive into dest, refusing entries that would land outside it. */
export async function extractZip(buf: Buffer, dest: string): Promise<void> {
  const root = path.resolve(dest);
  const entries = readZip(buf);
  for (const entry of entries) {
    const target = path.resolve(root, ...entry.name.split("/").filter(Boolean));
    if (path.isAbsolute(entry.name) || (target !== root && !target.startsWith(root + path.sep))) {
      throw new Error(`zip entry ${entry.name} would be written outside ${dest}`);
    }
  }
  await fs.mkdir(root, { recursive: true });
  for (const entry of entries) {
    const target = path.resolve(root, ...entry.name.split("/").filter(Boolean));
    if (entry.data === null) {
      await fs.mkdir(target, { recursive: true });
    } else {
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, entry.data);
    }
  }
}

/** The version in a bundle's own manifest. */
export function bundleVersion(bytes: Buffer, target: LauncherPlatform): string | null {
  const entry = readZip(bytes).find((e) => e.name === SURFACE_PLUGIN[target].manifest);
  if (!entry?.data) return null;
  try {
    const version = JSON.parse(entry.data.toString("utf8")).version;
    return typeof version === "string" ? version : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Choosing and verifying the bundle
// ---------------------------------------------------------------------------

export interface BundleRequest {
  target: LauncherPlatform;
  /** --plugin-version: a version, or "latest". Omitted: the pin. */
  version?: string;
  /** --from: a bundle file already downloaded. */
  from?: string;
  /** --sha256: the checksum the user expects for --from. */
  sha256?: string;
  baseUrl: string;
  /** Where downloaded bundles are kept: <OMNODEX_HOME>/plugins/cache. */
  cacheDir: string;
  /** The pins to install by default (tests pass their own). */
  pins?: Record<PluginPlatform, PluginPin>;
}

export interface ResolvedBundle {
  bytes: Buffer;
  version: string;
  sha256: string;
  /** True when this is not the version the CLI pins. */
  override: boolean;
  /** Where it came from, for messages. */
  source: string;
}

async function fetchOk(url: string): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(url, { cache: "no-store", signal: AbortSignal.timeout(60_000) });
  } catch (err) {
    throw new Error(`could not reach ${new URL(url).host}: ${(err as Error).message}`);
  }
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`);
  return res;
}

/** Published versions of a platform, from its versions.json; null when unreachable. */
async function publishedVersions(baseUrl: string, platform: PluginPlatform): Promise<{ version: string; sha256: string }[] | null> {
  try {
    const index = await (await fetchOk(`${baseUrl}/plugins/${platform}/versions.json?t=${Date.now()}`)).json();
    return Array.isArray(index?.versions) ? index.versions : null;
  } catch {
    return null;
  }
}

/**
 * Picks the bundle to install and checks it. Downloads are verified against
 * the pinned sha256, or for another version against its published checksum.
 * A file passed with --from must match the pin, a published checksum or the
 * user's --sha256; anything else is refused.
 */
export async function resolveBundle(req: BundleRequest): Promise<ResolvedBundle> {
  const { platform } = SURFACE_PLUGIN[req.target];
  const pin = (req.pins ?? PLUGIN_PINS)[platform];
  const wanted = req.sha256?.toLowerCase();
  if (wanted !== undefined && !SHA256.test(wanted)) throw new Error(`--sha256 must be 64 hex characters`);

  if (req.from) {
    const bytes = await fs.readFile(req.from);
    const sha256 = sha256Hex(bytes);
    if (wanted && sha256 !== wanted) {
      throw new Error(`${req.from} has sha256 ${sha256}, not the ${wanted} given with --sha256; not installed`);
    }
    const pinned = sha256 === pin.sha256 && (!req.version || req.version === pin.version);
    if (pinned) return { bytes, version: pin.version, sha256, override: false, source: req.from };
    const published = (await publishedVersions(req.baseUrl, platform))?.find(
      (v) => v.sha256 === sha256 && (!req.version || req.version === "latest" || v.version === req.version),
    );
    if (published) {
      return { bytes, version: published.version, sha256, override: published.version !== pin.version, source: req.from };
    }
    if (wanted) {
      const version = bundleVersion(bytes, req.target) ?? "unknown";
      return { bytes, version, sha256, override: true, source: req.from };
    }
    throw new Error(
      `${req.from} (sha256 ${sha256}) matches neither the pinned ${platform} plugin nor a published checksum; ` +
      `not installed. If you trust this file, pass --sha256 ${sha256}`,
    );
  }

  let version = pin.version;
  let expected = pin.sha256;
  if (req.version === "latest") {
    const latest = await (await fetchOk(`${req.baseUrl}/plugins/latest.json?t=${Date.now()}`)).json();
    const entry = latest?.plugins?.[platform];
    if (!entry || !SHA256.test(entry.sha256 ?? "")) throw new Error(`latest.json has no ${platform} entry`);
    version = entry.version;
    expected = entry.sha256;
  } else if (req.version && req.version !== pin.version) {
    version = req.version;
    const sumUrl = `${req.baseUrl}/plugins/${platform}/${version}/${bundleFile(platform)}.sha256`;
    let text: string;
    try {
      text = await (await fetchOk(sumUrl)).text();
    } catch (err) {
      throw new Error(`no published checksum for ${platform} ${version} (${(err as Error).message}); is that version published?`);
    }
    expected = text.trim().split(/\s+/)[0].toLowerCase();
    if (!SHA256.test(expected)) throw new Error(`${sumUrl} is not a sha256 checksum`);
  }

  const cached = path.join(req.cacheDir, `${platform}-${version}.plugin`);
  try {
    const bytes = await fs.readFile(cached);
    if (sha256Hex(bytes) === expected) {
      return { bytes, version, sha256: expected, override: version !== pin.version, source: cached };
    }
  } catch {
    // not cached yet
  }

  const url = `${req.baseUrl}/plugins/${platform}/${version}/${bundleFile(platform)}`;
  const bytes = Buffer.from(await (await fetchOk(url)).arrayBuffer());
  const got = sha256Hex(bytes);
  if (got !== expected) {
    throw new Error(`checksum mismatch for ${url}: expected ${expected}, got ${got}; not installed`);
  }
  await fs.mkdir(req.cacheDir, { recursive: true });
  await fs.writeFile(cached, bytes);
  return { bytes, version, sha256: got, override: version !== pin.version, source: url };
}

// ---------------------------------------------------------------------------
// Agent CLIs
// ---------------------------------------------------------------------------

type HostRun = { status: "missing" } | { status: "ok" | "failed"; output: string };

/** Runs an agent's CLI when it is on PATH. */
function runHost(command: string, args: string[], env: NodeJS.ProcessEnv): HostRun {
  const exe = findOnPath(command, { platform: process.platform, env });
  if (!exe) return { status: "missing" };
  const win = process.platform === "win32";
  // .cmd wrappers need a shell on Windows; quote what has spaces.
  const argv = win ? args.map((a) => (/[\s"]/.test(a) ? `"${a.replace(/"/g, '""')}"` : a)) : args;
  const r = spawnSync(win && /\s/.test(exe) ? `"${exe}"` : exe, argv, {
    env,
    encoding: "utf8",
    shell: win,
    timeout: 120_000,
  });
  const output = `${r.stdout ?? ""}${r.stderr ?? ""}${r.error ? r.error.message : ""}`.trim();
  return { status: r.status === 0 ? "ok" : "failed", output };
}

const lastLine = (text: string) => text.split(/\r?\n/).filter(Boolean).pop() ?? "";

// ---------------------------------------------------------------------------
// Install and remove, per agent
// ---------------------------------------------------------------------------

export interface PluginContext {
  home: string;
  omnodexHome: string;
  env: NodeJS.ProcessEnv;
  /** The project install ran in, for duplicate checks that are per project. */
  projectPath?: string;
}

export interface PluginInstallResult {
  /** Where the plugin files are. */
  pluginPath: string;
  /** What registered it, or what the user still has to do. */
  steps: string[];
  /** Possible duplicate connections the user should remove. */
  warnings: string[];
  /** True when the agent's CLI registered it (no app step left). */
  registered: boolean;
}

export const codexHome = (ctx: PluginContext) => ctx.env.CODEX_HOME || path.join(ctx.home, ".codex");
const codexMarketplaceFile = (ctx: PluginContext) => path.join(ctx.home, ".agents", "plugins", "marketplace.json");
const claudeMarketplaceDir = (ctx: PluginContext) => path.join(ctx.omnodexHome, "plugins", "claude-marketplace");
const antigravityPluginDir = (ctx: PluginContext) => path.join(ctx.home, ".gemini", "config", "plugins", "omnodex-antigravity");

/** Where a surface's plugin files live once installed. */
export function pluginDir(target: LauncherPlatform, ctx: PluginContext): string {
  switch (target) {
    case "claude-code":
      return path.join(claudeMarketplaceDir(ctx), "omnodex-cowork");
    case "codex":
      return path.join(codexHome(ctx), "plugins", "omnodex-codex");
    case "antigravity":
      return antigravityPluginDir(ctx);
  }
}

async function readJsonFile(file: string): Promise<Record<string, unknown> | null> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new Error(`${file} is not valid JSON; fix or remove it, then run install again`);
  }
}

async function writeJsonFile(file: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(value, null, 2) + "\n", "utf8");
}

/** Replace the plugin folder with the bundle's contents. */
async function unpackInto(dir: string, bytes: Buffer): Promise<void> {
  await fs.rm(dir, { recursive: true, force: true });
  await extractZip(bytes, dir);
}

interface PluginEntry {
  name?: string;
  [key: string]: unknown;
}

async function installCodex(bundle: ResolvedBundle, ctx: PluginContext): Promise<PluginInstallResult> {
  const dir = pluginDir("codex", ctx);
  await unpackInto(dir, bundle.bytes);

  // The personal marketplace: keep its name and other plugins.
  const file = codexMarketplaceFile(ctx);
  const existing = (await readJsonFile(file)) ?? {};
  const name = typeof existing.name === "string" && existing.name ? existing.name : LOCAL_MARKETPLACE;
  const relative = path.relative(ctx.home, dir);
  const sourcePath = relative && !relative.startsWith("..") && !path.isAbsolute(relative)
    ? `./${relative.split(path.sep).join("/")}`
    : dir;
  const entry = {
    name: "omnodex-codex",
    source: { source: "local", path: sourcePath },
    policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
    category: "Productivity",
  };
  const plugins = (Array.isArray(existing.plugins) ? existing.plugins as PluginEntry[] : []).filter((p) => p?.name !== "omnodex-codex");
  await writeJsonFile(file, {
    ...existing,
    name,
    interface: existing.interface ?? { displayName: "Omnodex local" },
    plugins: [...plugins, entry],
  });

  const warnings: string[] = [];
  const config = await fs.readFile(path.join(codexHome(ctx), "config.toml"), "utf8").catch(() => "");
  if (/^\s*\[mcp_servers\.omnodex\]/m.test(config)) {
    warnings.push("Codex also has a manual `omnodex` MCP server, which would start a second proxy. Remove it with `codex mcp remove omnodex`.");
  }

  const run = runHost("codex", ["plugin", "add", `omnodex-codex@${name}`], ctx.env);
  const steps = [`added omnodex-codex to the personal marketplace ${file}`];
  if (run.status === "ok") steps.push(`registered with \`codex plugin add omnodex-codex@${name}\``);
  else {
    if (run.status === "failed") steps.push(`\`codex plugin add\` failed: ${lastLine(run.output)}`);
    steps.push(`in ChatGPT Desktop: quit and reopen, open Plugins, choose your personal marketplace, and install Omnodex`);
  }
  return { pluginPath: dir, steps, warnings, registered: run.status === "ok" };
}

async function installClaude(bundle: ResolvedBundle, ctx: PluginContext): Promise<PluginInstallResult> {
  const marketplace = claudeMarketplaceDir(ctx);
  const dir = pluginDir("claude-code", ctx);
  await unpackInto(dir, bundle.bytes);
  await writeJsonFile(path.join(marketplace, ".claude-plugin", "marketplace.json"), {
    name: LOCAL_MARKETPLACE,
    owner: { name: "Omnodex" },
    plugins: [{
      name: "omnodex-cowork",
      source: "./omnodex-cowork",
      description: "Omnodex MCP proxy: records the MCP tool calls Claude makes",
      version: bundle.version,
    }],
  });

  const warnings: string[] = [];
  const claudeJson = await readJsonFile(path.join(ctx.home, ".claude.json")).catch(() => null);
  if (claudeJson && typeof claudeJson.mcpServers === "object" && claudeJson.mcpServers && "omnodex" in claudeJson.mcpServers) {
    warnings.push("Claude Code also has a manual `omnodex` MCP server, which would start a second proxy. Remove it with `claude mcp remove omnodex`.");
  }

  const selector = `omnodex-cowork@${LOCAL_MARKETPLACE}`;
  const steps = [`unpacked into the local marketplace ${marketplace}`];
  const add = runHost("claude", ["plugin", "marketplace", "add", marketplace], ctx.env);
  if (add.status === "missing") {
    steps.push(`claude is not on PATH; run \`claude plugin marketplace add "${marketplace}"\` and \`claude plugin install ${selector} --scope user\``);
    return { pluginPath: dir, steps, warnings, registered: false };
  }
  // Re-adding an existing marketplace fails; refresh it instead.
  if (add.status === "failed") runHost("claude", ["plugin", "marketplace", "update", LOCAL_MARKETPLACE], ctx.env);
  let install = runHost("claude", ["plugin", "install", selector, "--scope", "user"], ctx.env);
  if (install.status === "ok" && /already installed/i.test(install.output)) {
    install = runHost("claude", ["plugin", "update", selector, "--scope", "user"], ctx.env);
  }
  if (install.status === "ok") steps.push(`registered with \`claude plugin install ${selector} --scope user\``);
  else if (install.status === "failed") steps.push(`\`claude plugin install\` failed: ${lastLine(install.output)}`);
  return { pluginPath: dir, steps, warnings, registered: install.status === "ok" };
}

async function installAntigravity(bundle: ResolvedBundle, ctx: PluginContext): Promise<PluginInstallResult> {
  const dir = pluginDir("antigravity", ctx);
  await unpackInto(dir, bundle.bytes);
  const steps = [`unpacked into ${dir}, which the Antigravity app, IDE and agy load`];
  // Absolute node, launcher and working-directory paths for this host.
  const configure = path.join(dir, "bin", "configure.js");
  try {
    await fs.access(configure);
    const r = spawnSync(process.execPath, [configure], { cwd: os.tmpdir(), env: ctx.env, encoding: "utf8", timeout: 60_000 });
    if (r.status !== 0) throw new Error(lastLine(`${r.stdout}${r.stderr}`) || `exit ${r.status}`);
    steps.push("configured the plugin's paths for this host");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw new Error(`configuring the Antigravity plugin failed: ${(err as Error).message}`);
  }
  const warnings: string[] = [];
  if (ctx.projectPath) {
    const mcp = await readJsonFile(path.join(ctx.projectPath, ".agents", "mcp_config.json")).catch(() => null);
    if (mcp && typeof mcp.mcpServers === "object" && mcp.mcpServers && "omnodex" in mcp.mcpServers) {
      warnings.push("this project's .agents/mcp_config.json also starts the Omnodex proxy; remove its `omnodex` entry so the plugin's proxy is the only one.");
    }
  }
  return { pluginPath: dir, steps, warnings, registered: true };
}

/** Unpack a verified bundle and register it with the agent. */
export async function installPlugin(
  target: LauncherPlatform,
  bundle: ResolvedBundle,
  ctx: PluginContext,
): Promise<PluginInstallResult> {
  switch (target) {
    case "claude-code":
      return installClaude(bundle, ctx);
    case "codex":
      return installCodex(bundle, ctx);
    case "antigravity":
      return installAntigravity(bundle, ctx);
  }
}

/** Unregister and delete a surface's plugin. Returns what was done. */
export async function uninstallPlugin(target: LauncherPlatform, ctx: PluginContext): Promise<string[]> {
  const done: string[] = [];
  const dir = pluginDir(target, ctx);
  if (target === "codex") {
    const file = codexMarketplaceFile(ctx);
    const existing = await readJsonFile(file);
    const name = typeof existing?.name === "string" ? existing.name : LOCAL_MARKETPLACE;
    const run = runHost("codex", ["plugin", "remove", `omnodex-codex@${name}`], ctx.env);
    if (run.status === "ok") done.push(`ran \`codex plugin remove omnodex-codex@${name}\``);
    if (existing && Array.isArray(existing.plugins)) {
      const plugins = (existing.plugins as PluginEntry[]).filter((p) => p?.name !== "omnodex-codex");
      if (plugins.length === 0 && name === LOCAL_MARKETPLACE) await fs.rm(file, { force: true });
      else await writeJsonFile(file, { ...existing, plugins });
      done.push(`removed omnodex-codex from ${file}`);
    }
  } else if (target === "claude-code") {
    const selector = `omnodex-cowork@${LOCAL_MARKETPLACE}`;
    const run = runHost("claude", ["plugin", "uninstall", selector, "--scope", "user"], ctx.env);
    if (run.status === "ok") done.push(`ran \`claude plugin uninstall ${selector}\``);
    if (run.status === "missing") done.push(`claude is not on PATH; run \`claude plugin uninstall ${selector}\` where it is`);
    runHost("claude", ["plugin", "marketplace", "remove", LOCAL_MARKETPLACE], ctx.env);
    await fs.rm(claudeMarketplaceDir(ctx), { recursive: true, force: true });
  }
  await fs.rm(dir, { recursive: true, force: true });
  done.push(`deleted ${dir}`);
  return done;
}
