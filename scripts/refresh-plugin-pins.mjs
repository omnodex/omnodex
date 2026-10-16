#!/usr/bin/env node
/**
 * Rewrites packages/cli/src/plugin-pins.ts from the published plugin
 * manifest, so the next CLI release installs the current plugin versions.
 * Run after publishing plugins, check the diff, and commit it in a PR.
 *
 *   node scripts/refresh-plugin-pins.mjs           write the file
 *   node scripts/refresh-plugin-pins.mjs --check   exit 1 if it is out of date
 *
 * OMNODEX_DOWNLOADS_URL overrides https://downloads.omnodex.com.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.OMNODEX_DOWNLOADS_URL ?? "https://downloads.omnodex.com";
const FILE = join(dirname(fileURLToPath(import.meta.url)), "..", "packages", "cli", "src", "plugin-pins.ts");
const PLATFORMS = ["cowork", "codex", "antigravity"];

const res = await fetch(`${BASE}/plugins/latest.json?t=${Date.now()}`, { cache: "no-store" });
if (!res.ok) {
  console.error(`refresh-plugin-pins: fetching latest.json failed: HTTP ${res.status}`);
  process.exit(2);
}
const latest = await res.json();
const pins = {};
for (const platform of PLATFORMS) {
  const entry = latest.plugins?.[platform];
  if (!entry || !/^[0-9a-f]{64}$/.test(entry.sha256 ?? "") || typeof entry.version !== "string") {
    console.error(`refresh-plugin-pins: latest.json has no usable entry for ${platform}`);
    process.exit(2);
  }
  pins[platform] = { version: entry.version, sha256: entry.sha256, size: entry.size };
}

const current = readFileSync(FILE, "utf8");
const marker = "export const PLUGIN_PINS";
const head = current.slice(0, current.indexOf(marker));
const next = `${head}${marker}: Record<"cowork" | "codex" | "antigravity", PluginPin> = ${JSON.stringify(pins, null, 2)};\n`;

if (process.argv.includes("--check")) {
  if (next !== current) {
    console.error("refresh-plugin-pins: plugin-pins.ts is behind the published plugins; run node scripts/refresh-plugin-pins.mjs");
    process.exit(1);
  }
  console.log("refresh-plugin-pins: up to date");
} else if (next === current) {
  console.log("refresh-plugin-pins: already up to date");
} else {
  writeFileSync(FILE, next);
  for (const p of PLATFORMS) console.log(`  ${p} ${pins[p].version} ${pins[p].sha256}`);
  console.log("refresh-plugin-pins: wrote packages/cli/src/plugin-pins.ts");
}
