// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Which Omnodex homes need an agent's hooks file to answer before each call.
 *
 * One hooks file can serve several Omnodex homes: a project used from both
 * native Windows and WSL, or a project folder synced between computers.
 * Guardrails need the file's PreToolUse hook to run before the call, and
 * each home knows only its own mode. A sidecar next to the hooks file lists
 * the homes in guardrails that use it, so leaving guardrails in one home
 * keeps the hook in place while another home still needs it.
 *
 * The list lives beside the hooks file rather than in it because agents
 * rewrite their own settings files and drop keys they do not know. Entries
 * are hashes of the host name and home path, so the file names no user or
 * path. It exists only while some home is listed.
 *
 * Node only: import from "@omnodex/shared/guardrails-hooks".
 */

import { createHash } from "node:crypto";
import { promises as fs, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseEnforcementConfig } from "./enforcement.js";

const SIDECAR_SUFFIX = ".omnodex-guardrails.json";
const SIDECAR_VERSION = 1;

interface Sidecar {
  version: number;
  homes: string[];
}

/** The sidecar for a hooks file: `<dir>/<name>.omnodex-guardrails.json`. */
export function guardrailsSidecarPath(hooksFile: string): string {
  const base = path.basename(hooksFile).replace(/\.json$/i, "");
  return path.join(path.dirname(hooksFile), base + SIDECAR_SUFFIX);
}

/** A short, stable id for an Omnodex home on this host. */
export function guardrailsHomeId(omnodexHome: string, host: string = os.hostname()): string {
  let home = path.resolve(omnodexHome);
  // Windows paths compare without regard to case.
  if (/^[A-Za-z]:[\\/]/.test(home)) home = home.toLowerCase();
  return createHash("sha256").update(`${host.toLowerCase()}\n${home}`).digest("hex").slice(0, 16);
}

/** Whether an Omnodex home's enforcement mode is guardrails. Unreadable means no. */
export function homeInGuardrails(omnodexHome: string): boolean {
  try {
    const raw = JSON.parse(readFileSync(path.join(omnodexHome, "omnodex-config.json"), "utf8")) as { enforcement?: unknown };
    return parseEnforcementConfig(raw?.enforcement).mode === "guardrails";
  } catch {
    return false;
  }
}

/** The homes listed for a hooks file. A missing or unreadable sidecar lists none. */
export async function readGuardrailsHomes(hooksFile: string): Promise<string[]> {
  try {
    const parsed = JSON.parse(await fs.readFile(guardrailsSidecarPath(hooksFile), "utf8")) as Partial<Sidecar>;
    return Array.isArray(parsed.homes) ? parsed.homes.filter((h): h is string => typeof h === "string") : [];
  } catch {
    return [];
  }
}

/**
 * List or unlist a home for a hooks file, and return every home now listed.
 * The hook should answer before each call while the result is non-empty.
 * Deletes the sidecar once nothing is listed.
 */
export async function setGuardrailsHome(hooksFile: string, omnodexHome: string, on: boolean): Promise<string[]> {
  const id = guardrailsHomeId(omnodexHome);
  const homes = await readGuardrailsHomes(hooksFile);
  const listed = homes.includes(id);
  if (on === listed) return homes;
  const next = on ? [...homes, id] : homes.filter((h) => h !== id);
  const file = guardrailsSidecarPath(hooksFile);
  if (next.length === 0) {
    await fs.rm(file, { force: true });
    return next;
  }
  // Write then rename, so a crash mid-write never leaves a torn file.
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify({ version: SIDECAR_VERSION, homes: next } satisfies Sidecar, null, 2) + "\n");
  await fs.rename(tmp, file);
  return next;
}

/**
 * Bring a home's entry in line with its mode, and return whether the hooks
 * file should answer before each call: this home is in guardrails, or
 * another home that uses the file is.
 */
export async function syncGuardrailsHome(hooksFile: string, omnodexHome: string): Promise<boolean> {
  return (await setGuardrailsHome(hooksFile, omnodexHome, homeInGuardrails(omnodexHome))).length > 0;
}
