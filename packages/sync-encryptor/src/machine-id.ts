// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- machine identity
 *
 * The machine ID is 16 random hex characters, generated once and kept in
 * machine-id.json under OMNODEX_HOME. It keeps each machine's data apart
 * in the hosted service and says nothing about the machine.
 *
 * Older clients derived the ID from a hash of the hostname, which anyone
 * with a list of likely hostnames could reverse. A home that has synced
 * before keeps that old ID as `previous` until one sync has told the
 * service to move the old ID's data to the new one (pendingMachineIdRemap,
 * acknowledgeMachineIdRemap).
 *
 * The optional machine label is a human-readable name (e.g. "Work Laptop")
 * stored in config.json under machine.label. It leaves the machine only
 * encrypted (machine-label.ts).
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const ID_FILE = "machine-id.json";
const ID_RE = /^[0-9a-f]{16}$/;

interface StoredMachineId {
  id: string;
  /** The hostname-derived ID this home synced under before, until remapped. */
  previous?: string;
}

/** IDs this process generated but could not store, so they stay stable. */
const unstored = new Map<string, StoredMachineId>();

function defaultHome(): string {
  return process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
}

/** The ID older clients used: the first 16 hex of SHA-256(hostname). */
export function legacyMachineId(): string {
  return createHash("sha256").update(os.hostname()).digest("hex").slice(0, 16);
}

function readStored(file: string): StoredMachineId | undefined {
  try {
    const raw = JSON.parse(readFileSync(file, "utf8")) as Partial<StoredMachineId>;
    if (typeof raw.id !== "string" || !ID_RE.test(raw.id)) return undefined;
    const previous = typeof raw.previous === "string" && ID_RE.test(raw.previous) ? raw.previous : undefined;
    return previous ? { id: raw.id, previous } : { id: raw.id };
  } catch {
    return undefined;
  }
}

function loadMachineId(home: string): StoredMachineId {
  const file = path.join(home, ID_FILE);
  const stored = readStored(file);
  if (stored) return stored;
  const cached = unstored.get(file);
  if (cached) return cached;

  // A sync salt means this home has uploaded under the hostname-derived ID.
  const fresh: StoredMachineId = { id: randomBytes(8).toString("hex") };
  if (existsSync(path.join(home, "sync-salt.bin"))) fresh.previous = legacyMachineId();
  try {
    mkdirSync(home, { recursive: true });
    writeFileSync(file, JSON.stringify(fresh, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  } catch (err) {
    // Another process wrote it first: use theirs.
    if ((err as NodeJS.ErrnoException).code === "EEXIST") {
      const theirs = readStored(file);
      if (theirs) return theirs;
    }
    unstored.set(file, fresh);
  }
  return fresh;
}

/** This machine's ID, generated and stored on first use. */
export function computeMachineId(omnodexHome: string = defaultHome()): string {
  return loadMachineId(omnodexHome).id;
}

/** The old ID whose data the service should move to this one, if not done yet. */
export function pendingMachineIdRemap(omnodexHome: string = defaultHome()): string | undefined {
  return loadMachineId(omnodexHome).previous;
}

/** Records that the service has moved the old ID's data; stops sending it. */
export function acknowledgeMachineIdRemap(omnodexHome: string = defaultHome()): void {
  const file = path.join(omnodexHome, ID_FILE);
  const stored = readStored(file);
  if (!stored?.previous) return;
  try {
    writeFileSync(file, JSON.stringify({ id: stored.id }, null, 2) + "\n", { mode: 0o600 });
  } catch {
    // Not fatal: the remap is idempotent, so the next sync sends it again.
  }
}

export interface RemapOptions {
  home: string;
  apiUrl: string;
  apiToken: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

/**
 * If this home synced under the hostname-derived ID, asks the service once
 * to move that ID's data to the random one, so the machine keeps its history
 * and shows once. Never throws: a failure, or a service without the route,
 * leaves the remap pending for the next sync.
 */
export async function remapMachineId(opts: RemapOptions): Promise<"remapped" | "none" | "skipped"> {
  const previous = pendingMachineIdRemap(opts.home);
  if (!previous) return "none";
  try {
    const res = await (opts.fetchFn ?? fetch)(opts.apiUrl.replace(/\/$/, "") + "/api/v1/sync/machine-remap", {
      method: "POST",
      headers: { Authorization: `Bearer ${opts.apiToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: previous, to: computeMachineId(opts.home) }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
    if (!res.ok) return "skipped";
  } catch {
    return "skipped";
  }
  acknowledgeMachineIdRemap(opts.home);
  return "remapped";
}

/**
 * Read the machine label from the Omnodex config file, if set.
 * Returns undefined if not configured.
 */
export async function readMachineLabel(omnodexHome?: string): Promise<string | undefined> {
  const fs = await import("node:fs/promises");

  const home = omnodexHome ?? path.join(os.homedir(), ".omnodex");
  const configPath = path.join(home, "config.json");

  try {
    const raw = await fs.readFile(configPath, "utf8");
    const config = JSON.parse(raw) as Record<string, unknown>;
    if (config.machine && typeof config.machine === "object") {
      const machine = config.machine as Record<string, unknown>;
      if (typeof machine.label === "string" && machine.label.trim()) {
        return machine.label.trim();
      }
    }
  } catch {
    // Config file missing or malformed -- no label
  }
  return undefined;
}
