// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- machine identity
 *
 * Computes a stable machine identifier from the hostname. The ID is the
 * first 16 hex characters of SHA-256(hostname), giving a compact but
 * collision-resistant tag. Deterministic: same hostname always yields the
 * same ID.
 *
 * The optional machine label is a human-readable name (e.g. "Work Laptop")
 * stored in ~/.omnodex/config.json under machine.label. When absent, the
 * dashboard shows the raw hostname.
 */

import { createHash } from "node:crypto";
import * as os from "node:os";

/**
 * Compute a stable machine identifier from the OS hostname.
 * Returns the first 16 hex characters of SHA-256(hostname).
 */
export function computeMachineId(): string {
  const hostname = os.hostname();
  return createHash("sha256").update(hostname).digest("hex").slice(0, 16);
}

/**
 * Read the machine label from the Omnodex config file, if set.
 * Returns undefined if not configured.
 */
export async function readMachineLabel(omnodexHome?: string): Promise<string | undefined> {
  const path = await import("node:path");
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
