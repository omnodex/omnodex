// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * A spool of request bodies. The receiver writes each accepted body here and
 * answers before mapping it, because the sender gives up after a few seconds
 * and disables a destination that keeps failing. A body leaves the spool once
 * its events are written; one left behind by a crash is mapped again at the
 * next start, which is safe because event ids come from the spans.
 *
 * The spool holds request bodies as received, prompts and tool arguments
 * included, so the folder is private to the user and files are short-lived.
 */

import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

export type SpoolFormat = "protobuf" | "json";

export interface SpoolEntry {
  name: string;
  format: SpoolFormat;
}

const SUFFIX: Record<SpoolFormat, string> = { protobuf: ".pb", json: ".json" };

export class Spool {
  private seq = 0;

  constructor(readonly dir: string) {}

  async init(): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
  }

  /** Store a body. The name sorts in arrival order. */
  async put(body: Uint8Array, format: SpoolFormat): Promise<SpoolEntry> {
    const name = `${Date.now().toString().padStart(15, "0")}-${(this.seq++).toString().padStart(6, "0")}-${randomBytes(3).toString("hex")}${SUFFIX[format]}`;
    const final = path.join(this.dir, name);
    const tmp = `${final}.tmp`;
    await fs.writeFile(tmp, body, { mode: 0o600 });
    await fs.rename(tmp, final);
    return { name, format };
  }

  async read(entry: SpoolEntry): Promise<Buffer> {
    return fs.readFile(path.join(this.dir, entry.name));
  }

  async remove(entry: SpoolEntry): Promise<void> {
    await fs.rm(path.join(this.dir, entry.name), { force: true });
  }

  /** Bodies still waiting, oldest first. Partly written files are ignored. */
  async pending(): Promise<SpoolEntry[]> {
    const names = await fs.readdir(this.dir).catch(() => [] as string[]);
    return names
      .filter((n) => n.endsWith(".pb") || n.endsWith(".json"))
      .sort()
      .map((name) => ({ name, format: name.endsWith(".pb") ? ("protobuf" as const) : ("json" as const) }));
  }
}
