// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Seals: the background pass hashes the events recorded since the previous
 * seal, chains them onto the running head, and signs the result with this
 * machine's key. A seal is one line in event-log/seals.jsonl.
 *
 * Seals live beside the session files, not in them, so replay, sync and both
 * dashboards never see them. The last seal also records, outside the signed
 * body, how far into each session file it read, which is all the state the
 * next seal needs and survives a crash between writing a seal and anything
 * else.
 */

import { generateKeyPairSync, createPrivateKey, sign as cryptoSign, type KeyObject } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { TraceEvent } from "@omnodex/shared";
import { GENESIS_HEAD, canonicalize, eventHash, foldHead, keyIdFor, publicKeyHex } from "./canonical.js";

export const SEAL_FORMAT = "omnodex.seal/1";
export const KEY_FORMAT = "omnodex.seal-key/1";

/** The part of a seal that the signature covers. */
export interface SealBody {
  format: typeof SEAL_FORMAT;
  /** 1 for the first seal on a machine, then up by one. */
  seq: number;
  sealed_at: string;
  /** The head the previous seal ended on; sixty-four zeros for the first. */
  prev_head: string;
  /** The head after folding in every event of this seal, in order. */
  head: string;
  count: number;
  /** The sealed events, in the order they were folded in. */
  event_ids: string[];
  first_recorded_at: string;
  last_recorded_at: string;
  key_id: string;
  alg: "Ed25519";
}

export interface SealRecord extends SealBody {
  /** Hex Ed25519 signature over the canonical form of the body. */
  signature: string;
  /** Machine-local reading state. Not signed and never put in a bundle. */
  local?: { offsets: Record<string, number> };
}

export interface SigningKey {
  key_id: string;
  /** Raw 32-byte public key, hex. */
  public_key: string;
  privateKey: KeyObject;
}

export const sealsFile = (home: string) => path.join(home, "event-log", "seals.jsonl");
export const keyFile = (home: string) => path.join(home, "signing", "seal-key.json");

/** This machine's signing key, created on first use. */
export async function loadOrCreateKey(home: string): Promise<SigningKey> {
  const file = keyFile(home);
  const read = async (): Promise<SigningKey> => {
    const stored = JSON.parse(await fs.readFile(file, "utf8")) as { private_key: string };
    const privateKey = createPrivateKey({ key: Buffer.from(stored.private_key, "base64"), format: "der", type: "pkcs8" });
    const pub = publicKeyHex(privateKey);
    return { key_id: keyIdFor(pub), public_key: pub, privateKey };
  };
  try {
    return await read();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKeyHex(privateKey);
  const stored = {
    format: KEY_FORMAT,
    alg: "Ed25519",
    key_id: keyIdFor(pub),
    public_key: pub,
    private_key: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
  await fs.mkdir(path.dirname(file), { recursive: true });
  try {
    await fs.writeFile(file, JSON.stringify(stored, null, 2), { encoding: "utf8", mode: 0o600, flag: "wx" });
  } catch (err) {
    // Another process created it first; use theirs.
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return read();
    throw err;
  }
  return { key_id: stored.key_id, public_key: pub, privateKey };
}

export function signBody(body: SealBody, key: SigningKey): string {
  return cryptoSign(null, Buffer.from(canonicalize(body), "utf8"), key.privateKey).toString("hex");
}

// ---------------------------------------------------------------------------
// Reading seals
// ---------------------------------------------------------------------------

function parseSeal(line: string): SealRecord | undefined {
  try {
    const parsed = JSON.parse(line) as SealRecord;
    return parsed && parsed.format === SEAL_FORMAT && typeof parsed.seq === "number" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** Every seal on this machine, oldest first. */
export async function readSeals(home: string): Promise<SealRecord[]> {
  const text = await fs.readFile(sealsFile(home), "utf8").catch(() => "");
  return text.split("\n").map((l) => (l.trim() ? parseSeal(l) : undefined)).filter((s): s is SealRecord => s !== undefined);
}

/** The newest seal, read from the end of the file so the cost does not grow with it. */
export async function readLastSeal(home: string): Promise<SealRecord | undefined> {
  let handle: fs.FileHandle;
  try {
    handle = await fs.open(sealsFile(home), "r");
  } catch {
    return undefined;
  }
  try {
    const { size } = await handle.stat();
    let chunk = 64 * 1024;
    for (;;) {
      const start = Math.max(0, size - chunk);
      const buf = Buffer.alloc(size - start);
      await handle.read(buf, 0, buf.length, start);
      const lines = buf.toString("utf8").split("\n");
      // The first piece may be cut off unless the read began at the top.
      const complete = start === 0 ? lines : lines.slice(1);
      for (let i = complete.length - 1; i >= 0; i--) {
        if (!complete[i].trim()) continue;
        const seal = parseSeal(complete[i]);
        if (seal) return seal;
      }
      if (start === 0) return undefined;
      chunk *= 4;
    }
  } finally {
    await handle.close();
  }
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

export interface SealOptions {
  home: string;
  /** Every Omnodex root whose event log is sealed. The seals are kept in `home`. */
  roots: string[];
  now?: () => number;
}

export type SealResult =
  | { sealed: true; seq: number; count: number; head: string }
  | { sealed: false; reason: "nothing-new" | "busy" };

async function sessionFiles(roots: readonly string[]): Promise<string[]> {
  const files: string[] = [];
  for (const root of roots) {
    const dir = path.join(root, "event-log", "sessions");
    for (const name of (await fs.readdir(dir).catch(() => [] as string[])).sort()) {
      if (name.endsWith(".jsonl")) files.push(path.join(dir, name));
    }
  }
  return files;
}

interface Found {
  event: TraceEvent;
  file: string;
  pos: number;
  at: number;
}

const LOCK_STALE_MS = 120_000;

async function acquire(home: string, now: number): Promise<(() => Promise<void>) | undefined> {
  const lock = path.join(home, "seal.lock");
  await fs.mkdir(home, { recursive: true });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const handle = await fs.open(lock, "wx");
      await handle.close();
      return () => fs.rm(lock, { force: true });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const stat = await fs.stat(lock).catch(() => undefined);
      if (stat && now - stat.mtimeMs < LOCK_STALE_MS) return undefined;
      await fs.rm(lock, { force: true });
    }
  }
  return undefined;
}

/**
 * Seal everything recorded since the last seal. Safe to call from several
 * processes: one seals, the others return `busy`.
 */
export async function sealPending(opts: SealOptions): Promise<SealResult> {
  const now = opts.now?.() ?? Date.now();
  const release = await acquire(opts.home, now);
  if (!release) return { sealed: false, reason: "busy" };
  try {
    const last = await readLastSeal(opts.home);
    const offsets: Record<string, number> = { ...(last?.local?.offsets ?? {}) };
    const found: Found[] = [];
    for (const file of await sessionFiles(opts.roots)) {
      const stat = await fs.stat(file).catch(() => undefined);
      if (!stat) continue;
      let from = offsets[file] ?? 0;
      if (stat.size < from) from = 0; // replaced or emptied: read it again
      if (stat.size === from) {
        offsets[file] = from;
        continue;
      }
      const handle = await fs.open(file, "r");
      try {
        const buf = Buffer.alloc(stat.size - from);
        const { bytesRead } = await handle.read(buf, 0, buf.length, from);
        const whole = buf.subarray(0, bytesRead);
        const cut = whole.lastIndexOf(0x0a);
        if (cut === -1) continue; // a line still being written
        let lineStart = 0;
        for (let i = 0; i <= cut; i++) {
          if (whole[i] !== 0x0a) continue;
          const text = whole.subarray(lineStart, i).toString("utf8");
          if (text.trim()) {
            try {
              const event = JSON.parse(text) as TraceEvent;
              if (event && typeof event.event_id === "string" && typeof event.event_type === "string") {
                const at = Date.parse(event.recorded_at);
                found.push({ event, file, pos: from + lineStart, at: Number.isNaN(at) ? 0 : at });
              }
            } catch {
              // A damaged line cannot be sealed; the offset still moves past it.
            }
          }
          lineStart = i + 1;
        }
        offsets[file] = from + cut + 1;
      } finally {
        await handle.close();
      }
    }
    if (found.length === 0) return { sealed: false, reason: "nothing-new" };

    found.sort((a, b) => a.at - b.at || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.pos - b.pos);
    const key = await loadOrCreateKey(opts.home);
    const prevHead = last?.head ?? GENESIS_HEAD;
    let head = prevHead;
    for (const f of found) head = foldHead(head, eventHash(f.event));
    const body: SealBody = {
      format: SEAL_FORMAT,
      seq: (last?.seq ?? 0) + 1,
      sealed_at: new Date(now).toISOString(),
      prev_head: prevHead,
      head,
      count: found.length,
      event_ids: found.map((f) => f.event.event_id),
      first_recorded_at: found[0].event.recorded_at,
      last_recorded_at: found[found.length - 1].event.recorded_at,
      key_id: key.key_id,
      alg: "Ed25519",
    };
    const record: SealRecord = { ...body, signature: signBody(body, key), local: { offsets } };
    await fs.mkdir(path.dirname(sealsFile(opts.home)), { recursive: true });
    await fs.appendFile(sealsFile(opts.home), JSON.stringify(record) + "\n", "utf8");
    return { sealed: true, seq: body.seq, count: body.count, head };
  } finally {
    await release();
  }
}
