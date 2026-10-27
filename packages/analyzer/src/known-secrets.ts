// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Secrets this machine has seen in calls, with their context.
 *
 * A key sent with no header or `token=` around it looks like any other
 * string. If the same value was earlier seen as a secret, it can still be
 * recognized. This keeps what was seen in $OMNODEX_HOME/known-secrets.json:
 *
 *   { "version": 1, "secrets": { "<hmac>": { "type": "anthropic",
 *       "first_seen": "...", "last_seen": "...", "hosts": ["api.example.com"] } } }
 *
 * The value is never stored: each entry is keyed by an HMAC-SHA256 of it,
 * made with a random 32-byte key in $OMNODEX_HOME/known-secrets.key (mode
 * 0600, created on first use). With parameter redaction off the raw values
 * already sit in the local event log, so the key mainly stops this file
 * being a list of which strings are secrets. Neither file leaves the machine.
 *
 * An entry expires 30 days after it was last seen (each sighting resets
 * that), and the file keeps at most 5,000 entries, dropping the least
 * recently seen first. A sighting that only refreshes an entry is written at
 * most once a day.
 *
 * `hosts` are the external hosts the calls that showed the secret reached:
 * where a secret has already been sent with its context is not news. Only
 * values of 16 or more key, token or base64 characters are remembered, the
 * same shape the matching side looks for.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

export const KNOWN_SECRETS_FILE = "known-secrets.json";
export const KNOWN_SECRETS_KEY_FILE = "known-secrets.key";

/** How long an entry lives after it was last seen. */
export const SECRET_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
/** The most entries kept. */
export const SECRET_CAP = 5000;
const REFRESH_MS = 24 * 60 * 60 * 1000;
const MAX_HOSTS = 10;
const MAX_CANDIDATES = 500;
const MAX_VALUE = 512;

const REMEMBERABLE = /^[A-Za-z0-9_\-.+/]{16,}={0,2}$/;

export interface SecretRecord {
  type: string;
  first_seen: string;
  last_seen: string;
  hosts?: string[];
}

interface SecretsFile {
  version: 1;
  secrets: Record<string, SecretRecord>;
}

/** A remembered secret, as recalled for a value. */
export interface RememberedSecret {
  type: string;
  firstSeen: string;
  hosts: string[];
}

export interface SecretStore {
  /** The entry for a value, unless it expired before `at`. */
  recall(value: string, at: string): RememberedSecret | undefined;
  /** Record secrets seen in a call that reached `hosts`. */
  note(sightings: readonly { type: string; value: string }[], hosts: readonly string[], at: string): void;
}

/**
 * The strings in a call's parameters that could be a bare secret: runs of
 * 16 or more key, token or base64 characters. Escaped line breaks in the
 * serialized parameters count as separators, so a key after one is whole.
 */
export function secretCandidates(parameters: unknown): string[] {
  let text: string;
  try {
    text = JSON.stringify(parameters) ?? "";
  } catch {
    return [];
  }
  const found = new Set<string>();
  for (const m of text.replace(/\\[nrt]/g, " ").matchAll(/[A-Za-z0-9_\-.+/]{16,}={0,2}/g)) {
    if (m[0].length <= MAX_VALUE) found.add(m[0]);
    if (found.size >= MAX_CANDIDATES) break;
  }
  return [...found];
}

function loadKey(keyFile: string): Buffer {
  const read = (): Buffer | null => {
    try {
      const hex = fs.readFileSync(keyFile, "utf8").trim();
      return /^[0-9a-f]{64}$/.test(hex) ? Buffer.from(hex, "hex") : null;
    } catch {
      return null;
    }
  };
  const existing = read();
  if (existing) return existing;
  const key = crypto.randomBytes(32);
  try {
    fs.mkdirSync(path.dirname(keyFile), { recursive: true });
    try {
      fs.writeFileSync(keyFile, key.toString("hex") + "\n", { mode: 0o600, flag: "wx" });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      // Another process created it first, or it is unreadable and invalid.
      const theirs = read();
      if (theirs) return theirs;
      fs.writeFileSync(keyFile, key.toString("hex") + "\n", { mode: 0o600 });
    }
  } catch {
    // Unwritable home: a key for this process only.
  }
  return key;
}

function readSecrets(file: string): SecretsFile | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<SecretsFile>;
    if (parsed?.version === 1 && parsed.secrets && typeof parsed.secrets === "object") {
      return { version: 1, secrets: parsed.secrets };
    }
  } catch {
    // Missing or unreadable.
  }
  return null;
}

function expired(record: SecretRecord, at: string): boolean {
  return Date.parse(at) - Date.parse(record.last_seen) > SECRET_WINDOW_MS;
}

/** Drop expired entries, then the least recently seen beyond the cap. */
function prune(records: Record<string, SecretRecord>, at: string): void {
  for (const [hash, record] of Object.entries(records)) {
    if (expired(record, at)) delete records[hash];
  }
  const hashes = Object.keys(records);
  if (hashes.length <= SECRET_CAP) return;
  hashes.sort((a, b) => records[a]!.last_seen.localeCompare(records[b]!.last_seen));
  for (const hash of hashes.slice(0, hashes.length - SECRET_CAP)) delete records[hash];
}

function unionHosts(a: readonly string[] | undefined, b: readonly string[] | undefined): string[] {
  return [...new Set([...(a ?? []), ...(b ?? [])])].slice(0, MAX_HOSTS);
}

function writeSecrets(file: string, changed: Record<string, SecretRecord>, at: string): void {
  // Merge with whatever another process wrote since we loaded.
  const merged: Record<string, SecretRecord> = { ...(readSecrets(file)?.secrets ?? {}) };
  for (const [hash, record] of Object.entries(changed)) {
    const current = merged[hash];
    merged[hash] = !current
      ? record
      : {
          type: current.first_seen <= record.first_seen ? current.type : record.type,
          first_seen: current.first_seen < record.first_seen ? current.first_seen : record.first_seen,
          last_seen: current.last_seen > record.last_seen ? current.last_seen : record.last_seen,
          hosts: unionHosts(current.hosts, record.hosts),
        };
  }
  prune(merged, at);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ version: 1, secrets: merged }, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function makeStore(
  key: Buffer,
  records: Record<string, SecretRecord>,
  persist: (changed: Record<string, SecretRecord>, at: string) => void,
): SecretStore {
  const hash = (value: string): string => crypto.createHmac("sha256", key).update(value).digest("hex");
  return {
    recall(value, at): RememberedSecret | undefined {
      if (value.length > MAX_VALUE) return undefined;
      const record = records[hash(value)];
      if (!record || expired(record, at)) return undefined;
      return { type: record.type, firstSeen: record.first_seen, hosts: record.hosts ?? [] };
    },

    note(sightings, reached, at): void {
      const hosts = reached.map((h) => h.toLowerCase());
      const changed: Record<string, SecretRecord> = {};
      for (const { type, value } of sightings) {
        if (value.length > MAX_VALUE || !REMEMBERABLE.test(value)) continue;
        const h = hash(value);
        const current = records[h] && !expired(records[h]!, at) ? records[h]! : undefined;
        if (!current) {
          records[h] = changed[h] = { type, first_seen: at, last_seen: at, hosts: unionHosts(hosts, []) };
          continue;
        }
        const newHosts = hosts.filter((x) => !(current.hosts ?? []).includes(x));
        const older = at < current.first_seen;
        const stale = Date.parse(at) - Date.parse(current.last_seen) > REFRESH_MS;
        if (!newHosts.length && !older && !stale) continue;
        if (older) current.first_seen = at;
        if (at > current.last_seen) current.last_seen = at;
        current.hosts = unionHosts(current.hosts, hosts);
        changed[h] = current;
      }
      if (Object.keys(changed).length === 0) return;
      prune(records, at);
      try {
        persist(changed, at);
      } catch {
        // Keep the in-memory answer; the next writer will persist it.
      }
    },
  };
}

/**
 * The secret store for an installation. A file that does not exist yet is
 * seeded from `seed` (the secrets in the event logs) and written.
 */
export function openSecretStore(
  home: string,
  seed: (store: SecretStore) => void,
): SecretStore {
  const file = path.join(home, KNOWN_SECRETS_FILE);
  const key = loadKey(path.join(home, KNOWN_SECRETS_KEY_FILE));
  let records = readSecrets(file)?.secrets;
  if (records) return makeStore(key, records, (changed, at) => writeSecrets(file, changed, at));
  records = {};
  seed(makeStore(key, records, () => undefined));
  try {
    writeSecrets(file, records, new Date().toISOString());
  } catch {
    // Unwritable home: keep working in memory.
  }
  return makeStore(key, records, (changed, at) => writeSecrets(file, changed, at));
}

/** A secret store in memory only, for tests and hosts with nowhere to persist. */
export function memorySecretStore(): SecretStore {
  return makeStore(crypto.randomBytes(32), {}, () => undefined);
}
