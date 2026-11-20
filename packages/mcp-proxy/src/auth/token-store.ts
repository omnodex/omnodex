// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- auth/token-store
 *
 * Where OAuth credentials for remote upstreams are kept between runs. The
 * proxy and the CLI only see the TokenStore interface; the default
 * implementation is a plain JSON file under the Omnodex home directory that
 * only the current user can read, like the stream secret and API token.
 *
 * Records are keyed by upstream name and remember the upstream URL they were
 * issued for, so changing an upstream's URL never sends its old tokens to a
 * different server.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

/** Tokens as stored: the token response plus when it was received. */
export interface StoredTokens {
  access_token: string;
  token_type: string;
  refresh_token?: string;
  scope?: string;
  expires_in?: number;
  /** Authorization server that issued them; kept so they are not replayed elsewhere. */
  issuer?: string;
  /** Epoch milliseconds when this token response was received. */
  obtained_at: number;
}

/** Everything remembered about one upstream's sign-in. */
export interface UpstreamCredentials {
  /** The upstream URL these were issued for. */
  url: string;
  tokens?: StoredTokens;
  /** Registered client (client id, and secret when the server issued one). */
  client_information?: Record<string, unknown>;
  /** Discovery results, so a restart skips the metadata round trips. */
  discovery_state?: Record<string, unknown>;
}

export interface TokenStore {
  /** The record for an upstream, or undefined when none exists or its URL differs. */
  get(name: string, url: string): Promise<UpstreamCredentials | undefined>;
  /** Replaces the record for an upstream. */
  put(name: string, credentials: UpstreamCredentials): Promise<void>;
  /** Removes the record. Returns true when one existed. */
  delete(name: string): Promise<boolean>;
  /** Every stored record, by upstream name. */
  list(): Promise<Record<string, UpstreamCredentials>>;
}

export const TOKEN_FILE_NAME = "upstream-tokens.json";

export function defaultTokenFile(home?: string): string {
  const root = home ?? process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  return path.join(root, TOKEN_FILE_NAME);
}

interface TokenFile {
  version: 1;
  upstreams: Record<string, UpstreamCredentials>;
}

/** A JSON file readable only by the user (mode 0600; no-op on Windows). */
export class FileTokenStore implements TokenStore {
  private readonly file: string;
  /** Serializes this process's writes; each one re-reads the file first. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(file: string = defaultTokenFile()) {
    this.file = file;
  }

  async get(name: string, url: string): Promise<UpstreamCredentials | undefined> {
    const record = (await this.read()).upstreams[name];
    return record && record.url === url ? record : undefined;
  }

  async put(name: string, credentials: UpstreamCredentials): Promise<void> {
    await this.update((data) => {
      data.upstreams[name] = credentials;
    });
  }

  async delete(name: string): Promise<boolean> {
    let existed = false;
    await this.update((data) => {
      existed = name in data.upstreams;
      delete data.upstreams[name];
    });
    return existed;
  }

  async list(): Promise<Record<string, UpstreamCredentials>> {
    return (await this.read()).upstreams;
  }

  private async read(): Promise<TokenFile> {
    let raw: string;
    try {
      raw = await fs.readFile(this.file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return { version: 1, upstreams: {} };
      throw err;
    }
    try {
      const parsed = JSON.parse(raw) as Partial<TokenFile>;
      if (parsed && typeof parsed === "object" && parsed.upstreams && typeof parsed.upstreams === "object") {
        return { version: 1, upstreams: parsed.upstreams };
      }
    } catch {
      // Falls through: an unreadable file holds no usable tokens.
    }
    return { version: 1, upstreams: {} };
  }

  private update(change: (data: TokenFile) => void): Promise<void> {
    const run = this.queue.then(async () => {
      const data = await this.read();
      change(data);
      await fs.mkdir(path.dirname(this.file), { recursive: true });
      // Written beside the target and renamed, so a crash never leaves half a file.
      const temp = `${this.file}.${randomBytes(4).toString("hex")}.tmp`;
      await fs.writeFile(temp, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
      await fs.chmod(temp, 0o600).catch(() => undefined);
      await fs.rename(temp, this.file);
    });
    this.queue = run.catch(() => undefined);
    return run;
  }
}

/** A store that keeps everything in memory, for tests and for callers that must not touch disk. */
export class MemoryTokenStore implements TokenStore {
  private readonly records = new Map<string, UpstreamCredentials>();

  async get(name: string, url: string): Promise<UpstreamCredentials | undefined> {
    const record = this.records.get(name);
    return record && record.url === url ? structuredClone(record) : undefined;
  }
  async put(name: string, credentials: UpstreamCredentials): Promise<void> {
    this.records.set(name, structuredClone(credentials));
  }
  async delete(name: string): Promise<boolean> {
    return this.records.delete(name);
  }
  async list(): Promise<Record<string, UpstreamCredentials>> {
    return Object.fromEntries([...this.records].map(([k, v]) => [k, structuredClone(v)]));
  }
}
