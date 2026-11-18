// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The receiver's bearer token: what a telemetry destination sends in its
 * `authorization` header. It only grants "post spans to this receiver", and is
 * not any other Omnodex credential.
 */

import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

export const TOKEN_ENV = "OMNODEX_OTEL_TOKEN";
const TOKEN_FILE = "otel-receiver.json";

interface TokenFile {
  token: string;
  created_at: string;
}

function tokenPath(home: string): string {
  return path.join(home, TOKEN_FILE);
}

/** The stored token, or undefined when none was created or the file is unreadable. */
export async function readStoredToken(home: string): Promise<string | undefined> {
  try {
    const parsed = JSON.parse(await fs.readFile(tokenPath(home), "utf8")) as Partial<TokenFile>;
    return typeof parsed.token === "string" && parsed.token ? parsed.token : undefined;
  } catch {
    return undefined;
  }
}

/** The token to enforce: the environment's, else the stored one, else none. */
export async function resolveToken(home: string, env: NodeJS.ProcessEnv = process.env): Promise<string | undefined> {
  const fromEnv = env[TOKEN_ENV];
  if (fromEnv) return fromEnv;
  return readStoredToken(home);
}

/**
 * The stored token, creating it on first use. `rotate` replaces it, which
 * stops the old one working the next time the receiver starts.
 */
export async function ensureToken(home: string, options: { rotate?: boolean } = {}): Promise<{ token: string; created: boolean }> {
  if (!options.rotate) {
    const existing = await readStoredToken(home);
    if (existing) return { token: existing, created: false };
  }
  const token = `omxotel_${randomBytes(32).toString("base64url")}`;
  const body: TokenFile = { token, created_at: new Date().toISOString() };
  await fs.mkdir(home, { recursive: true });
  const file = tokenPath(home);
  // Written to a temporary name first so a crash never leaves half a token.
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(body, null, 2) + "\n", { mode: 0o600 });
  await fs.rename(tmp, file);
  await fs.chmod(file, 0o600).catch(() => undefined);
  return { token, created: true };
}
