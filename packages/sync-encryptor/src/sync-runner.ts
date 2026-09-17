// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- sync runner
 *
 * Runs one full blob sync against an OMNODEX_HOME: rebuild the SQLite read
 * model from the event log, encrypt it, push it, and persist the KDF salt.
 * Shared by `omnodex sync` and the automatic background sync so both
 * produce identical blobs.
 *
 * Exported as `@omnodex/sync-encryptor/sync-runner`, not from the package
 * index: it loads SQLite and the projector, which hook shims should not pay
 * for on every event.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { EventLog } from "@omnodex/event-log";
import { Projector, SqliteReadModelStore } from "@omnodex/projection";
import { SyncEncryptor } from "./sync-encryptor.js";
import type { SyncResult } from "./sync-encryptor.js";
import { HttpSyncTransport } from "./transport.js";
import { computeMachineId, readMachineLabel } from "./machine-id.js";

export interface SyncReadModelOptions {
  /** OMNODEX_HOME holding event-log/, traces.db and sync-salt.bin. */
  home: string;
  apiUrl: string;
  apiToken: string;
  passphrase: string;
  /** Opaque customer ID from license validation. */
  customerId: string;
  /** Limit the blob to these sessions. Default: all sessions. */
  sessionIds?: string[];
}

/** Rebuild the read model from the event log, then encrypt and push it. */
export async function syncReadModel(opts: SyncReadModelOptions): Promise<SyncResult> {
  const log = new EventLog({ root: path.join(opts.home, "event-log") });
  await log.init();
  const store = new SqliteReadModelStore({ dbPath: path.join(opts.home, "traces.db") });
  await store.init();

  try {
    // Replay is idempotent, so the blob always reflects the full event log.
    await new Projector(store).replay(log.readAll());

    // Reuse a persisted KDF salt across syncs (it is also embedded in each blob).
    const saltPath = path.join(opts.home, "sync-salt.bin");
    let kdfSalt: Uint8Array | undefined;
    try {
      kdfSalt = new Uint8Array(await fs.readFile(saltPath));
    } catch {
      // First sync: SyncEncryptor generates a fresh salt.
    }

    const encryptor = new SyncEncryptor({
      passphrase: opts.passphrase,
      customerId: opts.customerId,
      transport: new HttpSyncTransport({ baseUrl: opts.apiUrl, apiToken: opts.apiToken }),
      store,
      eventLog: log,
      kdfSalt,
      machineId: computeMachineId(),
      machineLabel: await readMachineLabel(opts.home),
    });

    const result = await encryptor.sync(opts.sessionIds);
    await fs.writeFile(saltPath, result.kdfSalt);
    return result;
  } finally {
    await store.close();
    await log.close();
  }
}
