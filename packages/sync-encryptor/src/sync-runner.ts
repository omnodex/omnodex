// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- sync runner
 *
 * Runs one sync against an OMNODEX_HOME: rebuild the SQLite read model from
 * the event log, encrypt it, push it, and persist the KDF salt. Shared by
 * `omnodex sync` and the automatic background sync so both produce the same
 * result.
 *
 * By default the read model goes up as segments of whole sessions, and only
 * segments that changed are uploaded (segment-sync.ts). A cloud without the
 * segment routes gets the single blob of every session instead, as does a
 * partial sync of chosen sessions. OMNODEX_SYNC_SEGMENTS=0 forces the blob.
 *
 * Exported as `@omnodex/sync-encryptor/sync-runner`, not from the package
 * index: it loads SQLite and the projector, which hook shims should not pay
 * for on every event.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { EventLog } from "@omnodex/event-log";
import { Projector, SqliteReadModelStore, runCorrelation } from "@omnodex/projection";
import { SyncEncryptor } from "./sync-encryptor.js";
import type { SyncResult } from "./sync-encryptor.js";
import { HttpSyncTransport } from "./transport.js";
import { computeMachineId, readMachineLabel } from "./machine-id.js";
import { syncSegments } from "./segment-sync.js";
import { HttpSegmentTransport, SegmentsUnsupportedError } from "./segment-transport.js";

export interface SyncReadModelOptions {
  /** OMNODEX_HOME holding event-log/, traces.db and sync-salt.bin. */
  home: string;
  apiUrl: string;
  apiToken: string;
  passphrase: string;
  /** Opaque customer ID from license validation. */
  customerId: string;
  /** Limit the blob to these sessions (a single-blob push). Default: all sessions. */
  sessionIds?: string[];
}

/** What a segmented sync adds to a SyncResult. */
export interface SegmentSyncSummary {
  /** Segments the cloud holds for this machine, and how many this sync uploaded. */
  count: number;
  uploaded: number;
  /** Envelope bytes of all of them. */
  totalBytes: number;
}

export type SyncRunResult = SyncResult & { segments?: SegmentSyncSummary };

/** Rebuild the read model from the event log, then encrypt and push it. */
export async function syncReadModel(opts: SyncReadModelOptions): Promise<SyncRunResult> {
  const log = new EventLog({ root: path.join(opts.home, "event-log") });
  await log.init();
  const store = new SqliteReadModelStore({ dbPath: path.join(opts.home, "traces.db") });
  await store.init();

  try {
    // Replay is idempotent, so the blob always reflects the full event log.
    await new Projector(store).replay(log.readAll());
    // A replay leaves a routed call's hook and proxy rows unpaired; pairing
    // is a pass over the whole model. Without it the hosted dashboard counts
    // every routed call, and any finding both hosts raised on it, twice.
    await runCorrelation(store);

    // Reuse a persisted KDF salt across syncs (it is also embedded in each blob).
    const saltPath = path.join(opts.home, "sync-salt.bin");
    let kdfSalt: Uint8Array | undefined;
    try {
      kdfSalt = new Uint8Array(await fs.readFile(saltPath));
    } catch {
      // First sync: SyncEncryptor generates a fresh salt.
    }

    const machineId = computeMachineId();
    const machineLabel = await readMachineLabel(opts.home);
    const encryptor = new SyncEncryptor({
      passphrase: opts.passphrase,
      customerId: opts.customerId,
      transport: new HttpSyncTransport({ baseUrl: opts.apiUrl, apiToken: opts.apiToken }),
      store,
      eventLog: log,
      kdfSalt,
      machineId,
      machineLabel,
    });
    // The salt is persisted before any upload, so every segment and blob
    // this machine writes shares it and the dashboard derives one key.
    const salt = encryptor.getKdfSalt();
    await fs.writeFile(saltPath, salt);

    if (!opts.sessionIds && process.env.OMNODEX_SYNC_SEGMENTS !== "0") {
      try {
        const r = await syncSegments({
          store,
          transport: new HttpSegmentTransport({ baseUrl: opts.apiUrl, apiToken: opts.apiToken }),
          passphrase: opts.passphrase,
          kdfSalt: salt,
          customerId: opts.customerId,
          apiUrl: opts.apiUrl,
          machineId,
          machineLabel,
          home: opts.home,
          eventLog: log,
        });
        return {
          blobId: r.commitId,
          ciphertextHash: "",
          sessionsIncluded: r.sessionsIncluded,
          payloadBytes: r.payloadBytes,
          // What the cloud's size limit applies to: the largest segment.
          blobBytes: r.largestBytes,
          kdfSalt: salt,
          machineId,
          segments: { count: r.segments, uploaded: r.uploaded, totalBytes: r.totalBytes },
        };
      } catch (err) {
        if (!(err instanceof SegmentsUnsupportedError)) throw err;
        // An older cloud: fall through to the single blob.
      }
    }

    const result = await encryptor.sync(opts.sessionIds);
    return result;
  } finally {
    await store.close();
    await log.close();
  }
}
