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
import { EventLog, capturePauseRows, localOnlySeen, markLocalOnlySeen } from "@omnodex/event-log";
import { CAPTURE_CONTROL_SESSION_ID, type TraceEvent } from "@omnodex/shared";
import { Projector, SqliteReadModelStore, runCorrelation } from "@omnodex/projection";
import { SyncEncryptor } from "./sync-encryptor.js";
import type { SyncResult } from "./sync-encryptor.js";
import { HttpSyncTransport } from "./transport.js";
import { computeMachineId, readMachineLabel } from "./machine-id.js";
import { syncSegments } from "./segment-sync.js";
import { HttpSegmentTransport, SegmentsUnsupportedError } from "./segment-transport.js";
import { TokenRotatedError, collectRotatedToken, ensureSecretVerifier } from "./stream-credentials.js";

/** The read model a home's syncs use once it has recorded anything local-only. */
export const SYNC_READ_MODEL_FILE = "sync-traces.db";

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

export type SyncRunResult = SyncResult & {
  segments?: SegmentSyncSummary;
  /** Set when the owner had rotated the token and this sync collected the new one (saved to stream-config.json). */
  collectedToken?: string;
};

/**
 * The events a sync uploads, in log order: none recorded local-only, and no
 * finding about a call that was. Sets `seen.localOnly` when it skipped one.
 */
export async function* uploadableEvents(
  events: AsyncIterable<TraceEvent>,
  seen: { localOnly: boolean } = { localOnly: false },
): AsyncGenerator<TraceEvent> {
  const localCalls = new Set<string>();
  for await (const e of events) {
    if (e.local_only) {
      seen.localOnly = true;
      if (e.event_type === "tool.invoked" || e.event_type === "tool.completed") localCalls.add(e.tool_call_id);
      continue;
    }
    if (
      e.event_type === "risk.detected" &&
      (localCalls.has(e.related_event_id) || e.related_event_ids?.some((id) => localCalls.has(id)))
    ) {
      seen.localOnly = true;
      continue;
    }
    yield e;
  }
}

/**
 * The read model a sync uploads from. Normally traces.db, which the local
 * dashboard shares. Once this home has recorded anything local-only, the
 * local dashboard's rows include it, so the sync builds its own model
 * (sync-traces.db) from the uploadable events alone.
 */
async function openSyncStore(home: string, dedicated: boolean): Promise<SqliteReadModelStore> {
  const store = new SqliteReadModelStore({ dbPath: path.join(home, dedicated ? SYNC_READ_MODEL_FILE : "traces.db") });
  await store.init();
  return store;
}

/**
 * Rebuild the read model from the event log, then encrypt and push it.
 *
 * First checks this machine's stream secret against the stream's verifier
 * (registering it the first time), and stops with SecretMismatchError if it
 * is not the stream's. If the owner rotated the token, collects the new one
 * by proving the secret, saves it, and syncs with it.
 */
export async function syncReadModel(opts: SyncReadModelOptions): Promise<SyncRunResult> {
  const credentials = { home: opts.home, apiUrl: opts.apiUrl, apiToken: opts.apiToken, passphrase: opts.passphrase };
  try {
    await ensureSecretVerifier(credentials);
    return await syncOnce(opts);
  } catch (err) {
    if (!(err instanceof TokenRotatedError)) throw err;
  }
  const apiToken = await collectRotatedToken(credentials);
  await ensureSecretVerifier({ ...credentials, apiToken });
  return { ...(await syncOnce({ ...opts, apiToken })), collectedToken: apiToken };
}

async function syncOnce(opts: SyncReadModelOptions): Promise<SyncRunResult> {
  const log = new EventLog({ root: path.join(opts.home, "event-log") });
  await log.init();
  const dedicated = await localOnlySeen(opts.home);
  let store = await openSyncStore(opts.home, dedicated);

  try {
    // Replay is idempotent, so the blob always reflects the full event log.
    const seen = { localOnly: false };
    await new Projector(store).replay(uploadableEvents(log.readAll(), seen));
    if (seen.localOnly && !dedicated) {
      // First local-only event: the shared model may already hold rows the
      // local dashboard built from it. Switch this home to its own model.
      await markLocalOnlySeen(opts.home);
      await store.close();
      store = await openSyncStore(opts.home, true);
      await new Projector(store).replay(uploadableEvents(log.readAll()));
    }
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
    // Pauses go up with every sync, so the dashboard shows them later even
    // if it was not open (live push is its only other source).
    const pauses = capturePauseRows(await log.readSession(CAPTURE_CONTROL_SESSION_ID));
    const encryptor = new SyncEncryptor({
      passphrase: opts.passphrase,
      customerId: opts.customerId,
      transport: new HttpSyncTransport({ baseUrl: opts.apiUrl, apiToken: opts.apiToken }),
      store,
      eventLog: log,
      kdfSalt,
      machineId,
      machineLabel,
      pauses,
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
          pauses,
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
