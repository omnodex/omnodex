// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- segmented sync
 *
 * Splits the synced read model into segments of whole sessions and uploads
 * only the segments whose content changed, instead of rebuilding and
 * re-uploading one blob of every session on every sync.
 *
 *   1. Serialize each session (its row and child rows) and hash it.
 *   2. Compare with the local manifest: sessions are new, changed,
 *      unchanged, or gone (no longer local, or past the retention window).
 *   3. New and changed sessions go to the open segment; a changed session
 *      leaves its sealed segment, so a long-running session or a late
 *      finding rewrites the small open segment, not an old one.
 *   4. The open segment is sealed once it passes SEGMENT_SEAL_BYTES of JSON.
 *   5. Each segment that gained, lost or changed a session is encrypted and
 *      uploaded whole under a new random id.
 *   6. The machine's full segment list is committed; the cloud retires the
 *      segments it leaves out, so a session gone locally leaves the cloud.
 *   7. The manifest is saved only after the commit succeeds.
 *
 * A missing, unreadable or foreign manifest (another machine, another
 * stream) means a full upload once, which replaces what the cloud held.
 * So does a commit the cloud refuses because a listed segment is gone.
 *
 * Files under OMNODEX_HOME:
 *   - sync-segments.json  which segment holds which session, and each
 *                         session's hash. No content.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { gzipSync } from "node:zlib";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { ReadModelStore, SessionRow } from "@omnodex/projection";
import type { EventLog } from "@omnodex/event-log";
import type { SyncPushedEvent } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";
import { deriveKey, encrypt, sha256Hex } from "./crypto.js";
import { encodeEnvelope, ENVELOPE_VERSION_GZIP } from "./envelope.js";
import { serializeReadModel, SYNC_PAYLOAD_VERSION, type SyncPayload } from "./serializer.js";
import { MissingSegmentsError, type SegmentTransport } from "./segment-transport.js";

/** Seal the open segment once its sessions pass this much JSON (about 2 MB gzipped). */
export const SEGMENT_SEAL_BYTES = 8 * 1024 * 1024;

/**
 * Sessions whose last activity is older than this are left out, matching
 * the cloud's retention period: the cloud removes a segment once all of its
 * sessions are this old.
 */
export const SEGMENT_WINDOW_DAYS = 120;

export const SEGMENT_MANIFEST_FILE = "sync-segments.json";
const MANIFEST_VERSION = 1;

interface ManifestSegment {
  id: string;
  sealed: boolean;
  /** Session ids, in the order they were added. */
  sessions: string[];
  /** JSON bytes of its sessions, before compression. */
  raw_bytes: number;
  /** Envelope bytes as uploaded. */
  bytes: number;
}

interface ManifestSession {
  hash: string;
  raw_bytes: number;
  first_at: string;
  last_at: string;
}

export interface SegmentManifest {
  version: number;
  machine_id: string;
  customer_id: string;
  api_url: string;
  segments: ManifestSegment[];
  sessions: Record<string, ManifestSession>;
  /** The cloud's id for the last commit. */
  last_commit_id?: string;
}

export interface SegmentSyncOptions {
  store: ReadModelStore;
  transport: SegmentTransport;
  passphrase: string;
  kdfSalt: Uint8Array;
  customerId: string;
  apiUrl: string;
  machineId: string;
  machineLabel?: string;
  /** OMNODEX_HOME, where the manifest lives. */
  home: string;
  /** For the sync.pushed audit event. */
  eventLog?: EventLog;
  /** Overrides for tests. */
  now?: number;
  sealBytes?: number;
  windowDays?: number;
}

export interface SegmentSyncResult {
  /** The cloud's id for this commit. */
  commitId: string;
  /** Session ids now in the cloud for this machine. */
  sessionsIncluded: string[];
  /** Segments now in the cloud for this machine, and how many this sync uploaded. */
  segments: number;
  uploaded: number;
  /** Envelope bytes uploaded by this sync. */
  uploadedBytes: number;
  /** Envelope bytes of all the machine's segments, and of the largest (what the cloud's cap applies to). */
  totalBytes: number;
  largestBytes: number;
  /** JSON bytes of all synced sessions, before compression. */
  payloadBytes: number;
}

interface Slice {
  id: string;
  /** The session's part of a SyncPayload, without serialized_at. */
  part: Omit<SyncPayload, "serialized_at" | "payload_version">;
  json: string;
  hash: string;
  firstAt: string;
  lastAt: string;
}

/** Run one segmented sync. Throws on failure, leaving the manifest as it was. */
export async function syncSegments(opts: SegmentSyncOptions): Promise<SegmentSyncResult> {
  const manifestPath = path.join(opts.home, SEGMENT_MANIFEST_FILE);
  let manifest = await readManifest(manifestPath, opts);
  try {
    return await runOnce(opts, manifest, manifestPath);
  } catch (err) {
    if (!(err instanceof MissingSegmentsError) || manifest.segments.length === 0) throw err;
    // The cloud no longer holds something the manifest lists: upload afresh.
    manifest = emptyManifest(opts);
    return runOnce(opts, manifest, manifestPath);
  }
}

async function runOnce(
  opts: SegmentSyncOptions,
  manifest: SegmentManifest,
  manifestPath: string,
): Promise<SegmentSyncResult> {
  const now = opts.now ?? Date.now();
  const sealBytes = opts.sealBytes ?? SEGMENT_SEAL_BYTES;
  const cutoff = new Date(now - (opts.windowDays ?? SEGMENT_WINDOW_DAYS) * 86_400_000).toISOString();

  // 1. Serialize and hash each session in the window, oldest first.
  const rows = (await opts.store.listSessions())
    .filter((s) => lastActivity(s) >= cutoff)
    .sort((a, b) => (a.started_at < b.started_at ? -1 : a.started_at > b.started_at ? 1 : a.session_id < b.session_id ? -1 : 1));
  const slices = new Map<string, Slice>();
  for (const row of rows) slices.set(row.session_id, await sliceOf(opts.store, row));

  // 2. Classify against the manifest, and 3. take changed and gone sessions
  // out of their segments.
  const dirty = new Set<ManifestSegment>();
  const placed = new Set<string>();
  for (const seg of manifest.segments) {
    const keep = seg.sessions.filter((sid) => slices.get(sid)?.hash === manifest.sessions[sid]?.hash);
    if (keep.length !== seg.sessions.length) {
      seg.sessions = keep;
      seg.raw_bytes = keep.reduce((n, sid) => n + slices.get(sid)!.json.length, 0);
      dirty.add(seg);
    }
    for (const sid of keep) placed.add(sid);
  }
  let segments = manifest.segments.filter((seg) => seg.sessions.length > 0);

  // New and changed sessions, into the open segment, sealing as it fills.
  let open = segments.find((seg) => !seg.sealed);
  for (const slice of slices.values()) {
    if (placed.has(slice.id)) continue;
    if (open && open.raw_bytes > 0 && open.raw_bytes + slice.json.length > sealBytes) {
      open.sealed = true;
      open = undefined;
    }
    if (!open) {
      open = { id: "", sealed: false, sessions: [], raw_bytes: 0, bytes: 0 };
      segments.push(open);
    }
    open.sessions.push(slice.id);
    open.raw_bytes += slice.json.length;
    dirty.add(open);
  }
  // A single session larger than the seal size fills a segment on its own.
  if (open && open.raw_bytes >= sealBytes) open.sealed = true;
  segments = segments.filter((seg) => seg.sessions.length > 0);

  // 5. Encrypt and upload each dirty segment under a new id.
  const key = await deriveKey(opts.passphrase, opts.kdfSalt);
  const uploads: { seg: ManifestSegment; id: string; bytes: number; hash: string }[] = [];
  for (const seg of segments) {
    if (!dirty.has(seg)) continue;
    const parts = seg.sessions.map((sid) => slices.get(sid)!);
    const payload = assemble(parts, new Date(now).toISOString());
    const { ciphertext, iv } = await encrypt(key, gzipSync(new TextEncoder().encode(JSON.stringify(payload))));
    const envelope = encodeEnvelope(opts.kdfSalt, iv, ciphertext, ENVELOPE_VERSION_GZIP);
    const id = newSegmentId();
    const bytes = await opts.transport.putSegment(id, envelope, {
      machineId: opts.machineId,
      machineLabel: opts.machineLabel,
      sessions: parts.length,
      firstAt: parts.reduce((m, p) => (p.firstAt < m ? p.firstAt : m), parts[0]!.firstAt),
      lastAt: parts.reduce((m, p) => (p.lastAt > m ? p.lastAt : m), parts[0]!.lastAt),
    });
    uploads.push({ seg, id, bytes, hash: await sha256Hex(ciphertext) });
  }

  // 6. Commit the full list; nothing is visible to the dashboard before this.
  // A sync that changed nothing commits nothing, so open dashboards are not
  // told to reload.
  const nextIds = segments.map((seg) => uploads.find((u) => u.seg === seg)?.id ?? seg.id);
  const unchanged = uploads.length === 0 && sameList(nextIds, manifest.segments.map((s) => s.id)) && manifest.segments.length > 0;
  const commitId = unchanged
    ? manifest.last_commit_id ?? ""
    : await opts.transport.commit(nextIds, { machineId: opts.machineId, machineLabel: opts.machineLabel });

  // 7. Only now record what the cloud holds.
  for (const u of uploads) {
    u.seg.id = u.id;
    u.seg.bytes = u.bytes;
  }
  const next: SegmentManifest = {
    ...emptyManifest(opts),
    last_commit_id: commitId,
    segments,
    sessions: Object.fromEntries([...slices.values()].map((s) => [s.id, {
      hash: s.hash, raw_bytes: s.json.length, first_at: s.firstAt, last_at: s.lastAt,
    }])),
  };
  await writeManifest(manifestPath, next);

  const sessionsIncluded = [...slices.keys()];
  const uploadedBytes = uploads.reduce((n, u) => n + u.bytes, 0);
  if (opts.eventLog && uploads.length > 0) {
    const at = new Date().toISOString();
    const audit: SyncPushedEvent = {
      schema_version: SCHEMA_VERSION,
      event_id: randomUUID(),
      session_id: sessionsIncluded[0] ?? "global",
      occurred_at: at,
      recorded_at: at,
      interceptor: "analyzer",
      event_type: "sync.pushed",
      payload_bytes: segments.reduce((n, s) => n + s.raw_bytes, 0),
      // One digest over the ciphertexts this sync uploaded, in order.
      ciphertext_hash: createHash("sha256").update(uploads.map((u) => u.hash).join("\n")).digest("hex"),
      sessions_included: sessionsIncluded,
      cloud_receipt_id: commitId,
      machine_id: opts.machineId,
      machine_label: opts.machineLabel,
    };
    await opts.eventLog.append(audit);
  }

  return {
    commitId,
    sessionsIncluded,
    segments: segments.length,
    uploaded: uploads.length,
    uploadedBytes,
    totalBytes: segments.reduce((n, s) => n + s.bytes, 0),
    largestBytes: segments.reduce((n, s) => Math.max(n, s.bytes), 0),
    payloadBytes: segments.reduce((n, s) => n + s.raw_bytes, 0),
  };
}

/** A session's latest activity, falling back for rows that predate last_event_at. */
function lastActivity(s: SessionRow): string {
  return s.last_event_at || s.ended_at || s.started_at;
}

async function sliceOf(store: ReadModelStore, row: SessionRow): Promise<Slice> {
  const { serialized_at: _at, payload_version: _v, ...part } = await serializeReadModel(store, [row.session_id]);
  const json = JSON.stringify(part);
  return {
    id: row.session_id,
    part,
    json,
    hash: createHash("sha256").update(json).digest("hex"),
    firstAt: row.started_at,
    lastAt: lastActivity(row),
  };
}

/** A segment's SyncPayload: its sessions' parts, side by side. */
function assemble(parts: Slice[], serializedAt: string): SyncPayload {
  const payload: SyncPayload = {
    serialized_at: serializedAt,
    payload_version: SYNC_PAYLOAD_VERSION,
    session_ids: [],
    sessions: [],
    tool_calls: {},
    file_events: {},
    risk_events: {},
    prompts: {},
    subagents: {},
  };
  for (const { part } of parts) {
    payload.session_ids.push(...part.session_ids);
    payload.sessions.push(...part.sessions);
    Object.assign(payload.tool_calls, part.tool_calls);
    Object.assign(payload.file_events, part.file_events);
    Object.assign(payload.risk_events, part.risk_events);
    Object.assign(payload.prompts, part.prompts);
    Object.assign(payload.subagents, part.subagents);
  }
  return payload;
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** 22 URL-safe characters: 128 random bits. */
function newSegmentId(): string {
  return randomBytes(16).toString("base64url");
}

function emptyManifest(opts: SegmentSyncOptions): SegmentManifest {
  return {
    version: MANIFEST_VERSION,
    machine_id: opts.machineId,
    customer_id: opts.customerId,
    api_url: opts.apiUrl,
    segments: [],
    sessions: {},
  };
}

/** The saved manifest, or an empty one when it is missing, unreadable or another machine's or stream's. */
async function readManifest(file: string, opts: SegmentSyncOptions): Promise<SegmentManifest> {
  try {
    const m = JSON.parse(await fs.readFile(file, "utf8")) as SegmentManifest;
    const valid =
      m && m.version === MANIFEST_VERSION &&
      m.machine_id === opts.machineId && m.customer_id === opts.customerId && m.api_url === opts.apiUrl &&
      Array.isArray(m.segments) && m.sessions && typeof m.sessions === "object" &&
      m.segments.every((s) =>
        typeof s.id === "string" && s.id.length > 0 && Array.isArray(s.sessions) &&
        typeof s.raw_bytes === "number" && typeof s.bytes === "number" &&
        s.sessions.every((sid) => typeof m.sessions[sid]?.hash === "string"));
    return valid ? m : emptyManifest(opts);
  } catch {
    return emptyManifest(opts);
  }
}

/** Written to a temporary file and renamed, so a crash never leaves half a manifest. */
async function writeManifest(file: string, manifest: SegmentManifest): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(manifest) + "\n");
  await fs.rename(tmp, file);
}
