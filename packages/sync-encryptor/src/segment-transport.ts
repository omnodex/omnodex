// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/sync-encryptor -- segment transport
 *
 * Uploads encrypted sync segments and commits a machine's segment list:
 *   PUT /api/v1/sync/segments/:id   one envelope, stored as pending
 *   PUT /api/v1/sync/manifest       the machine's full list of segment ids
 *
 * The cloud only makes uploaded segments visible once a commit lists them,
 * and retires the machine's segments the commit leaves out. Segment ids are
 * random and say nothing about content.
 */

import { SyncBlobTooLargeError } from "./transport.js";

export interface SegmentMeta {
  machineId: string;
  machineLabel?: string;
  /** Sessions in the segment. */
  sessions: number;
  /** Earliest and latest activity of its sessions; the cloud ages segments by lastAt. */
  firstAt: string;
  lastAt: string;
}

export interface SegmentTransport {
  /** Upload one envelope. Resolves to the bytes uploaded. */
  putSegment(segmentId: string, envelope: Uint8Array, meta: SegmentMeta): Promise<number>;
  /** Commit the machine's full segment list. Resolves to the cloud's commit id. */
  commit(segmentIds: string[], machine: { machineId: string; machineLabel?: string }): Promise<string>;
}

/** The API has no segment routes (an older or self-hosted cloud); use the single-blob push. */
export class SegmentsUnsupportedError extends Error {
  constructor() {
    super("the sync API does not support segments");
    this.name = "SegmentsUnsupportedError";
  }
}

/** A commit listed segments the cloud does not hold, for example after retention removed them. */
export class MissingSegmentsError extends Error {
  readonly missing: string[];
  constructor(missing: string[]) {
    super(`sync commit refused: ${missing.length} segment(s) not in the cloud`);
    this.name = "MissingSegmentsError";
    this.missing = missing;
  }
}

export interface HttpSegmentTransportOptions {
  baseUrl: string;
  apiToken: string;
  /** Per-request timeout in ms. Default: 30000. */
  timeoutMs?: number;
}

export class HttpSegmentTransport implements SegmentTransport {
  private readonly baseUrl: string;
  private readonly apiToken: string;
  private readonly timeoutMs: number;

  constructor(options: HttpSegmentTransportOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiToken = options.apiToken;
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  async putSegment(segmentId: string, envelope: Uint8Array, meta: SegmentMeta): Promise<number> {
    const res = await this.request("PUT", "/api/v1/sync/segments/" + encodeURIComponent(segmentId), {
      "Content-Type": "application/octet-stream",
      "X-Omnodex-Machine-Id": meta.machineId,
      ...(meta.machineLabel ? { "X-Omnodex-Machine-Label": meta.machineLabel } : {}),
      "X-Omnodex-Segment-Sessions": String(meta.sessions),
      "X-Omnodex-First-At": meta.firstAt,
      "X-Omnodex-Last-At": meta.lastAt,
    }, envelope);
    // A cloud without the route answers 404 with no JSON error code.
    if (res.status === 404) throw new SegmentsUnsupportedError();
    if (res.status === 413) throw new SyncBlobTooLargeError(envelope.byteLength);
    if (!res.ok) throw await failure("sync segment upload", res);
    return envelope.byteLength;
  }

  async commit(segmentIds: string[], machine: { machineId: string; machineLabel?: string }): Promise<string> {
    const res = await this.request("PUT", "/api/v1/sync/manifest", {
      "Content-Type": "application/json",
      "X-Omnodex-Machine-Id": machine.machineId,
      ...(machine.machineLabel ? { "X-Omnodex-Machine-Label": machine.machineLabel } : {}),
    }, JSON.stringify({ segments: segmentIds }));
    if (res.status === 404) throw new SegmentsUnsupportedError();
    if (res.status === 409) {
      const body = (await res.json().catch(() => null)) as { error?: string; missing?: unknown } | null;
      if (body?.error === "missing_segments" && Array.isArray(body.missing)) {
        throw new MissingSegmentsError(body.missing.filter((m): m is string => typeof m === "string"));
      }
      throw new Error("sync commit failed: HTTP 409");
    }
    if (!res.ok) throw await failure("sync commit", res);
    const data = (await res.json()) as { commit_id?: string };
    return data.commit_id ?? "";
  }

  private async request(method: string, path: string, headers: Record<string, string>, body: Uint8Array | string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(this.baseUrl + path, {
        method,
        headers: { ...headers, Authorization: "Bearer " + this.apiToken },
        // BodyInit typings do not accept a Uint8Array view; envelopes are
        // fresh full-size buffers, so the ArrayBuffer is exactly the bytes.
        body: typeof body === "string" ? body : (body.buffer as ArrayBuffer),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }
}

async function failure(what: string, res: Response): Promise<Error> {
  const text = await res.text().catch(() => "");
  return new Error(`${what} failed: HTTP ${res.status} ${text.slice(0, 200)}`);
}
