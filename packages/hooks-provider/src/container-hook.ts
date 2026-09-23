// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Capture from a cloud agent container.
 *
 * In a cloud-hosted Cowork task the agent runs in a disposable container
 * with no Omnodex install, no durable event log and no passphrase. The only
 * user-specific things there are the plugin's own files, so the plugin
 * bundle carries an `ingest.json`: a write-only ingest token and the
 * stream's public key.
 *
 * Each hook call maps the Claude Code payload to TraceEvents, seals every
 * event to the stream public key (HPKE, so only the owner's clients can
 * open it), and appends the ciphertext to a spool file. The spool is sent
 * once per turn, on Stop, or earlier when it grows past a size threshold,
 * so cloud usage grows with turns rather than with tool calls.
 *
 * Every failure is silent. Events that could not be sent stay on disk and
 * go out with the next flush; they are lost only if the container is
 * destroyed first.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import type { TraceEvent } from "@omnodex/shared";
import {
  base64ToBytes,
  computePublicKeyId,
  sealEvent,
  type HpkeEventWire,
} from "@omnodex/sync-encryptor/hpke-event";
import type { ClaudeCodeHookEventName, ClaudeCodeHookPayload } from "./claude-code-payload.js";
import { mapClaudeCodePayload } from "./claude-code-payload.js";

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/** Name of the per-user config file at the plugin root. */
export const INGEST_CONFIG_FILE = "ingest.json";

/** Paths that exist only in a cloud-hosted agent container. */
export const CLOUD_CONTAINER_MARKERS = ["/mnt/user-data", "/root/.ccr"];

/** Largest plaintext sealed for one event; the ingest API rejects more. */
export const MAX_EVENT_PLAINTEXT_BYTES = 256 * 1024;

/** A spool this large is flushed without waiting for the end of the turn. */
export const SPOOL_FLUSH_BYTES = 512 * 1024;

/** Per-request limits, kept under the ingest API's 100 events and 1 MB. */
export const MAX_BATCH_EVENTS = 100;
export const MAX_BATCH_BYTES = 900 * 1024;

/** A claim older than this was left by a killed process and is taken over. */
export const STALE_CLAIM_MS = 120_000;

/** Unsent events kept on disk; the oldest are dropped beyond this. */
export const MAX_PENDING_BYTES = 4 * 1024 * 1024;

/** Timeout for one ingest request. */
export const REQUEST_TIMEOUT_MS = 15_000;

/** Replaces parameter values when redaction is on (same as the MCP proxy). */
export const REDACTED_SENTINEL = "[REDACTED]";

/** Longest error message kept on a tool.completed event. */
const MAX_ERROR_MESSAGE_CHARS = 8 * 1024;

/** Hook events that end a turn or a session, and so flush the spool. */
const FLUSH_EVENTS = new Set(["Stop", "SessionEnd"]);

/** Hook events the payload mapper understands. */
const MAPPED_EVENTS = new Set<ClaudeCodeHookEventName>([
  "SessionStart",
  "SessionEnd",
  "PreToolUse",
  "PostToolUse",
  "PostToolUseFailure",
  "SubagentStart",
  "SubagentStop",
  "UserPromptSubmit",
]);

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Parsed and validated ingest.json. */
export interface IngestConfig {
  apiBase: string;
  ingestToken: string;
  sourceId: string;
  publicKey: Uint8Array;
  keyId: string;
  redactParameters: boolean;
  /** Capture even where no cloud container marker exists (testing only). */
  force: boolean;
}

const TOKEN_RE = /^oxi_[A-Za-z0-9_-]{16,128}$/;
const SOURCE_ID_RE = /^src_[0-9a-z_]{1,64}$/;
const KEY_ID_RE = /^[0-9a-f]{8}$/;

function isLoopback(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
}

/**
 * Validates the contents of ingest.json. Returns null for anything that is
 * missing or malformed, including a key_id that does not belong to the
 * public key, so a broken bundle captures nothing rather than sealing to
 * the wrong key.
 */
export async function parseIngestConfig(raw: unknown): Promise<IngestConfig | null> {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Record<string, unknown>;
  if (c.version !== 1) return null;
  if (typeof c.ingest_token !== "string" || !TOKEN_RE.test(c.ingest_token)) return null;
  if (typeof c.source_id !== "string" || !SOURCE_ID_RE.test(c.source_id)) return null;
  if (typeof c.key_id !== "string" || !KEY_ID_RE.test(c.key_id)) return null;
  if (typeof c.public_key !== "string") return null;

  let apiBase = "https://api.omnodex.com";
  if (c.api_base !== undefined) {
    if (typeof c.api_base !== "string") return null;
    let url: URL;
    try {
      url = new URL(c.api_base);
    } catch {
      return null;
    }
    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) return null;
    apiBase = url.origin;
  }

  let publicKey: Uint8Array;
  try {
    publicKey = base64ToBytes(c.public_key);
  } catch {
    return null;
  }
  if (publicKey.length !== 32) return null;
  if ((await computePublicKeyId(publicKey)) !== c.key_id) return null;

  return {
    apiBase,
    ingestToken: c.ingest_token,
    sourceId: c.source_id,
    publicKey,
    keyId: c.key_id,
    redactParameters: c.redact_parameters === true,
    force: c.force === true,
  };
}

/** Reads and validates `<pluginRoot>/ingest.json`; null when absent or invalid. */
export async function loadIngestConfig(pluginRoot: string): Promise<IngestConfig | null> {
  try {
    const text = fs.readFileSync(path.join(pluginRoot, INGEST_CONFIG_FILE), "utf8");
    return await parseIngestConfig(JSON.parse(text));
  } catch {
    return null;
  }
}

/** True inside a cloud-hosted agent container. */
export function isCloudContainer(
  markers: readonly string[] = CLOUD_CONTAINER_MARKERS,
  exists: (p: string) => boolean = fs.existsSync,
): boolean {
  return markers.some((m) => {
    try {
      return exists(m);
    } catch {
      return false;
    }
  });
}

// ---------------------------------------------------------------------------
// Event shaping
// ---------------------------------------------------------------------------

function newEventId(): string {
  return randomBytes(16).toString("hex");
}

function jsonBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

/**
 * Prepares one mapped event for sealing: marks the platform, redacts
 * parameter values when configured, and keeps the plaintext under the
 * per-event cap by dropping parameter values first and truncating a long
 * error message. Returns null for an event that still does not fit.
 */
export function prepareEvent(event: TraceEvent, redactParameters: boolean): TraceEvent | null {
  const out = { ...event, platform: "cowork" } as TraceEvent & {
    parameters?: Record<string, unknown>;
    error_message?: string;
  };
  if (out.parameters && redactParameters) {
    out.parameters = Object.fromEntries(Object.keys(out.parameters).map((k) => [k, REDACTED_SENTINEL]));
  }
  if (jsonBytes(out) <= MAX_EVENT_PLAINTEXT_BYTES) return out;

  if (out.parameters) {
    const originalBytes = jsonBytes(out.parameters);
    out.parameters = { _omnodex_truncated: true, original_bytes: originalBytes };
  }
  if (typeof out.error_message === "string" && out.error_message.length > MAX_ERROR_MESSAGE_CHARS) {
    out.error_message = out.error_message.slice(0, MAX_ERROR_MESSAGE_CHARS) + " [truncated]";
  }
  return jsonBytes(out) <= MAX_EVENT_PLAINTEXT_BYTES ? out : null;
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/** Where the hook keeps its spool, claims and status. */
export function ingestDir(home: string): string {
  return path.join(home, "ingest");
}

const SPOOL = "spool.ndjson";
const STATUS = "status.json";

function listFiles(dir: string, prefix: string): string[] {
  try {
    return fs
      .readdirSync(dir)
      .filter((f) => f.startsWith(prefix) && f.endsWith(".ndjson"))
      .sort();
  } catch {
    return [];
  }
}

function fileSize(p: string): number {
  try {
    return fs.statSync(p).size;
  } catch {
    return 0;
  }
}

/** Appends sealed events to the spool, one JSON line each. */
export function appendToSpool(home: string, events: HpkeEventWire[]): void {
  if (events.length === 0) return;
  const dir = ingestDir(home);
  fs.mkdirSync(dir, { recursive: true });
  // One write per hook call: O_APPEND keeps concurrent hooks' lines whole.
  fs.appendFileSync(path.join(dir, SPOOL), events.map((e) => JSON.stringify(e)).join("\n") + "\n");
}

/** Size of the current spool in bytes. */
export function spoolBytes(home: string): number {
  return fileSize(path.join(ingestDir(home), SPOOL));
}

/**
 * Takes everything waiting to be sent: the spool, earlier unsent remainders,
 * and claims abandoned by a killed flush. Each is renamed to a claim of this
 * process first, so two flushes never send the same file.
 */
export function claimPending(home: string, now: number): string[] {
  const dir = ingestDir(home);
  const tag = `${process.pid}-${now}`;
  const claimed: string[] = [];
  let n = 0;
  const take = (from: string): void => {
    const to = path.join(dir, `claim-${tag}-${n++}.ndjson`);
    try {
      fs.renameSync(path.join(dir, from), to);
      claimed.push(to);
    } catch {
      // Taken by a concurrent flush, or gone.
      return;
    }
    try {
      // A rename keeps the old mtime; restamp so the claim does not look abandoned.
      const t = new Date(now);
      fs.utimesSync(to, t, t);
    } catch {
      // ignore
    }
  };

  for (const f of listFiles(dir, "claim-")) {
    const mtime = (() => {
      try {
        return fs.statSync(path.join(dir, f)).mtimeMs;
      } catch {
        return now;
      }
    })();
    if (now - mtime >= STALE_CLAIM_MS) take(f);
  }
  for (const f of listFiles(dir, "pending-")) take(f);
  if (fileSize(path.join(dir, SPOOL)) > 0) take(SPOOL);
  return claimed;
}

/** Reads sealed events from claimed files; malformed lines are skipped. */
function readClaimed(files: string[]): string[] {
  const lines: string[] = [];
  for (const f of files) {
    let text = "";
    try {
      text = fs.readFileSync(f, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        JSON.parse(line);
        lines.push(line);
      } catch {
        // A line cut short by a killed writer.
      }
    }
  }
  return lines;
}

/** Keeps unsent lines for the next flush, dropping the oldest past the cap. */
function keepPending(home: string, lines: string[], now: number): number {
  if (lines.length === 0) return 0;
  const dir = ingestDir(home);
  let keep = lines;
  let bytes = keep.reduce((sum, l) => sum + Buffer.byteLength(l, "utf8") + 1, 0);
  let dropped = 0;
  while (bytes > MAX_PENDING_BYTES && keep.length > 0) {
    bytes -= Buffer.byteLength(keep[0]!, "utf8") + 1;
    keep = keep.slice(1);
    dropped++;
  }
  // Older pending files count toward the cap too.
  const others = listFiles(dir, "pending-");
  let otherBytes = others.reduce((s, f) => s + fileSize(path.join(dir, f)), 0);
  for (const f of others) {
    if (otherBytes + bytes <= MAX_PENDING_BYTES) break;
    otherBytes -= fileSize(path.join(dir, f));
    try {
      fs.unlinkSync(path.join(dir, f));
    } catch {
      // ignore
    }
  }
  if (keep.length > 0) {
    fs.writeFileSync(path.join(dir, `pending-${now}-${process.pid}.ndjson`), keep.join("\n") + "\n");
  }
  return dropped;
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/** HTTP status, or a transport error when no response arrived. */
export type PostResult = { status: number } | { error: string };

export type Poster = (url: string, token: string, body: string) => Promise<PostResult>;

/** POST with Node's fetch, which reaches the internet through the container's proxy. */
export const postWithFetch: Poster = async (url, token, body) => {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    await res.arrayBuffer().catch(() => undefined);
    return { status: res.status };
  } catch (err) {
    const e = err as { name?: string; cause?: { code?: string } };
    return { error: e.cause?.code ?? e.name ?? "fetch failed" };
  }
};

/**
 * POST with curl, the fallback when fetch cannot connect. The body goes over
 * stdin and the token through a header file, so neither appears in the
 * process list.
 */
export function makeCurlPoster(workDir: string): Poster {
  return (url, token, body) =>
    new Promise((resolve) => {
      const headerFile = path.join(workDir, `.headers-${process.pid}-${Date.now()}`);
      const cleanup = (): void => {
        try {
          fs.unlinkSync(headerFile);
        } catch {
          // ignore
        }
      };
      try {
        fs.mkdirSync(workDir, { recursive: true });
        fs.writeFileSync(headerFile, `Authorization: Bearer ${token}\nContent-Type: application/json\n`, { mode: 0o600 });
      } catch {
        resolve({ error: "curl header file" });
        return;
      }
      let out = "";
      let child;
      try {
        child = spawn(
          "curl",
          ["-sS", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", "-H", `@${headerFile}`,
            "--data-binary", "@-", "--max-time", String(REQUEST_TIMEOUT_MS / 1000), url],
          { stdio: ["pipe", "pipe", "ignore"] },
        );
      } catch {
        cleanup();
        resolve({ error: "curl spawn" });
        return;
      }
      child.stdout.on("data", (d: Buffer) => {
        out += d.toString("utf8");
      });
      child.on("error", () => {
        cleanup();
        resolve({ error: "curl spawn" });
      });
      child.on("close", (code) => {
        cleanup();
        const status = Number(out.trim());
        resolve(code === 0 && status > 0 ? { status } : { error: `curl exit ${code}` });
      });
      child.stdin.on("error", () => undefined);
      child.stdin.end(body);
    });
}

/** Tries each poster in turn until one gets an HTTP response. */
export function withFallback(...posters: Poster[]): Poster {
  return async (url, token, body) => {
    let last: PostResult = { error: "no transport" };
    for (const post of posters) {
      last = await post(url, token, body);
      if ("status" in last) return last;
    }
    return last;
  };
}

/** Statuses that will not change on retry: drop the batch rather than resend it forever. */
function isPermanent(status: number): boolean {
  return status === 400 || status === 401 || status === 403 || status === 404 || status === 413;
}

// ---------------------------------------------------------------------------
// Flush
// ---------------------------------------------------------------------------

export interface FlushResult {
  sent: number;
  dropped: number;
  pending: number;
  /** Last HTTP status or transport error seen. */
  last?: number | string;
}

/** Splits lines into request bodies within the per-request limits. */
export function batchLines(lines: string[]): string[][] {
  const batches: string[][] = [];
  let current: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    const size = Buffer.byteLength(line, "utf8") + 1;
    if (current.length > 0 && (current.length >= MAX_BATCH_EVENTS || bytes + size > MAX_BATCH_BYTES)) {
      batches.push(current);
      current = [];
      bytes = 0;
    }
    current.push(line);
    bytes += size;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * Sends everything waiting on disk. Sent and permanently rejected batches
 * are removed; on a transient failure (no response, 429, 5xx) the rest is
 * kept for the next flush and this one stops.
 */
export async function flushSpool(
  home: string,
  config: IngestConfig,
  post: Poster,
  now: number = Date.now(),
): Promise<FlushResult> {
  const claimed = claimPending(home, now);
  if (claimed.length === 0) return { sent: 0, dropped: 0, pending: 0 };

  const batches = batchLines(readClaimed(claimed));
  const url = `${config.apiBase}/api/v1/ingest/events`;
  const result: FlushResult = { sent: 0, dropped: 0, pending: 0 };
  let unsent: string[] = [];

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]!;
    const body = `{"events":[${batch.join(",")}]}`;
    const r = await post(url, config.ingestToken, body);
    if ("status" in r) {
      result.last = r.status;
      if (r.status >= 200 && r.status < 300) {
        result.sent += batch.length;
        continue;
      }
      if (isPermanent(r.status)) {
        result.dropped += batch.length;
        continue;
      }
    } else {
      result.last = r.error;
    }
    unsent = batches.slice(i).flat();
    break;
  }

  result.dropped += keepPending(home, unsent, now);
  result.pending = unsent.length;
  for (const f of claimed) {
    try {
      fs.unlinkSync(f);
    } catch {
      // ignore
    }
  }
  writeStatus(home, now, result);
  return result;
}

/** Records the last flush outcome (counts and status only, never content). */
function writeStatus(home: string, now: number, r: FlushResult): void {
  try {
    fs.writeFileSync(
      path.join(ingestDir(home), STATUS),
      JSON.stringify({ at: new Date(now).toISOString(), ...r }) + "\n",
    );
  } catch {
    // ignore
  }
}

// ---------------------------------------------------------------------------
// Hook entry
// ---------------------------------------------------------------------------

function timingPath(home: string, toolUseId: string): string | null {
  // tool_use_id comes from the payload; keep it to a safe file name.
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(toolUseId)) return null;
  return path.join(ingestDir(home), "timing", `${toolUseId}.ts`);
}

/** Fills in duration_ms from the matching PreToolUse, which Claude Code does not send. */
function trackDuration(home: string, payload: ClaudeCodeHookPayload, now: number): void {
  if (!("tool_use_id" in payload) || typeof payload.tool_use_id !== "string") return;
  const p = timingPath(home, payload.tool_use_id);
  if (!p) return;
  try {
    if (payload.hook_event_name === "PreToolUse") {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, String(now));
    } else if (payload.hook_event_name === "PostToolUse" || payload.hook_event_name === "PostToolUseFailure") {
      const started = Number(fs.readFileSync(p, "utf8"));
      fs.unlinkSync(p);
      if (!payload.duration_ms && Number.isFinite(started)) payload.duration_ms = Math.max(0, now - started);
    }
  } catch {
    // No matching PreToolUse: duration stays 0.
  }
}

export interface HandleOptions {
  home: string;
  post: Poster;
  now?: () => number;
}

/**
 * Handles one hook call: maps, seals and spools its events, then flushes
 * when the turn ended or the spool is large. Never throws.
 */
export async function handleHookPayload(
  payload: { hook_event_name?: unknown },
  config: IngestConfig,
  options: HandleOptions,
): Promise<FlushResult | null> {
  const now = options.now ?? Date.now;
  try {
    const name = payload.hook_event_name;
    if (typeof name !== "string") return null;

    if (MAPPED_EVENTS.has(name as ClaudeCodeHookEventName)) {
      const p = payload as ClaudeCodeHookPayload;
      if (typeof p.session_id !== "string") return null;
      trackDuration(options.home, p, now());
      const sealed: HpkeEventWire[] = [];
      for (const event of mapClaudeCodePayload(p, { newEventId })) {
        const prepared = prepareEvent(event, config.redactParameters);
        if (!prepared) continue;
        sealed.push(
          await sealEvent(config.publicKey, {
            eventId: prepared.event_id,
            ts: Date.parse(prepared.occurred_at) || now(),
            plaintext: new TextEncoder().encode(JSON.stringify(prepared)),
          }),
        );
      }
      appendToSpool(options.home, sealed);
    }

    if (FLUSH_EVENTS.has(name) || spoolBytes(options.home) >= SPOOL_FLUSH_BYTES) {
      return await flushSpool(options.home, config, options.post, now());
    }
    return null;
  } catch {
    return null;
  }
}
