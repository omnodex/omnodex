// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The OTLP/HTTP receiver: accepts trace exports, answers fast, then maps the
 * spans and hands the events to a sink.
 *
 * Why it answers first: the Claude API Console waits a few seconds for a
 * reply and disables a destination that keeps failing. So a request is
 * authenticated, decoded (to refuse a malformed body with 400), written to a
 * spool, and answered 200 before any mapping or rule evaluation runs. A queue
 * then works through the spool in arrival order.
 *
 * It listens on loopback unless told otherwise, only answers requests
 * addressed to a loopback name while it does (so a web page cannot reach it
 * through DNS rebinding), and refuses to listen on another address without a
 * token. Telemetry is cooperative and detective only: the receiver cannot
 * block anything and cannot know about spans never sent to it.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { gunzip } from "node:zlib";
import { promisify } from "node:util";
import type { TraceEvent } from "@omnodex/shared";
import { createOtelMapper, type OtelMapper } from "./mapper.js";
import { spansFromOtlpJson, type OtelSpan } from "./otlp.js";
import { ProtobufError, spansFromOtlpProtobuf } from "./protobuf.js";
import type { Sink } from "./local-sink.js";
import { Spool, type SpoolEntry, type SpoolFormat } from "./spool.js";

const gunzipAsync = promisify(gunzip);

export interface ReceiverStats {
  started_at: string;
  /** Requests answered 200. */
  requests: number;
  /** Requests refused: bad token, bad body, too large, queue full. */
  rejected: number;
  spans_received: number;
  spans_mapped: number;
  spans_ignored: number;
  /** The Console's Test button reaching this receiver. */
  test_markers: number;
  events_written: number;
  findings_written: number;
  /** Batches the sink failed on; their spooled bodies are tried again at the next start. */
  delivery_failures: number;
  /** Log exports accepted and not used. */
  logs_ignored: number;
  /** Bodies waiting to be mapped. */
  pending: number;
  /** Inferred denials waiting for a late tool span. */
  pending_denials: number;
  last_span_at: string | null;
}

export interface ReceiverOptions {
  host: string;
  port: number;
  /** When set, every request but the health check must send it as a bearer token. */
  token?: string;
  /** Permit a non-loopback address. Requires a token. */
  allowRemote?: boolean;
  spool: Spool;
  sink: Sink;
  /** Largest request body, compressed or not. Default 32 MiB. */
  maxBodyBytes?: number;
  /** Bodies waiting before new ones are refused with 503. Default 500. */
  maxPending?: number;
  /** How often inferred denials are checked for release, in ms. Default 5000. */
  sweepMs?: number;
  mapper?: OtelMapper;
  log?: (message: string) => void;
}

export interface Receiver {
  readonly host: string;
  readonly port: number;
  stats(): ReceiverStats;
  /** Stop listening, finish the queue and record any denials still held. */
  close(): Promise<void>;
}

export function isLoopbackHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "::1" || /^127(\.\d{1,3}){3}$/.test(h);
}

/** Split "host:port", "[::1]:port" or a bare port (loopback). Throws on anything else. */
export function parseListen(value: string): { host: string; port: number } {
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return { host: "127.0.0.1", port: checkPort(trimmed) };
  const m = /^(\[[^\]]+\]|[^:]+):(\d+)$/.exec(trimmed);
  if (!m) throw new Error(`expected host:port or a port, got "${value}"`);
  return { host: m[1]!.replace(/^\[|\]$/g, ""), port: checkPort(m[2]!) };
}

function checkPort(text: string): number {
  const n = Number.parseInt(text, 10);
  if (!Number.isInteger(n) || n < 0 || n > 65535) throw new Error(`port out of range: ${text}`);
  return n;
}

function digest(s: string): Buffer {
  return createHash("sha256").update(s).digest();
}

function tokenMatches(header: string | undefined, token: string): boolean {
  const m = /^Bearer\s+(.+)$/i.exec(header ?? "");
  if (!m) return false;
  // Hashing both sides gives equal-length buffers, so the comparison takes the same time whatever the guess.
  return timingSafeEqual(digest(m[1]!.trim()), digest(token));
}

function hostAllowed(hostHeader: string | undefined): boolean {
  if (!hostHeader) return false;
  const name = hostHeader.startsWith("[") ? hostHeader.slice(0, hostHeader.indexOf("]") + 1) : hostHeader.split(":")[0]!;
  return isLoopbackHost(name);
}

function mediaType(header: string | undefined): string {
  return (header ?? "").split(";")[0]!.trim().toLowerCase();
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Work for the queue's single worker: a spooled request to map, or events ready to write. */
type Job = { entry: SpoolEntry; spans: OtelSpan[] } | { events: TraceEvent[] };

function decode(body: Buffer, format: SpoolFormat): OtelSpan[] {
  if (format === "protobuf") return spansFromOtlpProtobuf(body);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    throw new ProtobufError("body is not valid JSON");
  }
  return spansFromOtlpJson(parsed);
}

export async function startReceiver(options: ReceiverOptions): Promise<Receiver> {
  const { host, port, spool, sink } = options;
  const log = options.log ?? (() => undefined);
  const maxBody = options.maxBodyBytes ?? 32 * 1024 * 1024;
  const maxPending = options.maxPending ?? 500;
  const mapper = options.mapper ?? createOtelMapper();
  const loopback = isLoopbackHost(host);

  if (!loopback) {
    if (!options.allowRemote) {
      throw new Error(`refusing to listen on non-loopback address ${host}. Pass --allow-remote, with a token, to do this deliberately.`);
    }
    if (!options.token) throw new Error(`listening on non-loopback address ${host} requires a token. Run 'omnodex otel token' to create one.`);
  }

  const stats: ReceiverStats = {
    started_at: new Date().toISOString(),
    requests: 0,
    rejected: 0,
    spans_received: 0,
    spans_mapped: 0,
    spans_ignored: 0,
    test_markers: 0,
    events_written: 0,
    findings_written: 0,
    delivery_failures: 0,
    logs_ignored: 0,
    pending: 0,
    pending_denials: 0,
    last_span_at: null,
  };

  await spool.init();

  // -- the queue -------------------------------------------------------------

  const queue: Job[] = [];
  let working = false;
  let idle: Promise<void> = Promise.resolve();

  async function deliver(events: TraceEvent[]): Promise<void> {
    const result = await sink.deliver(events);
    stats.events_written += result.events;
    stats.findings_written += result.findings;
  }

  async function runJob(job: Job): Promise<void> {
    if (!("entry" in job)) {
      try {
        await deliver(job.events);
      } catch (err) {
        stats.delivery_failures++;
        log(`delivery of inferred denials failed: ${(err as Error).message}`);
      }
      return;
    }
    try {
      const { events, stats: m } = mapper.mapSpans(job.spans);
      stats.spans_mapped += m.mapped;
      stats.spans_ignored += m.ignored;
      stats.test_markers += m.testMarkers;
      await deliver(events);
      await spool.remove(job.entry);
    } catch (err) {
      // The body stays in the spool, so the next start maps it again.
      stats.delivery_failures++;
      log(`delivery failed, keeping ${job.entry.name} for the next start: ${(err as Error).message}`);
    }
  }

  function pump(): void {
    if (working) return;
    working = true;
    idle = (async () => {
      try {
        for (let job = queue.shift(); job; job = queue.shift()) {
          stats.pending = queue.length;
          await runJob(job);
        }
      } finally {
        working = false;
        stats.pending = queue.length;
      }
    })();
  }

  function enqueue(job: Job): void {
    queue.push(job);
    stats.pending = queue.length;
    pump();
  }

  // Bodies a crash left in the spool come first, oldest first.
  for (const entry of await spool.pending()) {
    try {
      queue.push({ entry, spans: decode(await spool.read(entry), entry.format) });
    } catch (err) {
      log(`dropping unreadable spooled body ${entry.name}: ${(err as Error).message}`);
      await spool.remove(entry);
    }
  }
  if (queue.length > 0) {
    log(`mapping ${queue.length} request(s) left in the spool`);
    pump();
  }

  const sweep = setInterval(() => {
    const due = mapper.drainPending();
    stats.pending_denials = mapper.pendingDenials;
    // Behind the queue, so a denial is never written ahead of the batch that held it.
    if (due.length > 0) enqueue({ events: due });
  }, options.sweepMs ?? 5000);
  sweep.unref();

  // -- the server ------------------------------------------------------------

  async function readBody(req: http.IncomingMessage): Promise<Buffer> {
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBody) throw new HttpError(413, "request body too large");
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > maxBody) throw new HttpError(413, "request body too large");
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
  }

  async function inflate(raw: Buffer, encoding: string | undefined): Promise<Buffer> {
    const enc = (encoding ?? "identity").toLowerCase();
    if (enc === "identity" || enc === "") return raw;
    if (enc !== "gzip") throw new HttpError(415, `unsupported content-encoding ${enc}`);
    try {
      return await gunzipAsync(raw, { maxOutputLength: maxBody });
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE") throw new HttpError(413, "request body too large");
      throw new HttpError(400, "body is not valid gzip");
    }
  }

  function reply(res: http.ServerResponse, status: number, body = "", type = "text/plain"): void {
    res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body) });
    res.end(body);
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = (req.url ?? "").split("?")[0];
    if (loopback && !hostAllowed(req.headers.host)) throw new HttpError(403, "host not allowed");
    if (req.method === "GET" && url === "/healthz") {
      reply(res, 200, "ok");
      return;
    }
    if (options.token && !tokenMatches(req.headers.authorization, options.token)) {
      res.setHeader("www-authenticate", "Bearer");
      throw new HttpError(401, "unauthorized");
    }
    if (req.method === "GET" && url === "/status") {
      stats.pending_denials = mapper.pendingDenials;
      reply(res, 200, JSON.stringify(stats), "application/json");
      return;
    }
    if (url !== "/v1/traces" && url !== "/v1/logs") throw new HttpError(404, "not found");
    if (req.method !== "POST") throw new HttpError(405, "POST only");

    const type = mediaType(req.headers["content-type"]);
    const format: SpoolFormat | undefined = type === "application/x-protobuf" ? "protobuf" : type === "application/json" ? "json" : undefined;
    if (!format) throw new HttpError(415, "send application/x-protobuf or application/json");

    const body = await inflate(await readBody(req), req.headers["content-encoding"] as string | undefined);
    const ok = (): void => {
      stats.requests++;
      // An empty export response: no partial success, nothing rejected.
      if (format === "json") reply(res, 200, "{}", "application/json");
      else reply(res, 200, "", "application/x-protobuf");
    };

    if (url === "/v1/logs") {
      // Log exports (Claude Code's event stream) are not mapped yet. Accepted
      // so a sender configured for them does not report errors.
      stats.logs_ignored++;
      ok();
      return;
    }

    let spans: OtelSpan[];
    try {
      spans = decode(body, format);
    } catch (err) {
      if (err instanceof ProtobufError) throw new HttpError(400, `malformed export: ${err.message}`);
      throw err;
    }
    if (queue.length >= maxPending) {
      res.setHeader("retry-after", "5");
      throw new HttpError(503, "busy, try again");
    }

    stats.spans_received += spans.length;
    if (spans.length > 0) stats.last_span_at = new Date().toISOString();
    if (spans.length === 0) {
      ok();
      return;
    }
    const entry = await spool.put(body, format);
    enqueue({ entry, spans });
    ok();
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      stats.rejected++;
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) log(`request failed: ${(err as Error).message}`);
      // The rest of an oversized or refused upload is not worth reading.
      if (status === 413 || status === 415) res.setHeader("connection", "close");
      if (!res.headersSent) reply(res, status, err instanceof HttpError ? err.message : "internal error");
      else res.end();
    });
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const bound = server.address() as AddressInfo;

  return {
    host,
    port: bound.port,
    stats() {
      stats.pending = queue.length;
      stats.pending_denials = mapper.pendingDenials;
      return { ...stats };
    },
    async close() {
      clearInterval(sweep);
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      });
      // Let the queue finish, then record the denials still being held.
      const rest = mapper.drainPending({ force: true });
      if (rest.length > 0) enqueue({ events: rest });
      for (let seen = idle; ; seen = idle) {
        await seen;
        if (seen === idle && !working && queue.length === 0) break;
      }
      await sink.close();
    },
  };
}
