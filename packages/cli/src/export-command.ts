// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex export`: write events and findings from the local event log to a
 * file as JSON lines, in Omnodex's own normalized form or as OCSF.
 *
 * It reads local files and writes one local file. It opens no connection, so
 * a collector already on the machine (a SIEM forwarder or log agent) can tail
 * the output. With --follow the command keeps running, appends new events and
 * rotates the file by size.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { TraceEvent } from "@omnodex/shared";
import { buildBundle } from "./evidence/bundle.js";
import {
  inWindow,
  normalizeEvent,
  parseInclude,
  parseTimeArg,
  toOcsf,
  type ContentGroup,
} from "./export-events.js";

export const EXPORT_FORMATS = ["jsonl", "ocsf"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export const EXPORT_FLAGS = ["--follow", "--bundle"] as const;
export const EXPORT_VALUES = ["--format", "--since", "--until", "--out", "--include", "--max-size", "--keep"] as const;

export const DEFAULT_MAX_SIZE = 50 * 1024 * 1024;
export const DEFAULT_KEEP = 5;
const DEFAULT_POLL_MS = 1000;

export interface ExportIo {
  /** Write exported text to standard output (used for `--out -`). */
  write(text: string): void;
  error(line: string): void;
}

export interface ExportDeps {
  /** Omnodex roots to read; each holds an `event-log` folder. */
  roots: string[];
  io: ExportIo;
  /** The Omnodex home, where seals and the signing key live (needed for --bundle). */
  home?: string;
  /** Ends --follow. */
  signal?: AbortSignal;
  /** How often --follow looks for new events. */
  pollMs?: number;
  now?: () => number;
}

export interface ExportOptions {
  format: ExportFormat;
  since?: number;
  until?: number;
  out: string;
  follow: boolean;
  /** Write a signed evidence bundle instead of an event feed. */
  bundle: boolean;
  include: Set<ContentGroup>;
  maxSize: number;
  keep: number;
}

/** Parse a size such as 500000, 512k, 50m or 1g. */
export function parseSize(text: string): number | undefined {
  const m = /^(\d+)([kmg])?$/i.exec(text.trim());
  if (!m) return undefined;
  const mult = { k: 1024, m: 1024 ** 2, g: 1024 ** 3 }[(m[2] ?? "").toLowerCase() as "k" | "m" | "g"] ?? 1;
  const bytes = Number(m[1]) * mult;
  return bytes > 0 ? bytes : undefined;
}

export function parseExportArgs(args: readonly string[], now: number = Date.now()): ExportOptions | { error: string } {
  const flags = new Set<string>();
  const values = new Map<string, string>();
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((EXPORT_FLAGS as readonly string[]).includes(arg)) flags.add(arg);
    else if ((EXPORT_VALUES as readonly string[]).includes(arg)) values.set(arg, args[++i]);
    else return { error: `unexpected argument '${arg}'` };
  }
  const out = values.get("--out");
  if (!out) return { error: "--out <file> is required (use --out - for standard output)" };
  const format = values.get("--format") ?? "jsonl";
  if (!(EXPORT_FORMATS as readonly string[]).includes(format)) {
    return { error: `unknown format '${format}' (use ${EXPORT_FORMATS.join(" or ")})` };
  }
  const follow = flags.has("--follow");
  const bundle = flags.has("--bundle");
  if (bundle) {
    for (const incompatible of ["--follow", "--format", "--include", "--max-size", "--keep"]) {
      if (flags.has(incompatible) || values.has(incompatible)) return { error: `${incompatible} cannot be used with --bundle` };
    }
  }
  let since: number | undefined;
  let until: number | undefined;
  if (values.has("--since")) {
    since = parseTimeArg(values.get("--since")!, now);
    if (since === undefined) return { error: `cannot read --since '${values.get("--since")}' (use a date, a timestamp, or an age such as 24h or 7d)` };
  }
  if (values.has("--until")) {
    if (follow) return { error: "--until cannot be used with --follow" };
    until = parseTimeArg(values.get("--until")!, now);
    if (until === undefined) return { error: `cannot read --until '${values.get("--until")}' (use a date, a timestamp, or an age such as 24h or 7d)` };
  }
  const include = parseInclude(values.get("--include"));
  if ("error" in include) return { error: include.error };
  let maxSize = DEFAULT_MAX_SIZE;
  if (values.has("--max-size")) {
    const parsed = parseSize(values.get("--max-size")!);
    if (parsed === undefined) return { error: `cannot read --max-size '${values.get("--max-size")}' (use bytes, or a size such as 512k, 50m or 1g)` };
    maxSize = parsed;
  }
  let keep = DEFAULT_KEEP;
  if (values.has("--keep")) {
    const parsed = Number(values.get("--keep"));
    if (!Number.isInteger(parsed) || parsed < 0) return { error: `cannot read --keep '${values.get("--keep")}' (use a whole number, 0 or more)` };
    keep = parsed;
  }
  return { format: format as ExportFormat, since, until, out, follow, bundle, include: include.groups, maxSize, keep };
}

/** One output line for an event, or undefined for a format the code does not know. */
export function formatEvent(event: TraceEvent, options: Pick<ExportOptions, "format" | "include">): string {
  const normalized = normalizeEvent(event, options.include);
  const record = options.format === "ocsf" ? toOcsf(normalized) : normalized;
  return JSON.stringify(record) + "\n";
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

async function sessionFiles(roots: readonly string[]): Promise<string[]> {
  const files: string[] = [];
  for (const root of roots) {
    const dir = path.join(root, "event-log", "sessions");
    const names = await fs.readdir(dir).catch(() => [] as string[]);
    for (const name of names.sort()) {
      if (name.endsWith(".jsonl")) files.push(path.join(dir, name));
    }
  }
  return files;
}

function parseLines(text: string): TraceEvent[] {
  const events: TraceEvent[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = JSON.parse(line) as TraceEvent;
      if (parsed && typeof parsed === "object" && typeof parsed.event_type === "string") events.push(parsed);
    } catch {
      // A partial or damaged line is skipped, as everywhere else the log is read.
    }
  }
  return events;
}

function eventMs(event: TraceEvent): number {
  const ms = Date.parse(event.occurred_at);
  if (!Number.isNaN(ms)) return ms;
  const rec = Date.parse(event.recorded_at);
  return Number.isNaN(rec) ? 0 : rec;
}

/** Every event in the window, oldest first. */
export async function readWindow(roots: readonly string[], since?: number, until?: number): Promise<TraceEvent[]> {
  const events: TraceEvent[] = [];
  for (const file of await sessionFiles(roots)) {
    const text = await fs.readFile(file, "utf8").catch(() => "");
    for (const event of parseLines(text)) {
      if (inWindow(event, since, until)) events.push(event);
    }
  }
  return events.sort((a, b) => eventMs(a) - eventMs(b));
}

/** Where --follow stopped reading each session file. */
export interface Watermark {
  version: 1;
  offsets: Record<string, number>;
}

/** Reads new complete lines from every session file since the last poll. */
export class LogFollower {
  private offsets = new Map<string, number>();
  private started = false;

  constructor(private readonly roots: readonly string[], saved?: Watermark) {
    if (saved) {
      for (const [file, offset] of Object.entries(saved.offsets)) this.offsets.set(file, offset);
    }
  }

  /**
   * Where to begin when there is no saved watermark: the end of every file
   * that exists now (`fromEnd`), or the start of all of them.
   */
  async begin(fromEnd: boolean): Promise<void> {
    this.started = true;
    if (!fromEnd) return;
    for (const file of await sessionFiles(this.roots)) {
      if (this.offsets.has(file)) continue;
      const stat = await fs.stat(file).catch(() => undefined);
      if (stat) this.offsets.set(file, stat.size);
    }
  }

  watermark(): Watermark {
    return { version: 1, offsets: Object.fromEntries(this.offsets) };
  }

  /** New events since the previous call. A file not seen before is read from its start. */
  async poll(): Promise<TraceEvent[]> {
    if (!this.started) await this.begin(false);
    const events: TraceEvent[] = [];
    for (const file of await sessionFiles(this.roots)) {
      const stat = await fs.stat(file).catch(() => undefined);
      if (!stat) continue;
      let offset = this.offsets.get(file) ?? 0;
      // The file was replaced or emptied: read it again from the top.
      if (stat.size < offset) offset = 0;
      if (stat.size > offset) {
        const handle = await fs.open(file, "r");
        try {
          const buf = Buffer.alloc(stat.size - offset);
          const { bytesRead } = await handle.read(buf, 0, buf.length, offset);
          // Only whole lines count: a line still being written is read again
          // next time, and a saved offset never lands inside one.
          const cut = buf.subarray(0, bytesRead).lastIndexOf(0x0a);
          if (cut !== -1) {
            events.push(...parseLines(buf.subarray(0, cut).toString("utf8")));
            offset += cut + 1;
          }
        } finally {
          await handle.close();
        }
      }
      this.offsets.set(file, offset);
    }
    return events.sort((a, b) => eventMs(a) - eventMs(b));
  }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/**
 * Appends to a file and, when it would pass `maxSize`, moves it aside as
 * `<file>.1` first, shifting older files up and dropping any beyond `keep`.
 * The file is not held open between writes, so a collector that tails it by
 * name sees an ordinary rename.
 */
export class RotatingFile {
  constructor(private readonly file: string, private readonly maxSize: number, private readonly keep: number) {}

  async append(text: string): Promise<void> {
    await fs.mkdir(path.dirname(this.file), { recursive: true });
    const stat = await fs.stat(this.file).catch(() => undefined);
    if (stat && stat.size > 0 && stat.size + Buffer.byteLength(text) > this.maxSize) await this.rotate();
    await fs.appendFile(this.file, text, "utf8");
  }

  private async rotate(): Promise<void> {
    if (this.keep === 0) {
      await fs.rm(this.file, { force: true });
      return;
    }
    await fs.rm(`${this.file}.${this.keep}`, { force: true });
    for (let n = this.keep - 1; n >= 1; n--) {
      await fs.rename(`${this.file}.${n}`, `${this.file}.${n + 1}`).catch((err: NodeJS.ErrnoException) => {
        if (err.code !== "ENOENT") throw err;
      });
    }
    await fs.rename(this.file, `${this.file}.1`);
  }
}

async function readWatermark(file: string): Promise<Watermark | undefined> {
  try {
    const parsed = JSON.parse(await fs.readFile(file, "utf8")) as Watermark;
    if (parsed?.version === 1 && parsed.offsets && typeof parsed.offsets === "object") return parsed;
  } catch {
    // No usable watermark: start as a first run.
  }
  return undefined;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    }
    signal?.addEventListener("abort", done, { once: true });
  });
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/** Run `omnodex export`. Returns the exit code. */
export async function runExport(args: readonly string[], deps: ExportDeps): Promise<number> {
  const now = deps.now?.() ?? Date.now();
  const options = parseExportArgs(args, now);
  if ("error" in options) {
    deps.io.error(`[export] ${options.error}. Run 'omnodex export --help' for usage.`);
    return 1;
  }
  const toStdout = options.out === "-";
  if (options.bundle) return runBundle(options, deps, now);
  const lines = (events: TraceEvent[]) => events.map((e) => formatEvent(e, options)).join("");

  if (!options.follow) {
    const events = await readWindow(deps.roots, options.since, options.until);
    const text = lines(events);
    if (toStdout) {
      if (text) deps.io.write(text);
    } else {
      await fs.mkdir(path.dirname(path.resolve(options.out)), { recursive: true });
      await fs.writeFile(options.out, text, "utf8");
    }
    deps.io.error(`[export] wrote ${events.length} event(s) as ${options.format}${toStdout ? "" : ` to ${options.out}`}.`);
    return 0;
  }

  // Following. A file output keeps a watermark beside it, so a restart carries
  // on from where the last run stopped instead of repeating events.
  const watermarkFile = toStdout ? undefined : `${options.out}.watermark.json`;
  const saved = watermarkFile ? await readWatermark(watermarkFile) : undefined;
  const follower = new LogFollower(deps.roots, saved);
  if (!saved) await follower.begin(options.since === undefined);
  const sink = toStdout ? undefined : new RotatingFile(options.out, options.maxSize, options.keep);
  const pollMs = deps.pollMs ?? DEFAULT_POLL_MS;
  let total = 0;
  // A first run with --since also exports that history; later runs and
  // restarts pick up from the watermark, so --since applies only to the first.
  const since = saved ? undefined : options.since;

  deps.io.error(`[export] following ${deps.roots.length} root(s) as ${options.format}${toStdout ? "" : ` to ${options.out}`}${saved ? " (resuming)" : ""}. Stop with Ctrl+C.`);
  while (!deps.signal?.aborted) {
    const events = (await follower.poll()).filter((e) => inWindow(e, since));
    if (events.length > 0) {
      const text = lines(events);
      if (sink) await sink.append(text);
      else deps.io.write(text);
      total += events.length;
    }
    if (watermarkFile) await fs.writeFile(watermarkFile, JSON.stringify(follower.watermark()), "utf8");
    await sleep(pollMs, deps.signal);
  }
  deps.io.error(`[export] stopped after ${total} event(s).`);
  return 0;
}

/** `omnodex export --bundle`: seal what is pending and write the signed bundle. */
async function runBundle(options: ExportOptions, deps: ExportDeps, now: number): Promise<number> {
  if (!deps.home) {
    deps.io.error("[export] --bundle needs the Omnodex home.");
    return 1;
  }
  try {
    const built = await buildBundle({ home: deps.home, roots: deps.roots, since: options.since, until: options.until, now: () => now });
    if (options.out === "-") {
      deps.io.write(built.text);
    } else {
      await fs.mkdir(path.dirname(path.resolve(options.out)), { recursive: true });
      await fs.writeFile(options.out, built.text, "utf8");
    }
    deps.io.error(`[export] wrote a bundle of ${built.seals} seal(s) and ${built.events} event(s)${options.out === "-" ? "" : ` to ${options.out}`}.`);
    deps.io.error("[export] The bundle holds every event in full, prompts and tool parameters included. Check it before handing it on.");
    if (built.missing.length > 0) {
      deps.io.error(`[export] ${built.missing.length} sealed event(s) are no longer in the log and are missing from the bundle; omnodex verify will report them as dropped.`);
    }
    return 0;
  } catch (err) {
    deps.io.error(`[export] ${err instanceof Error ? err.message : String(err)}.`);
    return 1;
  }
}
