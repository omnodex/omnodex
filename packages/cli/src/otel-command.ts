// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex otel`: receive OpenTelemetry traces from agents that have no hooks.
 *
 *   otel serve [--listen <host:port>] [--allow-remote]   run the OTLP/HTTP receiver
 *   otel token [--rotate]                                print the receiver's bearer token
 *
 * The receiver runs where you control it and writes the local event log, the
 * same as a hook does, so prompts and tool arguments stay on your side.
 */

import * as path from "node:path";
import {
  createLocalSink,
  ensureToken,
  isLoopbackHost,
  parseListen,
  resolveToken,
  Spool,
  startReceiver,
  TOKEN_ENV,
} from "@omnodex/otel-receiver";

export const OTEL_SERVE_FLAGS = ["--allow-remote"] as const;
export const OTEL_SERVE_VALUES = ["--listen"] as const;
export const OTEL_TOKEN_FLAGS = ["--rotate"] as const;
export const DEFAULT_LISTEN = "127.0.0.1:4318";

export interface OtelIo {
  log(line: string): void;
  error(line: string): void;
}

export interface OtelDeps {
  home: string;
  io: OtelIo;
  /** Aborted to stop `serve` (Ctrl+C, a service manager). */
  signal?: AbortSignal;
  env?: NodeJS.ProcessEnv;
  /** Called once the receiver is listening, with its address. For tests. */
  onListening?: (info: { host: string; port: number }) => void;
}

function valueOf(args: readonly string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

const USAGE = [
  "Usage: omnodex otel <serve | token>",
  "",
  "  serve [--listen <host:port>] [--allow-remote]   run the OTLP/HTTP receiver (default 127.0.0.1:4318)",
  "  token [--rotate]                                print the receiver's bearer token, creating it on first use",
].join("\n");

/** Returns the process exit code. */
export async function runOtel(args: readonly string[], deps: OtelDeps): Promise<number> {
  const [sub, ...rest] = args;
  if (sub === "token") return runToken(rest, deps);
  if (sub === "serve") return runServe(rest, deps);
  deps.io.error(sub ? `unknown otel command '${sub}'` : "an otel command is required");
  deps.io.error(USAGE);
  return 1;
}

async function runToken(args: readonly string[], deps: OtelDeps): Promise<number> {
  const { token, created } = await ensureToken(deps.home, { rotate: args.includes("--rotate") });
  // The token alone on standard output, so a script can capture it.
  deps.io.log(token);
  if (created) deps.io.error(args.includes("--rotate") ? "[otel] new token created; restart the receiver to use it" : "[otel] token created");
  return 0;
}

async function runServe(args: readonly string[], deps: OtelDeps): Promise<number> {
  const env = deps.env ?? process.env;
  let listen: { host: string; port: number };
  try {
    listen = parseListen(valueOf(args, "--listen") ?? DEFAULT_LISTEN);
  } catch (err) {
    deps.io.error(`[otel] --listen: ${(err as Error).message}`);
    return 1;
  }
  const token = await resolveToken(deps.home, env);
  const sink = await createLocalSink({ home: deps.home, onError: (m) => deps.io.error(`[otel] ${m}`) });
  let receiver;
  try {
    receiver = await startReceiver({
      host: listen.host,
      port: listen.port,
      token,
      allowRemote: args.includes("--allow-remote"),
      spool: new Spool(path.join(deps.home, "otel-spool")),
      sink,
      log: (m) => deps.io.error(`[otel] ${m}`),
    });
  } catch (err) {
    await sink.close();
    const e = err as NodeJS.ErrnoException;
    deps.io.error(e.code === "EADDRINUSE" ? `[otel] ${listen.host}:${listen.port} is already in use` : `[otel] ${e.message}`);
    return 1;
  }

  const where = `${listen.host.includes(":") ? `[${listen.host}]` : listen.host}:${receiver.port}`;
  deps.io.log(`[otel] receiving traces at http://${where}/v1/traces`);
  deps.io.log(
    token
      ? `[otel] a bearer token is required (${env[TOKEN_ENV] ? TOKEN_ENV : "see 'omnodex otel token'"})`
      : "[otel] no token set: any process on this machine can post spans. Run 'omnodex otel token' to require one.",
  );
  if (!isLoopbackHost(listen.host)) {
    deps.io.log("[otel] listening beyond this machine: put it behind TLS, the sender should reach it over https");
  }
  deps.io.log("[otel] writing the local event log. Ctrl+C to stop.");
  deps.onListening?.({ host: listen.host, port: receiver.port });

  await new Promise<void>((resolve) => {
    if (deps.signal?.aborted) resolve();
    else deps.signal?.addEventListener("abort", () => resolve(), { once: true });
  });
  deps.io.log("[otel] shutting down...");
  await receiver.close();
  const s = receiver.stats();
  deps.io.log(`[otel] ${s.requests} request(s), ${s.spans_received} span(s) received, ${s.events_written} event(s) and ${s.findings_written} finding(s) written`);
  return 0;
}
