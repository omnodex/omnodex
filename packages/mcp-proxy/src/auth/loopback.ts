// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- auth/loopback
 *
 * A one-shot HTTP receiver on the loopback interface for the OAuth redirect.
 * It accepts exactly one callback carrying the expected state, answers the
 * browser with a short page, and hands the authorization code to the caller.
 * It binds 127.0.0.1 only, so nothing off this machine can reach it.
 */

import * as http from "node:http";
import type { AddressInfo } from "node:net";

export interface LoopbackReceiver {
  /** The redirect URI to register and send to the authorization server. */
  readonly redirectUrl: string;
  /** Resolves with the code; rejects on denial, timeout or close. */
  readonly code: Promise<string>;
  /** Sets the state the callback must carry. Required before the callback arrives. */
  expectState(state: string): void;
  close(): void;
}

export interface LoopbackOptions {
  /** Port to try first; falls back to any free port when it is busy. */
  preferredPort?: number;
  /** How long to wait for the callback. Default 10 minutes. */
  timeoutMs?: number;
  path?: string;
}

const PAGE = (title: string, body: string): string =>
  `<!doctype html><meta charset="utf-8"><title>${title}</title>` +
  `<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">` +
  `<h1>${title}</h1><p>${body}</p></body>`;

function listen(server: http.Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => reject(err);
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
}

export async function startLoopbackReceiver(options: LoopbackOptions = {}): Promise<LoopbackReceiver> {
  const callbackPath = options.path ?? "/callback";
  let expectedState: string | undefined;
  let settle: { resolve: (code: string) => void; reject: (err: Error) => void };
  const code = new Promise<string>((resolve, reject) => {
    settle = { resolve, reject };
  });
  // A caller that never awaits (the sign-in was abandoned) must not crash the process.
  code.catch(() => undefined);

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== callbackPath) {
      res.writeHead(404).end();
      return;
    }
    const state = url.searchParams.get("state");
    if (!expectedState || state !== expectedState) {
      res.writeHead(400, { "content-type": "text/html" }).end(PAGE("Sign-in failed", "This request did not match a sign-in started by Omnodex."));
      return;
    }
    const error = url.searchParams.get("error");
    const authCode = url.searchParams.get("code");
    if (error || !authCode) {
      res.writeHead(400, { "content-type": "text/html" }).end(PAGE("Sign-in was not completed", "You can close this tab and try again."));
      settle.reject(new Error(`authorization was not granted${error ? ` (${error})` : ""}`));
    } else {
      res.writeHead(200, { "content-type": "text/html" }).end(PAGE("Signed in", "You can close this tab and return to your agent."));
      settle.resolve(authCode);
    }
    close();
  });

  let timer: NodeJS.Timeout | undefined;
  function close(): void {
    clearTimeout(timer);
    server.close();
    server.closeAllConnections?.();
    settle.reject(new Error("sign-in receiver closed"));
  }

  try {
    await listen(server, options.preferredPort ?? 0);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EADDRINUSE" || !options.preferredPort) throw err;
    await listen(server, 0);
  }
  const { port } = server.address() as AddressInfo;
  timer = setTimeout(() => {
    settle.reject(new Error("timed out waiting for sign-in"));
    close();
  }, options.timeoutMs ?? 10 * 60_000);
  timer.unref();

  return {
    redirectUrl: `http://127.0.0.1:${port}${callbackPath}`,
    code,
    expectState(state: string) {
      expectedState = state;
    },
    close,
  };
}
