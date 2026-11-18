// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * `omnodex auth login|status|logout <upstream>`: OAuth sign-in for the
 * remote MCP servers in omnodex-proxy.json.
 *
 *   login   discover the server's authorization server, open a browser, and
 *           store the tokens that come back
 *   status  show, for each remote server that can use OAuth, whether this
 *           machine is signed in and when access expires
 *   logout  forget the stored sign-in
 *
 * Tokens are never printed. The running proxy picks a new sign-in up when
 * the upstream is retried (omnodex_status with retry_failed: true), or at
 * the next start.
 */

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import {
  oauthSettings,
  type HttpUpstream,
  type ProxyConfig,
  type SignInOptions,
  type SignInSession,
  type TokenStore,
} from "@omnodex/mcp-proxy";
import type { ControlIo } from "./capture-controls.js";

export interface AuthDeps {
  io: ControlIo;
  store: TokenStore;
  loadConfig: () => Promise<ProxyConfig>;
  beginSignIn: (options: SignInOptions) => Promise<SignInSession>;
  openBrowser: (url: string) => void;
  now?: () => number;
}

const USAGE = "omnodex auth login <upstream> | status | logout <upstream>";

function oauthUpstreams(config: ProxyConfig): HttpUpstream[] {
  return config.upstream_servers.filter(
    (s): s is HttpUpstream => s.transport === "http" && oauthSettings(s) !== undefined
  );
}

/** Opens a URL in the default browser, best effort. The caller always prints it too. */
export function openBrowser(url: string): void {
  let command: string;
  let args: string[];
  const isWsl = process.platform === "linux" && /microsoft/i.test(safeRead("/proc/version"));
  if (process.platform === "darwin") {
    [command, args] = ["open", [url]];
  } else if (process.platform === "win32") {
    [command, args] = ["rundll32", ["url.dll,FileProtocolHandler", url]];
  } else if (isWsl) {
    [command, args] = ["powershell.exe", ["-NoProfile", "-Command", `Start-Process '${url.replace(/'/g, "''")}'`]];
  } else {
    [command, args] = ["xdg-open", [url]];
  }
  try {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.on("error", () => undefined);
    child.unref();
  } catch {
    // The URL has been printed.
  }
}

function safeRead(file: string): string {
  try {
    return readFileSync(file, "utf8");
  } catch {
    return "";
  }
}

function describeExpiry(expiresAt: number, now: number, canRefresh: boolean): string {
  const seconds = Math.round((expiresAt - now) / 1000);
  if (seconds <= 0) return canRefresh ? "access expired, refreshes on next use" : "access expired";
  const minutes = Math.round(seconds / 60);
  const span = minutes < 90 ? `${Math.max(1, minutes)} min` : `${Math.round(minutes / 60)} h`;
  return `access expires in ${span}${canRefresh ? ", refreshes automatically" : ""}`;
}

export async function runAuth(args: string[], deps: AuthDeps): Promise<number> {
  const { io, store } = deps;
  const [sub, name] = args.filter((a) => !a.startsWith("--"));
  const noBrowser = args.includes("--no-browser");
  const now = (deps.now ?? Date.now)();

  if (sub !== "login" && sub !== "status" && sub !== "logout") {
    io.error(`usage: ${USAGE}`);
    return 1;
  }

  const config = await deps.loadConfig().catch((err: unknown) => {
    io.error(`[auth] ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  });
  if (!config) return 1;
  const upstreams = oauthUpstreams(config);

  if (sub === "status") {
    if (upstreams.length === 0) {
      io.log("[auth] no remote upstream in omnodex-proxy.json uses OAuth sign-in.");
      return 0;
    }
    for (const server of upstreams) {
      const record = await store.get(server.name, server.url);
      const tokens = record?.tokens;
      if (!tokens) {
        io.log(`${server.name}: not signed in (run: omnodex auth login ${server.name})`);
      } else if (tokens.expires_in === undefined) {
        io.log(`${server.name}: signed in${tokens.refresh_token ? ", refreshes automatically" : ""}`);
      } else {
        const expiresAt = tokens.obtained_at + tokens.expires_in * 1000;
        io.log(`${server.name}: signed in, ${describeExpiry(expiresAt, now, Boolean(tokens.refresh_token))}`);
      }
    }
    return 0;
  }

  if (!name) {
    io.error(`usage: ${USAGE}`);
    return 1;
  }
  const server = upstreams.find((s) => s.name === name);
  if (!server) {
    const known = upstreams.map((s) => s.name);
    io.error(
      `[auth] no upstream named '${name}' uses OAuth sign-in in omnodex-proxy.json` +
        (known.length > 0 ? ` (available: ${known.join(", ")})` : "") +
        "."
    );
    return 1;
  }

  if (sub === "logout") {
    const existed = await store.delete(server.name);
    io.log(
      existed
        ? `[auth] signed out of ${server.name}. The server may keep the grant until it expires; revoke it in the server's settings if you want it gone now.`
        : `[auth] ${server.name} was not signed in.`
    );
    return 0;
  }

  const settings = oauthSettings(server) ?? {};
  let session: SignInSession;
  try {
    session = await deps.beginSignIn({
      upstreamName: server.name,
      serverUrl: server.url,
      store,
      ...(settings.scope ? { scope: settings.scope } : {}),
      ...(settings.client_id ? { clientId: settings.client_id } : {}),
      ...(settings.client_metadata_url ? { clientMetadataUrl: settings.client_metadata_url } : {}),
      ...(settings.callback_port ? { callbackPort: settings.callback_port } : {}),
    });
  } catch (err) {
    io.error(`[auth] could not start sign-in for ${server.name}: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  io.log(`[auth] sign in to ${server.name} in your browser. If it does not open, visit:`);
  io.log(session.authorizationUrl);
  if (!noBrowser) deps.openBrowser(session.authorizationUrl);
  try {
    await session.completed;
  } catch (err) {
    io.error(`[auth] sign-in did not finish: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
  io.log(
    `[auth] signed in to ${server.name}. A running proxy picks it up on its next retry ` +
      "(call omnodex_status with retry_failed: true), or at the next start."
  );
  return 0;
}
