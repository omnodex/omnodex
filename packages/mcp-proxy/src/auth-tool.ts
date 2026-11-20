// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General Public
// License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- auth-tool
 *
 * Built-in omnodex_auth tool. For an upstream that needs sign-in it returns a
 * URL for the user to open; the proxy finishes the sign-in itself when the
 * browser comes back, stores the tokens, and reconnects the upstream, so the
 * host needs no restart. The tool never returns or logs tokens.
 */

import type { UpstreamClientPool } from "./upstream-client.js";

export const AUTH_TOOL = {
  name: "omnodex_auth",
  description:
    "Signs the user in to a remote MCP server that needs authorization " +
    "(state needs_auth in omnodex_status). Returns a sign-in URL: ask the user " +
    "to open it in a browser on this machine. When they finish, the server " +
    "connects by itself; check omnodex_status. Omit upstream when exactly one " +
    "server needs sign-in.",
  inputSchema: {
    type: "object" as const,
    properties: {
      upstream: {
        type: "string",
        description: "Name of the upstream server, as shown in omnodex_status",
      },
    },
  },
};

export interface AuthToolResult {
  status: "sign_in_url" | "already_connected" | "not_oauth" | "unknown_upstream" | "nothing_to_sign_in" | "choose_upstream" | "error";
  upstream?: string;
  url?: string;
  upstreams?: string[];
  message: string;
}

export async function handleAuth(
  args: Record<string, unknown>,
  pool: UpstreamClientPool
): Promise<AuthToolResult> {
  let name = typeof args.upstream === "string" ? args.upstream : undefined;
  if (!name) {
    const waiting = pool
      .getUpstreamStatuses()
      .filter((u) => u.state === "needs_auth")
      .map((u) => u.name);
    if (waiting.length === 0) {
      return { status: "nothing_to_sign_in", message: "No upstream server needs sign-in right now." };
    }
    if (waiting.length > 1) {
      return {
        status: "choose_upstream",
        upstreams: waiting,
        message: "Several servers need sign-in. Call omnodex_auth again with upstream set to one of them.",
      };
    }
    name = waiting[0];
  }
  const result = await pool.signIn(name);
  if (result.status === "sign_in_url") {
    return {
      status: "sign_in_url",
      upstream: result.upstream,
      url: result.url,
      message:
        `Ask the user to open this URL in a browser on this machine and sign in to "${result.upstream}". ` +
        "The server connects automatically afterwards; check omnodex_status.",
    };
  }
  return { status: result.status, upstream: result.upstream, message: result.message };
}
