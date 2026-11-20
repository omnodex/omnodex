// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- auth/background
 *
 * What the running proxy uses for an OAuth upstream: the stored credentials,
 * refreshed ahead of expiry, with no ability to start a sign-in.
 */

import type { HttpUpstream } from "../config.js";
import { oauthSettings } from "../config.js";
import { AuthorizationRequiredError, UpstreamOAuthProvider } from "./oauth-provider.js";
import { DEFAULT_CALLBACK_PORT } from "./oauth-provider.js";
import type { TokenStore } from "./token-store.js";

export interface UpstreamAuth {
  provider: UpstreamOAuthProvider;
  /** Refreshes tokens that are expired or about to be. False: the user must sign in again. */
  ensureFresh(): Promise<boolean>;
}

/** The background auth for an upstream, or undefined when it does not use OAuth. */
export function createUpstreamAuth(server: HttpUpstream, store: TokenStore): UpstreamAuth | undefined {
  const settings = oauthSettings(server);
  if (!settings) return undefined;
  const provider = new UpstreamOAuthProvider({
    upstreamName: server.name,
    serverUrl: server.url,
    store,
    redirectUrl: `http://127.0.0.1:${settings.callback_port ?? DEFAULT_CALLBACK_PORT}/callback`,
    ...(settings.scope ? { scope: settings.scope } : {}),
    ...(settings.client_id ? { clientId: settings.client_id } : {}),
    ...(settings.client_metadata_url ? { clientMetadataUrl: settings.client_metadata_url } : {}),
  });
  return {
    provider,
    async ensureFresh() {
      const { auth } = await import("@modelcontextprotocol/sdk/client/auth.js");
      return provider.refreshIfExpiring(() => auth(provider, { serverUrl: server.url }));
    },
  };
}

export { AuthorizationRequiredError };
