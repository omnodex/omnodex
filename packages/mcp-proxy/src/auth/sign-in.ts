// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- auth/sign-in
 *
 * The interactive half of upstream OAuth, shared by `omnodex auth login` and
 * the omnodex_auth tool: start a loopback receiver, ask the SDK to discover
 * the upstream's authorization server and build the authorization URL, then
 * exchange the code that comes back and store the tokens.
 *
 * beginSignIn returns as soon as the URL exists. The caller shows it to the
 * user (the CLI also opens a browser) and waits on `completed`, or lets it
 * finish in the background.
 */

import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { startLoopbackReceiver } from "./loopback.js";
import { DEFAULT_CALLBACK_PORT, UpstreamOAuthProvider } from "./oauth-provider.js";
import type { TokenStore } from "./token-store.js";

export interface SignInOptions {
  upstreamName: string;
  serverUrl: string;
  store: TokenStore;
  scope?: string;
  clientId?: string;
  clientMetadataUrl?: string;
  callbackPort?: number;
  /** How long to wait for the user. Default 10 minutes. */
  timeoutMs?: number;
  fetchFn?: FetchLike;
}

export interface SignInSession {
  /** Where the user signs in. Contains no credentials. */
  readonly authorizationUrl: string;
  /** Resolves once tokens are stored; rejects on denial, timeout or cancel. */
  readonly completed: Promise<void>;
  cancel(): void;
}

export async function beginSignIn(options: SignInOptions): Promise<SignInSession> {
  const { auth } = await import("@modelcontextprotocol/sdk/client/auth.js");
  const receiver = await startLoopbackReceiver({
    preferredPort: options.callbackPort ?? DEFAULT_CALLBACK_PORT,
    ...(options.timeoutMs ? { timeoutMs: options.timeoutMs } : {}),
  });

  try {
    let authorizationUrl: URL | undefined;
    const provider = new UpstreamOAuthProvider({
      upstreamName: options.upstreamName,
      serverUrl: options.serverUrl,
      store: options.store,
      redirectUrl: receiver.redirectUrl,
      onAuthorizationUrl: (url) => {
        authorizationUrl = url;
      },
      ...(options.scope ? { scope: options.scope } : {}),
      ...(options.clientId ? { clientId: options.clientId } : {}),
      ...(options.clientMetadataUrl ? { clientMetadataUrl: options.clientMetadataUrl } : {}),
    });

    // A new sign-in starts from scratch: old tokens are dropped, and a client
    // registered with a different redirect address cannot be reused.
    const existing = await options.store.get(options.upstreamName, options.serverUrl);
    const registered = existing?.client_information?.redirect_uris;
    if (Array.isArray(registered) && !registered.includes(receiver.redirectUrl)) {
      await provider.invalidateCredentials("client");
    }
    await provider.invalidateCredentials("tokens");

    const fetchOption = options.fetchFn ? { fetchFn: options.fetchFn } : {};
    const first = await auth(provider, {
      serverUrl: options.serverUrl,
      ...(options.scope ? { scope: options.scope } : {}),
      ...fetchOption,
    });
    if (first === "AUTHORIZED" || !authorizationUrl) {
      throw new Error("the authorization server did not ask the user to sign in");
    }
    const state = provider.pendingState;
    if (state) receiver.expectState(state);

    const completed = receiver.code
      .then(async (code) => {
        await auth(provider, { serverUrl: options.serverUrl, authorizationCode: code, ...fetchOption });
      })
      .finally(() => receiver.close());
    completed.catch(() => undefined);

    return { authorizationUrl: authorizationUrl.toString(), completed, cancel: () => receiver.close() };
  } catch (err) {
    receiver.close();
    throw err;
  }
}
