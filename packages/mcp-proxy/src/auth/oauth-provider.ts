// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy -- auth/oauth-provider
 *
 * The OAuth client for one remote upstream. It implements the MCP SDK's
 * OAuthClientProvider on top of a TokenStore; the SDK does the protocol work
 * (protected resource and authorization server discovery, PKCE with S256,
 * resource indicators, client registration, token exchange and refresh).
 *
 * Two modes:
 *   - background (the running proxy): never starts a sign-in. When the stored
 *     credentials can no longer be refreshed, the redirect the SDK asks for
 *     becomes an AuthorizationRequiredError, which the pool reports as
 *     needs_auth.
 *   - interactive (omnodex auth login, the omnodex_auth tool): hands the
 *     authorization URL to a callback instead of opening anything itself.
 */

import { randomBytes } from "node:crypto";
import type { OAuthClientProvider, OAuthDiscoveryState } from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { StoredTokens, TokenStore, UpstreamCredentials } from "./token-store.js";

/** Identifies Omnodex to authorization servers that accept URL-based client ids. */
export const DEFAULT_CLIENT_METADATA_URL = "https://omnodex.com/oauth/omnodex-client.json";

/** The loopback port tried first, so the published client metadata can list it. */
export const DEFAULT_CALLBACK_PORT = 47831;

/** Tokens this close to expiry are refreshed before use. */
export const REFRESH_MARGIN_MS = 60_000;

/**
 * The SDK needs a browser redirect and none is allowed (the proxy is running
 * in the background). Named like the SDK's own UnauthorizedError so existing
 * needs_auth handling recognizes it.
 */
export class AuthorizationRequiredError extends Error {
  constructor(message = "Sign-in is required") {
    super(message);
    this.name = "UnauthorizedError";
  }
}

export interface UpstreamOAuthProviderOptions {
  upstreamName: string;
  serverUrl: string;
  store: TokenStore;
  /** Where the authorization server sends the user back to. */
  redirectUrl: string;
  /** Called with the authorization URL; absent means background mode. */
  onAuthorizationUrl?: (url: URL) => void | Promise<void>;
  scope?: string;
  /** Overrides the Omnodex client metadata document URL. */
  clientMetadataUrl?: string;
  /** Pre-registered client id, used instead of metadata documents and registration. */
  clientId?: string;
  now?: () => number;
}

export class UpstreamOAuthProvider implements OAuthClientProvider {
  readonly clientMetadataUrl: string;
  private readonly opts: UpstreamOAuthProviderOptions;
  private readonly now: () => number;
  private verifier: string | undefined;
  private expectedState: string | undefined;
  private refreshing: Promise<boolean> | undefined;
  /** Serializes read-modify-write cycles on this upstream's record. */
  private chain: Promise<unknown> = Promise.resolve();

  constructor(opts: UpstreamOAuthProviderOptions) {
    this.opts = opts;
    this.now = opts.now ?? Date.now;
    this.clientMetadataUrl = opts.clientMetadataUrl ?? DEFAULT_CLIENT_METADATA_URL;
  }

  get redirectUrl(): string {
    return this.opts.redirectUrl;
  }

  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: "Omnodex",
      client_uri: "https://omnodex.com",
      redirect_uris: [this.opts.redirectUrl],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      ...(this.opts.scope ? { scope: this.opts.scope } : {}),
    };
  }

  /** The state value the callback must carry; set once a sign-in begins. */
  get pendingState(): string | undefined {
    return this.expectedState;
  }

  state(): string {
    this.expectedState = randomBytes(16).toString("base64url");
    return this.expectedState;
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    if (this.opts.clientId) return { client_id: this.opts.clientId };
    const record = await this.record();
    return record?.client_information as OAuthClientInformationMixed | undefined;
  }

  async saveClientInformation(info: OAuthClientInformationMixed): Promise<void> {
    await this.patch((r) => {
      r.client_information = info as unknown as Record<string, unknown>;
    });
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    const stored = (await this.record())?.tokens;
    if (!stored) return undefined;
    const { obtained_at: _obtainedAt, ...tokens } = stored;
    return tokens as OAuthTokens;
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    await this.patch((r) => {
      // A refresh response may omit the refresh token: keep the one we have.
      const previous = r.tokens?.refresh_token;
      const stored: StoredTokens = { ...(tokens as Omit<StoredTokens, "obtained_at">), obtained_at: this.now() };
      if (!stored.refresh_token && previous) stored.refresh_token = previous;
      r.tokens = stored;
    });
  }

  async redirectToAuthorization(url: URL): Promise<void> {
    if (!this.opts.onAuthorizationUrl) throw new AuthorizationRequiredError();
    await this.opts.onAuthorizationUrl(url);
  }

  saveCodeVerifier(verifier: string): void {
    this.verifier = verifier;
  }

  codeVerifier(): string {
    if (!this.verifier) throw new Error("No sign-in is in progress");
    return this.verifier;
  }

  async discoveryState(): Promise<OAuthDiscoveryState | undefined> {
    return (await this.record())?.discovery_state as OAuthDiscoveryState | undefined;
  }

  async saveDiscoveryState(state: OAuthDiscoveryState): Promise<void> {
    await this.patch((r) => {
      r.discovery_state = state as unknown as Record<string, unknown>;
    });
  }

  async invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier" | "discovery"): Promise<void> {
    if (scope === "verifier") {
      this.verifier = undefined;
      return;
    }
    await this.patch((r) => {
      if (scope === "all" || scope === "tokens") delete r.tokens;
      if (scope === "all" || scope === "client") delete r.client_information;
      if (scope === "all" || scope === "discovery") delete r.discovery_state;
    });
  }

  /** True when credentials are stored, so the SDK may refresh them on a 401. */
  async hasCredentials(): Promise<boolean> {
    return (await this.record())?.tokens !== undefined;
  }

  /** True when the access token is expired or about to be, and a refresh token exists. */
  async needsRefresh(): Promise<boolean> {
    const tokens = (await this.record())?.tokens;
    if (!tokens?.refresh_token || tokens.expires_in === undefined) return false;
    return this.now() >= tokens.obtained_at + tokens.expires_in * 1000 - REFRESH_MARGIN_MS;
  }

  /**
   * Refreshes the access token now if it is near expiry. Concurrent callers
   * share one request. Resolves false when a refresh was needed and failed
   * because the user must sign in again.
   */
  refreshIfExpiring(refresh: () => Promise<"AUTHORIZED" | "REDIRECT">): Promise<boolean> {
    this.refreshing ??= (async () => {
      try {
        if (!(await this.needsRefresh())) return true;
        return (await refresh()) === "AUTHORIZED";
      } catch (err) {
        if (err instanceof AuthorizationRequiredError) return false;
        throw err;
      } finally {
        this.refreshing = undefined;
      }
    })();
    return this.refreshing;
  }

  private async record(): Promise<UpstreamCredentials | undefined> {
    await this.chain;
    return this.opts.store.get(this.opts.upstreamName, this.opts.serverUrl);
  }

  private patch(change: (record: UpstreamCredentials) => void): Promise<void> {
    const run = this.chain.then(async () => {
      const record =
        (await this.opts.store.get(this.opts.upstreamName, this.opts.serverUrl)) ??
        ({ url: this.opts.serverUrl } as UpstreamCredentials);
      change(record);
      await this.opts.store.put(this.opts.upstreamName, record);
    });
    this.chain = run.catch(() => undefined);
    return run;
  }
}
