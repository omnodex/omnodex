// An MCP server behind OAuth, all on one local origin, for tests of the
// proxy's OAuth client: protected resource metadata, authorization server
// metadata, dynamic registration (or client ID metadata documents), the
// authorize and token endpoints with PKCE and refresh token rotation, and the
// MCP endpoint itself.
//
//   startOAuthMcpServer({ expiresIn, cimd }) returns:
//     url                  MCP endpoint URL
//     mcp                  the underlying helper (requests, dropSessions, ...)
//     registrations        client metadata received at /register
//     tokenRequests        form bodies received at /token
//     authorizeRequests    query parameters received at /authorize
//     approve(authUrl)     plays the browser: follows /authorize to the
//                          loopback redirect and returns that response status
//     revokeAccess()       makes the current access token stop working
//     revokeRefresh()      makes refresh tokens stop working
//     close()

import { createHash, randomBytes } from "node:crypto";
import { startHttpMcpServer } from "./http-mcp-server.mjs";

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

export async function startOAuthMcpServer(options = {}) {
  let expiresIn = options.expiresIn ?? 3600;
  const registrations = [];
  const tokenRequests = [];
  const authorizeRequests = [];
  const codes = new Map(); // code -> { challenge, redirectUri, clientId, resource }
  let refreshTokens = new Set();
  let origin = "";
  let counter = 0;
  let mcp;

  function issue(clientId) {
    counter += 1;
    const access = `access-${counter}-${randomBytes(6).toString("hex")}`;
    const refresh = `refresh-${counter}-${randomBytes(6).toString("hex")}`;
    refreshTokens.add(refresh);
    mcp.setToken(access);
    return { access_token: access, token_type: "Bearer", expires_in: expiresIn, refresh_token: refresh, scope: "read" };
  }

  async function routes(req, res) {
    const url = new URL(req.url, origin);
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      json(res, 200, { resource: `${origin}/mcp`, authorization_servers: [origin], scopes_supported: ["read"] });
      return true;
    }
    if (url.pathname.startsWith("/.well-known/oauth-authorization-server")) {
      json(res, 200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        registration_endpoint: `${origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        ...(options.cimd ? { client_id_metadata_document_supported: true } : {}),
      });
      return true;
    }
    if (url.pathname === "/register" && req.method === "POST") {
      const body = JSON.parse(await readBody(req));
      registrations.push(body);
      json(res, 201, { ...body, client_id: `client-${registrations.length}` });
      return true;
    }
    if (url.pathname === "/authorize") {
      const q = Object.fromEntries(url.searchParams);
      authorizeRequests.push(q);
      const code = randomBytes(8).toString("hex");
      codes.set(code, { challenge: q.code_challenge, redirectUri: q.redirect_uri, clientId: q.client_id, resource: q.resource });
      const back = new URL(q.redirect_uri);
      back.searchParams.set("code", code);
      if (q.state) back.searchParams.set("state", q.state);
      res.writeHead(302, { location: back.toString() }).end();
      return true;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      const form = Object.fromEntries(new URLSearchParams(await readBody(req)));
      tokenRequests.push(form);
      if (form.grant_type === "authorization_code") {
        const entry = codes.get(form.code);
        codes.delete(form.code);
        const verifierOk =
          entry && createHash("sha256").update(form.code_verifier ?? "").digest("base64url") === entry.challenge;
        if (!entry || !verifierOk || entry.redirectUri !== form.redirect_uri) {
          json(res, 400, { error: "invalid_grant", error_description: "bad code or verifier" });
        } else {
          json(res, 200, issue(entry.clientId));
        }
        return true;
      }
      if (form.grant_type === "refresh_token") {
        if (!refreshTokens.has(form.refresh_token)) {
          json(res, 400, { error: "invalid_grant", error_description: "refresh token revoked" });
        } else {
          refreshTokens.delete(form.refresh_token);
          json(res, 200, issue(form.client_id));
        }
        return true;
      }
      json(res, 400, { error: "unsupported_grant_type" });
      return true;
    }
    return false;
  }

  mcp = await startHttpMcpServer({ token: "no-token-issued-yet", extraRoutes: routes });
  origin = new URL(mcp.url).origin;

  return {
    url: mcp.url,
    mcp,
    registrations,
    tokenRequests,
    authorizeRequests,
    setExpiresIn(seconds) {
      expiresIn = seconds;
    },
    async approve(authUrl) {
      const redirect = await fetch(authUrl, { redirect: "manual" });
      const location = redirect.headers.get("location");
      const callback = await fetch(location);
      await callback.text();
      return callback.status;
    },
    revokeAccess() {
      mcp.setToken("revoked-" + randomBytes(4).toString("hex"));
    },
    revokeRefresh() {
      refreshTokens = new Set();
    },
    close: () => mcp.close(),
  };
}
