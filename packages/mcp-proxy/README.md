# @omnodex/mcp-proxy

An MCP (Model Context Protocol) proxy that sits between any MCP-capable agent and
its upstream MCP servers. Intercepts tool calls, logs them to the local Omnodex
event log, and forwards them transparently to the upstream server.

Part of the [Omnodex](https://omnodex.com) local security monitoring pipeline.
Licensed under AGPL v3.

---

## What It Does

The proxy registers itself as a single MCP server in your agent's config. It
connects to your real MCP servers (filesystem, GitHub, Slack, etc.) in the
background, exposes their tools under prefixed names (`filesystem__read_file`,
`github__create_issue`), and logs every tool call as a `tool.invoked` /
`tool.completed` TraceEvent to the local event log.

```
Agent (Cowork / Codex / any MCP runtime)
  |
  | stdio MCP
  v
Omnodex MCP Proxy  ──[tool.invoked]──▶  Local event log
  |                ──[tool.completed]─▶  Local event log
  | stdio or Streamable HTTP (one connection per upstream)
  v
Your real MCP servers (local processes, or remote servers over HTTPS)
```

The agent sees one unified tool surface. Each real server is invisible to it
(and to you, until you look at the event log).

---

## What Is Logged

**This section matters.** The proxy is a full intermediary -- it sees everything
that passes between the agent and your MCP servers. Here is exactly what it does
and does not record.

| Data | Logged? | Notes |
|------|---------|-------|
| Tool name | ✅ Yes | e.g. `filesystem__read_file` |
| Tool call parameters | ✅ Yes (default) | File paths, queries, code snippets. See [Parameter redaction](#parameter-redaction). |
| Tool call result (content) | ❌ No | Only the byte size of the response is recorded. |
| Upstream server credentials | ❌ No | For stdio upstreams they are env vars inside the upstream process. For HTTP upstreams they come from env vars named in the config and are sent only as request headers; header values are never written to the event log, stderr or `omnodex_status`, and are scrubbed from error text. |
| MCP handshake messages | ❌ No | `initialize`, `initialized`, ping/pong. |
| `tools/list` responses | ❌ No | Tool discovery is not a security-relevant event. |
| Session start / end | ✅ Yes | Timestamp, the proxied upstream servers, and each one's transport. For HTTP upstreams only the URL host is recorded, never the path, query string or credentials. |
| Tool call duration | ✅ Yes | `duration_ms` in `tool.completed` events. |
| Error messages | ✅ Yes | When upstream returns an error response. |

**Where the log goes:** `$OMNODEX_HOME/event-log/` (default: `~/.omnodex/event-log/`).
The log is local-only. Nothing is sent to Omnodex servers.

### Parameter redaction

Parameters are logged by default. This is a deliberate choice: parameter values
are what security rules analyze (detecting credential patterns in file writes,
suspicious data in API calls). Disabling parameter logging silently disables
content-based rules for those servers.

To disable parameter logging for a server, set `redact_parameters: true` in
`omnodex-proxy.json`. Values are replaced with `[REDACTED]`; parameter keys are
preserved so tool-name-based rules still work.

```json
{
  "upstream_servers": [
    { "name": "filesystem", "transport": "stdio", "command": "npx", "args": ["..."] },
    { "name": "hr-api", "transport": "stdio", "command": "node", "args": ["..."],
      "redact_parameters": true }
  ]
}
```

You can also set `redact_parameters: true` at the top level to redact all servers.

---

## Installation

Install Omnodex from source (the current npm release does not include the proxy entry point):

```bash
git clone https://github.com/omnodex/omnodex.git
cd omnodex
npm install
npx tsc -b
```

The proxy entry point is `packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js`. Run it with Node.js, or through the CLI as `omnodex mcp-proxy start`.

### For Cowork or Codex

The Omnodex plugins start the proxy for you. Point them at your build with `proxy_bin` in `omnodex-proxy.json`:

```json
{
  "version": 1,
  "proxy_bin": "/path/to/omnodex/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js",
  "upstream_servers": [ ... ]
}
```

On Windows, use Windows paths with escaped backslashes. For Codex on any platform you can instead register the proxy directly, as in the manual setup below. Setup guides: [Cowork](https://docs.omnodex.com/guides/cowork/), [Codex](https://docs.omnodex.com/guides/codex/).

### Manual setup (any MCP-capable agent)

1. Add the proxy as an MCP server in your agent config:

```json
{
  "name": "omnodex",
  "command": "/absolute/path/to/node",
  "args": [
    "/path/to/omnodex/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js",
    "--config",
    "/home/<you>/.omnodex/omnodex-proxy.json"
  ]
}
```

Use absolute paths: desktop apps may not share your terminal's `PATH` or expand `~`.

2. Create `~/.omnodex/omnodex-proxy.json` with your upstream servers:

```json
{
  "version": 1,
  "redact_parameters": false,
  "upstream_servers": [
    {
      "name": "filesystem",
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/your/project"]
    },
    {
      "name": "github",
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "${GITHUB_TOKEN}" }
    }
  ]
}
```

3. Restart your agent. It will connect to the proxy, which connects to your
   upstream servers. Tool names become `filesystem__read_file`, `github__create_issue`, etc.
   Start a new conversation or task afterwards; existing ones may keep their old tool list.

---

## CLI Commands

```bash
# Start the proxy (agents spawn this automatically via MCP config;
# run manually to debug or verify upstream connections)
omnodex mcp-proxy start [--config <path>]

# Serve the proxy over Streamable HTTP at http://<host:port>/mcp, for hosts
# that connect to MCP servers by URL
omnodex mcp-proxy serve --http 127.0.0.1:8787 [--config <path>] [--allow-remote]

# Create a config template if none exists
omnodex mcp-proxy install

# Show configured upstream servers and their redaction status
omnodex mcp-proxy status
```

---

## Configuration Reference

Full schema for `omnodex-proxy.json`:

```json
{
  "version": 1,
  "redact_parameters": false,
  "upstream_servers": [
    {
      "name": "server-name",
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path"],
      "env": { "API_KEY": "${API_KEY}" },
      "redact_parameters": false,
      "name_override": "fs",
      "tool_timeout_sec": 60
    },
    {
      "name": "remote-server",
      "transport": "http",
      "url": "https://mcp.example.com/mcp",
      "bearer_token_env_var": "EXAMPLE_API_KEY",
      "http_headers": { "X-Workspace": "my-workspace" },
      "env_http_headers": { "X-Api-Key": "EXAMPLE_HEADER_KEY" }
    }
  ],
  "upstream_connection": {
    "discovery_window_ms": 15000,
    "connect_timeout_ms": 30000,
    "retry_initial_delay_ms": 1000,
    "retry_give_up_delay_ms": 180000
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | `1` | required | Config schema version |
| `redact_parameters` | boolean | `false` | Global default: replace all parameter values with `[REDACTED]` |
| `upstream_servers[].name` | string | required | Server identifier; used as tool name prefix |
| `upstream_servers[].transport` | `"stdio"` \| `"http"` | required | Connection type |
| `upstream_servers[].command` | string | required for stdio | Executable to spawn |
| `upstream_servers[].args` | string[] | `[]` | Arguments to pass to command |
| `upstream_servers[].env` | object | `{}` | Env vars; values support `${VAR}` interpolation |
| `upstream_servers[].redact_parameters` | boolean | inherits global | Per-server override |
| `upstream_servers[].name_override` | string | (none) | Use a shorter prefix instead of `name` |
| `upstream_servers[].tool_timeout_sec` | number | `60` | Limit for one tool call on this upstream |
| `upstream_servers[].url` | string | required for http | Streamable HTTP endpoint (`http` or `https`) |
| `upstream_servers[].bearer_token_env_var` | string | (none) | Env var holding a bearer token, sent as `Authorization: Bearer <token>`. Overrides any `Authorization` header from the two fields below. The upstream fails to connect if the variable is unset |
| `upstream_servers[].http_headers` | object | (none) | Static request headers. Not for secrets |
| `upstream_servers[].env_http_headers` | object | (none) | Headers read from env vars, as `{ "Header-Name": "ENV_VAR" }`. A header whose variable is unset is not sent |
| `upstream_connection.discovery_window_ms` | number | `15000` | Ceiling on how long the first `tools/list` waits for upstreams still connecting, from proxy start. See [Sizing the discovery window](#sizing-the-discovery-window) |
| `upstream_connection.connect_timeout_ms` | number | `30000` | Limit for one connection attempt (start plus tool listing) |
| `upstream_connection.retry_initial_delay_ms` | number | `1000` | First retry delay for a failed upstream; doubles on each retry |
| `upstream_connection.retry_give_up_delay_ms` | number | `180000` | Retries stop once the next delay would reach this |

`upstream_servers` may be empty or omitted; the proxy then serves only its built-in tools.

`${VAR}` in `env` values is resolved from the proxy's process environment. Secrets
stay out of the config file.

HTTP upstream keys match Codex's `config.toml` (`url`, `bearer_token_env_var`,
`http_headers`, `env_http_headers`, `tool_timeout_sec`), so entries can move between
the two. Credentials come from environment variables only. Desktop apps may not
inherit variables set in an interactive shell, so check that they reach the proxy:
an upstream whose `bearer_token_env_var` is unset reports that by name in
`omnodex_status`.

---

## Known Limitations

**Built-in tool blindness.** The proxy only sees MCP tool calls. Built-in agent
tools (read, write, edit, and shell tools in Cowork; `apply_patch` and shell commands
in Codex) are not routed through the MCP protocol and are invisible to the proxy. For
Codex, the hook integration records them separately. Cowork does not currently run
plugin hooks, so its built-in tools are not recorded.

**Additive coverage only.** The proxy observes only MCP servers explicitly routed
through it. MCP servers the agent connects to directly are not monitored.

**Late upstreams.** The proxy answers the agent right away and connects upstreams in
the background. Upstreams that connect after the discovery window are announced with
`notifications/tools/list_changed`; agents that ignore that notification see their tools
after a reconnect or a new conversation.

**HTTP upstreams.** Remote servers are supported over Streamable HTTP with bearer
tokens and headers from environment variables. OAuth sign-in for remote servers is
not supported yet; use a server's token-based endpoint where it has one. The legacy
HTTP+SSE transport is not supported.

### Serving over HTTP

`omnodex mcp-proxy serve --http <host:port>` (or `omnodex-mcp-proxy --http <host:port>`)
serves the proxy over Streamable HTTP at `/mcp` instead of stdin/stdout, and runs until
stopped. Each client session is its own proxy session, with its own `session.started`
and `session.ended` events; all sessions share one set of upstream connections.

- **Loopback only by default.** It binds to `127.0.0.1`, `localhost` or `::1`, and
  rejects requests whose `Host` is not a loopback name or whose `Origin` is not a
  loopback origin, so a web page cannot reach it through DNS rebinding.
- **Beyond loopback** requires `--allow-remote` and a token in
  `OMNODEX_PROXY_HTTP_TOKEN`; clients send it as `Authorization: Bearer <token>`. The
  proxy calls upstream tools with your credentials, so do not expose it without one.
  The token can also be set on loopback.

---

## Upstream Connections

Upstreams connect in parallel and independently. A slow, failing or crashed upstream
never affects the others or the built-in tools (`omnodex_status`, `omnodex_connect`,
`omnodex_connection_status`).

- **Discovery window.** The first `tools/list`, and any call to a tool the proxy does
  not know yet, waits up to `discovery_window_ms` from proxy start for upstreams still
  connecting. The wait ends as soon as every upstream has settled, so the setting is a
  ceiling, not a delay. See [Sizing the discovery window](#sizing-the-discovery-window).
- **Changes.** When an upstream connects or disconnects later, the proxy sends
  `notifications/tools/list_changed`. Claude Code acts on it and picks the tools up
  mid-session; the Codex clients and Cowork ignore it, so for those the discovery
  window is what matters.
- **Retries.** A failed or disconnected upstream is retried after
  `retry_initial_delay_ms`, doubling each time. Once the next delay would reach
  `retry_give_up_delay_ms` (with the defaults: 9 attempts over about 4 minutes), retries
  stop and the proxy logs a warning to stderr and to the agent as an MCP log message.
  An upstream that crashes within 30 seconds of connecting keeps counting toward that
  limit.
- **Calls to a down upstream** return an error saying the upstream is connecting, is
  retrying, or has stopped retrying, with its last error.
- **Rejected credentials.** An HTTP upstream that answers 401 or 403, while
  connecting or on a later call, moves to `needs_auth`, its tools are removed, and it
  is not retried on a timer, since only new credentials can fix it.
- **Lost sessions.** When a remote server no longer recognizes the session (HTTP 404),
  the proxy starts a new session and retries the call once.
- **Timeouts and cancellation.** Each tool call is limited to `tool_timeout_sec`
  (default 60). When the agent cancels a call, the proxy cancels it at the upstream.
- **Status.** `omnodex_status` reports each upstream's transport, state (`connecting`,
  `connected`, `failed`, `needs_auth`), last error, tool count, last attempt time and
  next retry. Call it with `retry_failed: true` to retry every failed or `needs_auth`
  upstream immediately with a fresh count, or restart the agent.

### Sizing the discovery window

Most agent clients read the tool list once, when they start the server. Measured
behavior with an upstream that connects 12s after start:

| Client | Picks up a late upstream in a running session |
| --- | --- |
| Claude Code | Yes, the tool list updates within seconds |
| ChatGPT Desktop (Codex mode) | No |
| Codex CLI | No |
| Cowork Desktop | No |

For the clients that answer no, an upstream connecting after the window is unusable
for the rest of that session, even though the proxy has it connected and
`omnodex_status` shows it. Restarting the agent does not help on its own, because the
proxy restarts with it and the upstream is slow again.

So the window has to cover your slowest upstream. To measure one, start the proxy by
hand and watch how long it takes:

```bash
node packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js --config ~/.omnodex/omnodex-proxy.json
```

Each upstream prints a line when it fails, and `omnodex_status` reports
`state` per upstream. Simpler: start your agent, ask it to call `omnodex_status`, and
look for any upstream still `connecting`, or any tool missing from the list. Then set
the window above that time:

```json
{ "upstream_connection": { "discovery_window_ms": 25000 } }
```

Rules of thumb:

- A local server started from an installed binary connects in well under a second.
- A first run of `npx -y` or `uvx` downloads the package: several seconds, occasionally
  tens of seconds on a slow network. Later runs are faster because the package is cached.
- A server that authenticates over the network on startup takes as long as that call.

**Raising it** costs nothing when upstreams are healthy, because the wait ends as soon
as they have all settled. It costs time only when one is slow or hanging: the agent's
first tool listing can block for up to the window. `initialize` is answered immediately
either way, so the agent still starts; Codex answered normally with a 12s first listing.

**Lowering it** makes that first listing quicker at the cost of dropping any upstream
that has not connected yet for the whole session. Use a low value only when every
upstream is a fast local process, or when you would rather the agent start with fewer
tools than wait.

`connect_timeout_ms` is a separate, longer limit on one connection attempt. An upstream
can still be connecting when the window closes; it is simply not in the first listing.

---

## Architecture

The proxy implements the `Interceptor` interface from `@omnodex/shared` and emits
the same `TraceEvent` wire format as all other Omnodex interceptors. The event log,
projector, analyzer, and dashboard are interceptor-agnostic: they handle proxy-sourced
events identically to hook-sourced events, distinguished only by the `interceptor: "mcp-proxy"`
field on each event.

The proxy is both an MCP server (accepts the agent over stdio, or clients over
Streamable HTTP) and an MCP client pool (maintains an outbound stdio or Streamable
HTTP connection to each upstream server).

Tool naming and routing (`src/core/tool-routing.ts`) and the events the proxy
records (`src/core/events.ts`) use no Node APIs, so a proxy on another runtime can
share them. A test enforces this. Tool names
from upstream servers are namespaced with a prefix (`filesystem__read_file`) to avoid
collisions and to make the `mcp_server` field in every TraceEvent unambiguous. The
separator is `__` because MCP clients only accept letters, digits, `_` and `-` in tool
names.

Tool definitions are otherwise passed through unchanged, with one normalization: a
`$schema` declaration naming a JSON Schema dialect other than 2020-12 (commonly
draft-07) is removed from `inputSchema` and `outputSchema`, because clients validate
tool schemas as 2020-12 and reject other dialects. Tool results are forwarded with both
`content` and `structuredContent`.

---

## Development

```bash
npm install
npm run build          # tsc -b
npm test               # unit + integration tests
```

Tests use Node's built-in test runner (`node:test`). Integration tests in
`test/upstream-client.test.mjs` spawn a real mock MCP server subprocess and verify end-to-end request routing, parameter logging, and error handling. `test/http-upstream.test.mjs` runs an in-process Streamable HTTP server to cover headers, bearer tokens, `needs_auth`, session loss, timeouts, cancellation and credential redaction.
