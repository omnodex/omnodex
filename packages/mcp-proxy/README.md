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
background, exposes their tools under prefixed names (`filesystem/read_file`,
`github/create_issue`), and logs every tool call as a `tool.invoked` /
`tool.completed` TraceEvent to the local event log.

```
Agent (Cowork / Codex / any MCP runtime)
  |
  | stdio MCP
  v
Omnodex MCP Proxy  ──[tool.invoked]──▶  Local event log
  |                ──[tool.completed]─▶  Local event log
  | stdio MCP (one connection per upstream)
  v
Your real MCP servers (filesystem, github, slack, ...)
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
| Tool name | ✅ Yes | e.g. `filesystem/read_file` |
| Tool call parameters | ✅ Yes (default) | File paths, queries, code snippets. See [Parameter redaction](#parameter-redaction). |
| Tool call result (content) | ❌ No | Only the byte size of the response is recorded. |
| Upstream server credentials | ❌ No | API keys and tokens are env vars inside the upstream process -- they never appear in MCP protocol messages. |
| MCP handshake messages | ❌ No | `initialize`, `initialized`, ping/pong. |
| `tools/list` responses | ❌ No | Tool discovery is not a security-relevant event. |
| Session start / end | ✅ Yes | Timestamp and list of proxied upstream servers. |
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

```bash
npm install -g @omnodex/cli
```

This installs the `omnodex` CLI and the `omnodex-mcp-proxy` binary.

### For Cowork Desktop or Codex

Install the plugin bundle (one-click, no terminal required):

- **Cowork:** install `omnodex-cowork.plugin` from [omnodex.com/download](https://omnodex.com/download)
- **Codex:** install `omnodex-codex.plugin` from the same page

Then follow the in-app setup prompt, or run:

```bash
omnodex mcp-proxy install --platform cowork   # or --platform codex
```

### Manual setup (any MCP-capable agent)

1. Add the proxy as an MCP server in your agent config:

```json
{
  "name": "omnodex",
  "command": "omnodex-mcp-proxy",
  "args": ["--config", "~/.omnodex/omnodex-proxy.json"]
}
```

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
   upstream servers. Tool names become `filesystem/read_file`, `github/create_issue`, etc.

---

## CLI Commands

```bash
# Start the proxy (agents spawn this automatically via MCP config;
# run manually to debug or verify upstream connections)
omnodex mcp-proxy start [--config <path>]

# Print setup instructions and create a config template
omnodex mcp-proxy install [--platform cowork|codex|generic]

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
      "name_override": "fs"
    }
  ]
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
| `upstream_servers[].name_override` | string | — | Use a shorter prefix instead of `name` |

`${VAR}` in `env` values is resolved from the proxy's process environment. Secrets
stay out of the config file.

---

## Known Limitations

**Built-in tool blindness.** The proxy only sees MCP tool calls. Built-in agent
tools (Read, Write, Edit, Bash, Glob, Grep in Cowork; apply_patch in Codex) are not
routed through the MCP protocol and are therefore invisible to the proxy. For Codex,
the hook-based CodexInterceptor covers built-ins separately. For Cowork, this gap
will close when plugin hook delivery is fixed.

**Additive coverage only (v0.5).** The proxy observes only MCP servers explicitly
routed through it. MCPs the agent connects to directly are not monitored. A future
auto-injection installer (`omnodex mcp-proxy install`) will migrate existing direct
connections to route through the proxy.

**HTTP upstream transport.** The `transport: "http"` config field is accepted by
the schema but not yet implemented. Stdio covers all common local MCP servers.
HTTP support is planned for a future release.

---

## Architecture

The proxy implements the `Interceptor` interface from `@omnodex/shared` and emits
the same `TraceEvent` wire format as all other Omnodex interceptors. The event log,
projector, analyzer, and dashboard are interceptor-agnostic — they handle proxy-sourced
events identically to hook-sourced events, distinguished only by the `interceptor: "mcp-proxy"`
field on each event.

The proxy is both an MCP server (accepts inbound stdio from the agent) and an MCP
client pool (maintains outbound stdio connections to each upstream server). Tool names
from upstream servers are namespaced with a prefix (`filesystem/read_file`) to avoid
collisions and to make the `mcp_server` field in every TraceEvent unambiguous.

---

## Development

```bash
npm install
npm run build          # tsc -b
npm test               # 49 unit + integration tests
```

Tests use Node's built-in test runner (`node:test`). Integration tests in
`test/upstream-client.test.mjs` spawn a real mock MCP server subprocess and verify end-to-end request routing, parameter logging, and error handling.
