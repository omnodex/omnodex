# Omnodex

[![CI](https://github.com/omnodex/omnodex/actions/workflows/ci.yml/badge.svg)](https://github.com/omnodex/omnodex/actions/workflows/ci.yml)

**Security and observability for AI agent execution.** Omnodex captures every tool call, credential use, file access, and third-party connection made by an AI agent - and surfaces it for human review.

Core pipeline: **Intercept -> Trace -> Analyze -> Report.** Zero token overhead to the agent session.

Full documentation: [docs.omnodex.com](https://docs.omnodex.com/)

---

## Install

Omnodex runs on the host where your agent runs. Install from source; the current npm release (0.2.0) does not include the hook handlers or MCP proxy that the integrations load at runtime.

```bash
git clone https://github.com/omnodex/omnodex.git
cd omnodex
npm install
npx tsc -b
npm install -g ./packages/cli     # links the omnodex command to this build
```

Requires Node.js 24 or newer. On Windows, run these in PowerShell for agents that run natively on Windows (Cowork, ChatGPT Desktop), and in WSL for agents you run inside WSL. Native Windows and WSL are separate hosts with separate Omnodex data.

Hooks find their handlers through `omnodex-config.json` in the Omnodex home (`~/.omnodex`, or `C:\Users\<you>\.omnodex` on Windows):

```json
{
  "shim_paths": {
    "claude-code": "/path/to/omnodex/packages/hooks-provider/dist/bin/claude-hook-shim.js",
    "codex": "/path/to/omnodex/packages/codex-provider/dist/bin/codex-hook-shim.js",
    "antigravity": "/path/to/omnodex/packages/antigravity-provider/dist/bin/antigravity-hook-shim.js"
  }
}
```

Full setup guides: [docs.omnodex.com](https://docs.omnodex.com/getting-started/installation/)

---

## Integrations

| Agent | Mechanism | Setup |
| --- | --- | --- |
| Claude Code (CLI and IDE extensions) | Hooks | `omnodex install claude-code` in the project |
| OpenAI Codex (ChatGPT Desktop, CLI, IDE) | Hooks, plus the Omnodex MCP server | `omnodex install codex` in the project, and register the MCP server in Codex |
| Cowork | MCP proxy via the Omnodex plugin | Plugin plus `omnodex-proxy.json` with `proxy_bin` |
| Google Antigravity (CLI, Desktop, IDE) | Hooks, optionally the MCP proxy | `omnodex install antigravity [--mcp]` in the project |
| Any other MCP client | MCP proxy | Point the client at the proxy |

### Claude Code

```bash
cd /your/project
omnodex install claude-code
```

Writes hook entries to `.claude/settings.local.json` (or `.claude/settings.json` with `--project-settings`). Start a new Claude Code session afterwards; hooks load at session start. The CLI and the IDE extensions both read these project settings.

Hooks record session lifecycle, every tool call (built-in and MCP) with parameters, timing, and status, and `file.read` / `file.written` events for Claude Code's file tools. They run outside the agent's context window, with zero token overhead.

To remove: `omnodex uninstall claude-code --confirm`.

### OpenAI Codex

Two independent parts:

1. **Hooks**, per project:

   ```bash
   cd /your/project
   omnodex install codex
   ```

   Writes `.codex/hooks.json`. Hooks are enabled by default in Codex; no feature flag is needed. Trust the Omnodex hooks when Codex asks. Local hooks record session lifecycle and local Bash/unified-exec, `apply_patch`, MCP, and function calls. Successful `apply_patch` calls also produce `file.written` events for paths present in the patch.

2. **The Omnodex MCP server**, once per host. `omnodex install codex` does not register it. In ChatGPT Desktop use **Settings > MCP servers > Add server** (STDIO), or from the CLI:

   ```bash
   codex mcp add omnodex -- /absolute/path/to/node /path/to/omnodex/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js --config ~/.omnodex/omnodex-proxy.json
   ```

   Use the absolute path of the config file on hosts where `~` is not expanded. The Desktop app, CLI, and IDE extension share this entry when they run on the same host. On native Windows, use Windows paths.

Hosted tools such as web search run on OpenAI's side and are not visible to local hooks.

### Cowork

Install the `omnodex-cowork` plugin, then create `~/.omnodex/omnodex-proxy.json` (on Windows, `C:\Users\<you>\.omnodex\omnodex-proxy.json`) with `proxy_bin` pointing at `packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js` in your build and at least one upstream MCP server. Fully quit and reopen Cowork.

The proxy records calls to the MCP servers routed through it. Cowork's built-in tools are not recorded: Cowork does not currently run plugin hooks.

### Google Antigravity

```bash
cd /your/project
omnodex install antigravity           # hooks
omnodex install antigravity --mcp     # MCP proxy
```

Writes `.agents/hooks.json` and, with `--mcp`, `.agents/mcp_config.json`. The CLI (`agy`), Desktop App, and Antigravity IDE share this configuration.

### MCP proxy

For any MCP-capable agent, the proxy sits between the agent and its upstream MCP servers and records every call:

```bash
omnodex mcp-proxy install    # create a config template in the Omnodex home
omnodex mcp-proxy status     # show configured upstreams
omnodex mcp-proxy start      # run the proxy on stdin/stdout
```

Upstream tools are exposed as `<server>__<tool>`, for example `filesystem__read_file`. See [packages/mcp-proxy](packages/mcp-proxy/README.md) for the configuration reference and exactly what is logged.

### Dashboards

```bash
omnodex dashboard            # http://localhost:7890
```

The local dashboard shows a connection graph, credential ledger, risk events, and an event timeline, updated in real time. To include another host's data (for example the Windows home from WSL), add it with `--roots /mnt/c/Users/<you>/.omnodex` or `dashboard.roots` in `~/.omnodex/config.json`.

To use the hosted dashboard at `dashboard.omnodex.com`, run `omnodex connect` on each host. It starts a device code flow and stores an API token and a generated sync passphrase; events are encrypted end-to-end (AES-256-GCM) before they leave the machine. Each host appears as its own machine; set `machine.label` in `config.json` for a readable name.

---

## Quick start (mock pipeline)

To explore Omnodex without connecting to a live agent:

```bash
npm install
npx tsc -b

# Run a simulated session through the full pipeline
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js spike

# Detect risks in the captured events
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js detect

# Launch the dashboard
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js dashboard
# open http://localhost:7890
```

All data lives under `OMNODEX_HOME` (defaults to `~/.omnodex`).

---

## CLI reference

```
omnodex install <target> [project]  install hooks for an AI agent platform
                                      targets: claude-code, codex, antigravity
                                      --debug               verbose shim logging
                                      --project-settings    (claude-code) edit
                                                            settings.json instead
                                      --hooks, --mcp        (antigravity) hooks and/or
                                                            the MCP proxy
omnodex uninstall [target] [project] remove Omnodex hooks (requires --confirm)
omnodex status [project]            show which hooks are installed
                                      --all                 full installation registry
                                                            with stale install warnings
omnodex update                      self-update (npm: npm update -g; source: git pull
                                      --ff-only + npm install + npm run build)
                                      --check               dry-run, show available updates
                                      --refresh-launchers   rewrite hook launchers only
omnodex --version, -V               show version (source installs show branch + sha)

omnodex connect [--token <token>]   connect this host to your dashboard account.
  [--passphrase <phrase>]             Without a stored token: starts a device code flow
  [--platform <name>] [--api <url>]   (displays a code + URL, polls for authorization).
                                      With a token: prints a one-time connection link.
                                      Generates a sync passphrase on first run; the
                                      passphrase is transferred end-to-end encrypted.
omnodex sync                        encrypt the read model and upload it to the cloud.
                                      Connected hosts also sync automatically in the
                                      background when a hooked session ends (at most
                                      once a minute). Turn off with "auto_sync": false
                                      in stream-config.json or OMNODEX_AUTO_SYNC=0.

omnodex mcp-proxy <subcommand>      manage the MCP proxy interceptor
                                      install   generate proxy config template
                                      status    inspect the current config
                                      start     start the proxy server

omnodex spike [name]                run a simulated session through the full pipeline
omnodex detect [session]            scan event log for risks (all sessions if omitted).
                                      Hooks and the MCP proxy also run detection in the
                                      background, with or without a connected dashboard:
                                      when a session ends, and at least every 15 minutes
                                      while one runs. Turn off with OMNODEX_AUTO_DETECT=0.
                                      The MCP proxy also judges each call as it records it
                                      (off the response path); OMNODEX_CAPTURE_DETECT=0
                                      turns that off.
omnodex replay                      rebuild the SQLite read model from the event log
omnodex report                      print a session summary
omnodex dashboard [port]            start the local dashboard (default port 7890)
                                      --roots <path> [path...]  additional OMNODEX_HOME
                                                                roots to tail
                                      --no-detect   skip the historical detection pass
omnodex clear <session-id>          remove one session
omnodex clear --all --confirm       delete the entire Omnodex home (events, config,
                                      and cloud connection)
omnodex license [clear]             show license tier, or clear the cached license
```

---

## Architecture

1. **Event-log-first storage.** The source of truth is an append-only JSONL event log under `$OMNODEX_HOME/event-log/sessions/`. SQLite is a derived read model rebuilt by replaying the log. The dashboard supports tailing multiple roots simultaneously for multi-source aggregation.
2. **Async by design.** Interceptors append to the event log and exit. They never block the agent's execution path. The projector and analyzer run asynchronously and are allowed to lag.
3. **Single `Interceptor` interface.** Every interception source implements the same contract in `@omnodex/shared`. Five implementations are complete: `ClaudeCodeInterceptor`, `CodexInterceptor`, `AntigravityInterceptor`, `MCPProxy`, and `MockInterceptor`. Additional interceptors drop in without touching anything downstream.
4. **Zero token overhead.** The hook-based architecture runs out-of-band from the agent's context window. No interception approach that consumes the customer's tokens is acceptable.

---

## Tests

```bash
# All packages
node --test \
  packages/event-log/test/*.test.mjs \
  packages/projection/test/*.test.mjs \
  packages/hooks-provider/test/*.test.mjs \
  packages/codex-provider/test/*.test.mjs \
  packages/antigravity-provider/test/*.test.mjs \
  packages/cli/test/*.test.mjs \
  packages/analyzer/test/**/*.test.mjs \
  packages/analyzer/test/*.test.mjs \
  packages/sync-encryptor/test/*.test.mjs \
  packages/feature-extractor/test/*.test.mjs \
  packages/license-client/test/*.test.mjs \
  packages/mcp-proxy/test/*.test.mjs

# Single package
cd packages/codex-provider && node --test test/**/*.test.mjs
```

One pre-existing timing flake in the CLI streaming suite (`tailSession`) that only manifests in the combined run due to resource contention - it passes reliably when run in isolation.

---

## Known limitations

- **npm release** - The published npm package (0.2.0) does not include the hook handlers or the MCP proxy entry point, so hooks installed from it record nothing and the Cowork and Codex plugins cannot start the proxy. Install from source.
- **Codex hook outcomes** - Hosted tools such as web search are not visible to local hooks. Codex currently provides no failure hook. Some failed calls emit only `PreToolUse`, and nonzero Bash responses omit the exit code, so Omnodex records only statuses that the hook payload proves instead of inferring an error.
- **Cowork built-in tools** - Cowork does not run plugin-contributed hooks ([#27398](https://github.com/anthropics/claude-code/issues/27398), [#40495](https://github.com/anthropics/claude-code/issues/40495)), so only MCP tool calls routed through the proxy are recorded.
- **One host's hooks per project folder** - Hook commands contain the installing host's paths. Installing from native Windows and from WSL in the same project folder replaces the other host's hooks.
- **MCP proxy upstreams** - The proxy needs at least one upstream, stops if any upstream fails to start, and supports `stdio` upstreams only.
- **Proxy session end with ChatGPT Desktop** - ChatGPT Desktop can stop the proxy without closing its connection, so those proxy sessions may be missing `session.ended`.
- **Grep/Glob file read counts** - Reported as invocation counts, not individual file counts. The hook layer cannot observe how many files a search actually opened.
- **`duration_ms` for Codex events** - Computed from wall-clock timing between PreToolUse and PostToolUse shim invocations, not from Codex itself (Codex does not send this field).
- **Dual settings file duplication (Claude Code)** - If both `.claude/settings.json` and `.claude/settings.local.json` contain Omnodex hooks, events will be double-counted. Use `settings.local.json` exclusively (the `omnodex install claude-code` default).

---

## Package layout

```
packages/
  shared/                  Event schema + Interceptor interface
  event-log/               Append-only JSONL event log (source of truth)
  projection/              Projector + ReadModelStore (in-memory and SQLite)
  analyzer/                Rule engine: RuleDefinition, RuleEngine, RuleRegistry,
                           community rules across multiple categories, detectRisks()
  hooks-provider/          ClaudeCodeInterceptor + MockInterceptor + claude-hook-shim
  codex-provider/          CodexInterceptor + codex-hook-shim
  antigravity-provider/    AntigravityInterceptor + antigravity-hook-shim
  mcp-proxy/               MCP proxy interceptor (sits between agent and upstream
                           MCP servers). Built-in tools: omnodex_status,
                           omnodex_connect, omnodex_connection_status
  sync-encryptor/          Zero-knowledge AES-256-GCM sync encryption (Argon2id KDF),
                           streaming key derivation (HKDF), StreamingTransport
  feature-extractor/       Privacy-preserving feature extraction for cloud analytics
  license-client/          License validation client (cloud API, cache, offline fallback)
  cli/                     omnodex CLI: install, uninstall, status, update, spike,
                           detect, replay, report, dashboard, mcp-proxy, license,
                           connect. Multi-root dashboard config (config.ts)
                           Stable hook launchers (launcher-template.ts)
                           Installation registry (registry.ts)
                           Self-update + background check (update.ts)
```

---

## License

Omnodex is dual-licensed:

- **Open source:** [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE). You may use, modify, and distribute Omnodex under these terms. If you modify Omnodex and provide it as a network service, you must share your modifications under the same license.
- **Commercial:** A commercial license is available for organizations that need a non-copyleft license, want to avoid the AGPL's source-sharing requirements, or need access to Hosted, Pro, and Enterprise features. See [omnodex.com/licensing](https://omnodex.com/licensing) for details.

Using Omnodex internally to monitor your own AI agents? The AGPL applies, but we encourage this use. If your organization requires a non-copyleft license for internal deployment, [contact us](https://omnodex.com/contact) about a commercial license.

Copyright (c) 2026 Omnodex, LLC.
