# Omnodex

[![CI](https://github.com/omnodex/omnodex/actions/workflows/ci.yml/badge.svg)](https://github.com/omnodex/omnodex/actions/workflows/ci.yml)

**Security and observability for AI agent execution.** Omnodex captures every tool call, credential use, file access, and third-party connection made by an AI agent - and surfaces it for human review.

Core pipeline: **Intercept -> Trace -> Analyze -> Report.** Zero token overhead to the agent session.

Full documentation: [docs.omnodex.com](https://docs.omnodex.com/)

---

## Integrations

Omnodex supports multiple interception surfaces. Choose the one that matches how you run your agent.

---

### Claude Code

#### CLI / Terminal

The primary integration. Omnodex hooks into Claude Code's native hook system - hooks fire asynchronously outside the agent's context window, adding zero token overhead.

**Prerequisites**

- Node.js 24 or newer
- Claude Code installed and authenticated

**Install**

```bash
npm install -g omnodex      # or: npx omnodex
```

**Enable hooks for a project**

```bash
cd /your/project
omnodex install claude-code
```

This writes Omnodex hook entries into `.claude/settings.local.json`. Claude Code picks them up automatically on the next session start - no restart required.

Options:
```
omnodex install claude-code [project]   # defaults to cwd
omnodex install claude-code --debug    # verbose shim logging to stderr
omnodex install claude-code --project-settings  # write to settings.json
```

To remove the hooks:
```bash
omnodex uninstall claude-code --confirm
```

**View the dashboard**

```bash
omnodex dashboard
# open http://localhost:7890
```

The dashboard shows a connection graph, credential ledger, risk events, and a full event timeline with click-through detail. It updates in real time via SSE - risks are detected and pushed to the browser as each tool call arrives.

**Multi-source aggregation:** If you run multiple agent surfaces simultaneously (e.g. Cowork on Windows + Claude Code in WSL), the dashboard can tail all of them at once. Configure additional roots in `~/.omnodex/config.json`:

```json
{
  "dashboard": {
    "roots": ["\\\\wsl$\\Ubuntu\\home\\you\\.omnodex"]
  }
}
```

Or pass them as a CLI flag: `omnodex dashboard --roots /path/to/.omnodex`. The default root (`~/.omnodex`) is always included. Events from all roots merge into a single timeline, filterable by source.

---

#### IDE Extensions (VS Code, Cursor, JetBrains)

Claude Code's IDE extensions use the same `.claude/settings.local.json` hook configuration as the CLI. Run `omnodex install claude-code` in your project directory and the hooks will fire inside IDE-based Claude Code sessions automatically.

---

#### claude.ai Web

> **Not yet available.** The claude.ai web interface does not support local MCP servers or hooks. Omnodex will support claude.ai web sessions via a hosted MCP proxy.

---

#### Claude Desktop - claude.ai chat app

The Claude desktop chat app supports MCP servers via its configuration. Add `omnodex-mcp-proxy` as an MCP server and route your existing MCP servers through it to capture all tool calls.

```json
{
  "mcpServers": {
    "omnodex": {
      "command": "omnodex-mcp-proxy",
      "args": []
    }
  }
}
```

Configure the upstream servers in the Omnodex proxy config (see `omnodex mcp-proxy install`).

---

#### Cowork

Omnodex integrates with Cowork via an MCP proxy plugin. The proxy sits between Cowork and your upstream MCP servers, capturing every tool call to the Omnodex event log.

Install the Omnodex plugin and add `omnodex-mcp-proxy` as the MCP server command in the plugin's `mcp.json`. All Cowork MCP traffic flows through the proxy transparently.

> **Note:** Hook-based interception is not available in Cowork - plugin-contributed hooks are currently ignored upstream ([#27398](https://github.com/anthropics/claude-code/issues/27398), [#40495](https://github.com/anthropics/claude-code/issues/40495)). The MCP proxy approach provides equivalent coverage for all MCP tool calls.

---

### OpenAI Codex

#### CLI / Terminal

Omnodex integrates with the Codex hook system, using the same architecture as the Claude Code integration: a lightweight shim subprocess receives hook payloads on stdin, maps them to Omnodex trace events, and appends them to the event log without touching the agent's execution path.

**Prerequisites**

- Node.js 24 or newer
- Codex CLI installed

**Enable hooks in your Codex config**

Codex hooks require an opt-in feature flag. Add this to `~/.codex/config.toml` (or the project-local `.codex/config.toml`):

```toml
[features]
codex_hooks = true
```

**Install**

```bash
npm install -g omnodex      # or: npx omnodex
```

**Enable hooks for a project**

```bash
cd /your/project
omnodex install codex
```

This writes Omnodex hook entries into `.codex/hooks.json`. Codex picks them up automatically.

Options:
```
omnodex install codex [project]    # defaults to cwd
omnodex install codex --debug      # verbose shim logging to stderr
```

To remove the hooks:
```bash
omnodex uninstall codex --confirm
```

**View the dashboard**

Same as Claude Code - run `omnodex dashboard` and open `http://localhost:7890`.

**Known limitations (Codex hooks are a work in progress)**

Codex hooks currently only fire for Bash tool calls. The following are **not** intercepted via hooks today:
- File writes (`apply_patch`)
- MCP tool calls
- WebSearch
- `unified_exec` shell calls (partial interception only)

These are upstream gaps in Codex's hook coverage ([#20204](https://github.com/openai/codex/issues/20204)). The Omnodex schema is ready - coverage will expand automatically when Codex ships it.

---

#### IDE Extension (VS Code, Cursor)

The Codex IDE extension uses the same `.codex/` config directory as the CLI. Run `omnodex install codex` in your project and hooks will fire in IDE sessions.

---

#### Codex Desktop App

The Codex desktop app runs the Codex CLI under the hood and shares the same `.codex/hooks.json` configuration. `omnodex install codex` applies to desktop sessions as well.

For complete tool coverage beyond what Codex hooks currently support (file writes, MCP calls), run the Omnodex MCP proxy alongside the hook-based approach. See the [MCP Proxy](#mcp-proxy) section below.

---

#### Codex Web

> **Not yet available.** Codex web sessions will be supported via a hosted Omnodex MCP proxy.

---

### Google Antigravity

#### CLI, Desktop App, IDE Extensions

Omnodex hooks into Google Antigravity's hook system via the Shared Agent Harness. A single `omnodex install antigravity` command covers all three surfaces (CLI `agy`, Desktop App, and IDE extensions) because they share the same `.agents/hooks.json` configuration.

**Prerequisites**

- Node.js 24 or newer
- Google Antigravity installed (CLI, Desktop, or IDE extension)

**Install**

```bash
npm install -g omnodex      # or: npx omnodex
```

**Enable hooks for a project**

```bash
cd /your/project
omnodex install antigravity
```

This writes Omnodex hook entries into `.agents/hooks.json`. All Antigravity surfaces pick them up automatically.

Options:
```
omnodex install antigravity [project]    # defaults to cwd
omnodex install antigravity --debug      # verbose shim logging to stderr
```

To remove the hooks:
```bash
omnodex uninstall antigravity --confirm
```

**View the dashboard**

Same as other integrations - run `omnodex dashboard` and open `http://localhost:7890`.

---

### MCP Proxy

For agents and platforms that don't expose a hook API, Omnodex provides a general-purpose MCP proxy. Route your agent's MCP traffic through the proxy and Omnodex captures tool calls, data flows, and credential usage across any MCP-compatible agent - regardless of model or runtime.

```bash
# Generate a proxy config template
omnodex mcp-proxy install

# Check the config
omnodex mcp-proxy status

# Start the proxy
omnodex mcp-proxy start
```

The proxy config maps upstream MCP servers. Point your agent at `omnodex-mcp-proxy` instead of its usual MCP servers, and the proxy forwards all traffic while logging every tool call to the Omnodex event log.

Target platforms: Cowork, Claude Desktop, Codex Desktop (full tool coverage), claude.ai Web (requires hosted proxy), Codex Web (requires hosted proxy), and any other agent that connects to MCP servers.

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
omnodex uninstall [target] [project] remove Omnodex hooks (requires --confirm)
omnodex status [project]            show which hooks are installed

omnodex mcp-proxy <subcommand>      manage the MCP proxy interceptor
                                      install   generate proxy config template
                                      status    inspect the current config
                                      start     start the proxy server

omnodex spike [name]                run a simulated session through the full pipeline
omnodex detect [session]            scan event log for risks (all sessions if omitted)
omnodex replay                      rebuild the SQLite read model from the event log
omnodex report                      print a session summary
omnodex dashboard [port]            start the local dashboard (default port 7890)
                                      --roots <path> [path...]  additional OMNODEX_HOME
                                                                roots to tail
                                      --no-detect   skip the historical detection pass
omnodex clear                       delete all event log data and the read model
omnodex license                     manage license activation and status
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

297 tests across 31 test files. One pre-existing timing flake in the CLI streaming suite (`tailSession`) that only manifests in the combined run due to resource contention - it passes reliably when run in isolation.

---

## Known limitations

- **Codex hook coverage** - Bash only today. File writes, MCP calls, and WebSearch are upstream gaps in Codex's hook system (see [#20204](https://github.com/openai/codex/issues/20204)).
- **Cowork hook-based interception unavailable** - All Cowork versions currently ignore plugin-contributed hooks ([#27398](https://github.com/anthropics/claude-code/issues/27398), [#40495](https://github.com/anthropics/claude-code/issues/40495)). The MCP proxy approach provides full coverage for MCP tool calls as a workaround.
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
                           19 community rules across 8 categories, detectRisks()
  hooks-provider/          ClaudeCodeInterceptor + MockInterceptor + claude-hook-shim
  codex-provider/          CodexInterceptor + codex-hook-shim
  antigravity-provider/    AntigravityInterceptor + antigravity-hook-shim
  mcp-proxy/               MCP proxy interceptor (sits between agent and upstream
                           MCP servers)
  sync-encryptor/          Zero-knowledge AES-256-GCM sync encryption (Argon2id KDF)
  feature-extractor/       Privacy-preserving feature extraction for cloud analytics
  license-client/          License validation client (cloud API, cache, offline fallback)
  cli/                     omnodex CLI: install, uninstall, status, spike,
                           detect, replay, report, dashboard, mcp-proxy, license
                           Multi-root dashboard config (config.ts)
```

---

## License

Omnodex is dual-licensed:

- **Open source:** [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE). You may use, modify, and distribute Omnodex under these terms. If you modify Omnodex and provide it as a network service, you must share your modifications under the same license.
- **Commercial:** A commercial license is available for organizations that need a non-copyleft license, want to avoid the AGPL's source-sharing requirements, or need access to Hosted, Pro, and Enterprise features. See [omnodex.com/licensing](https://omnodex.com/licensing) for details.

Using Omnodex internally to monitor your own AI agents? The AGPL applies, but we encourage this use. If your organization requires a non-copyleft license for internal deployment, [contact us](https://omnodex.com/contact) about a commercial license.

Copyright (c) 2026 Omnodex, LLC.
