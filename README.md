# Omnodex

[![CI](https://github.com/omnodex/omnodex/actions/workflows/ci.yml/badge.svg)](https://github.com/omnodex/omnodex/actions/workflows/ci.yml)

**Security and observability for AI agent execution.** Omnodex captures every tool call, credential use, file access, and third-party connection made by an AI agent - and surfaces it for human review.

Core pipeline: **Intercept -> Trace -> Analyze -> Report.** Zero token overhead to the agent session.

Full documentation: [docs.omnodex.com](https://docs.omnodex.com/)

---

## Install

Omnodex runs on the host where your agent runs.

```bash
npm install -g omnodex
```

Requires Node.js 24 or newer. On Windows, run this in PowerShell for agents that run natively on Windows (Cowork, ChatGPT Desktop), and in WSL for agents you run inside WSL. Native Windows and WSL are separate hosts with separate Omnodex data.

The package includes the CLI, the hook handlers and the MCP proxy. Hooks installed by `omnodex install` find the handlers on their own, and keep working across `npm update`.

### From source

```bash
git clone https://github.com/omnodex/omnodex.git
cd omnodex
npm install
npx tsc -b
npm install -g ./packages/cli     # links the omnodex command to this build
```

When hooks cannot find this build on their own, `omnodex install` records its handler in `shim_paths` in `omnodex-config.json` in the Omnodex home (`~/.omnodex`, or `C:\Users\<you>\.omnodex` on Windows).

Full setup guides: [docs.omnodex.com](https://docs.omnodex.com/getting-started/installation/)

---

## Integrations

| Agent | Mechanism | Setup |
| --- | --- | --- |
| Claude Code (CLI and IDE extensions) | Hooks, plus the MCP proxy through the Omnodex plugin | `omnodex install claude-code` |
| OpenAI Codex (ChatGPT Desktop, CLI, IDE) | Hooks, plus the MCP proxy through the Omnodex plugin | `omnodex install codex` |
| Cowork | MCP proxy via the Omnodex plugin | Plugin plus `omnodex-proxy.json` |
| Google Antigravity (CLI, Desktop, IDE) | Hooks, plus the MCP proxy through the Omnodex plugin | `omnodex install antigravity` |
| Any other MCP client | MCP proxy | Point the client at the proxy |

`omnodex install <target>` sets up both parts: the hooks, and the agent's Omnodex plugin, which runs the MCP proxy. `--hooks` or `--plugin` installs one of them. The plugin is downloaded from downloads.omnodex.com and checked against the sha256 this release of the CLI pins; it is unpacked where the agent looks for plugins and registered with the agent's own CLI when that is on PATH (`claude plugin install --scope user`, `codex plugin add`; Antigravity loads it from `~/.gemini/config/plugins/`). If the download fails, the hooks are still installed and the command says how to retry. `--plugin-version <version|latest>` installs another published version, checked against its published checksum, and `--from <file>` installs a bundle you downloaded yourself (it must match the pin, a published checksum, or `--sha256 <hex>`). The plugin applies to every project; `omnodex uninstall <target> --plugin` removes it.

### Every project or one project

`omnodex install` asks whether to record every project you open (recommended) or only the current one. Every project puts the hooks in the agent's user-level file (`~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.gemini/config/hooks.json`); one project puts them in the project, as described below. `--everywhere` and `--this-project` answer the question up front; `--yes` picks every project; without a terminal and without a flag, hooks go into the project.

- **Leave one project out:** `omnodex uninstall <target>` in that project. Other projects are still recorded. `omnodex install <target>` there records it again.
- **Stop recording every project:** `omnodex uninstall <target> --everywhere`.
- **No double counting:** a project that also has its own Omnodex hooks is recorded once; its project hooks step aside while every-project recording is on.
- `omnodex status` shows which applies to the current project.

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

2. **The Omnodex MCP server**, once per host. `omnodex install codex` installs the Omnodex plugin, which provides it: the plugin is added to your personal marketplace (`~/.agents/plugins/marketplace.json`) and registered with `codex plugin add`. Without the plugin, register the server yourself; in ChatGPT Desktop use **Settings > MCP servers > Add server** (STDIO), or from the CLI:

   ```bash
   codex mcp add omnodex -- /absolute/path/to/node /path/to/omnodex/packages/mcp-proxy/dist/bin/omnodex-mcp-proxy.js --config ~/.omnodex/omnodex-proxy.json
   ```

   Use the absolute path of the config file on hosts where `~` is not expanded. The Desktop app, CLI, and IDE extension share this entry when they run on the same host. On native Windows, use Windows paths.

Hosted tools such as web search run on OpenAI's side and are not visible to local hooks.

### Cowork

Install the `omnodex-cowork` plugin, then create `~/.omnodex/omnodex-proxy.json` (on Windows, `C:\Users\<you>\.omnodex\omnodex-proxy.json`) with at least one upstream MCP server. Fully quit and reopen Cowork. The plugin looks for the proxy in the usual global npm locations; if `launcher.log` in the Omnodex home says it was not found (for example with a Node version manager, or a source build), set `proxy_bin` to the full path of `omnodex-mcp-proxy.js`.

The proxy records calls to the MCP servers routed through it. Cowork's built-in tools are not recorded: Cowork does not currently run plugin hooks.

### Google Antigravity

```bash
cd /your/project
omnodex install antigravity           # hooks
omnodex install antigravity --mcp     # MCP proxy
```

Writes `.agents/hooks.json` and, with `--mcp`, `.agents/mcp_config.json`. The CLI (`agy`), Desktop App, and Antigravity IDE share this configuration.

Hooks observe completed tool calls through `PostToolUse`, with parameters and success/error status. They do not install a `PreToolUse` permission hook. Re-run `omnodex install antigravity` after upgrading an older installation to remove that handler. Hook-only tool duration is unknown (recorded as zero); use the MCP proxy for measured MCP timing. `PreInvocation` starts capture once per conversation, and `Stop` records an idle execution end only when `fullyIdle` is true. Model invocations do not end sessions, and idle execution does not mean the conversation was deleted. See the [Antigravity guide](https://docs.omnodex.com/guides/antigravity/) for setup and validation limits.

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

The local dashboard shows a connection graph, credential ledger, risk events, and an event timeline, updated in real time. It listens on loopback only and answers only requests addressed to `localhost`, `127.0.0.1` or `[::1]` from its own page, so other machines on the network and other websites open in your browser cannot read it. From WSL, a Windows browser reaches it at the same `http://localhost:7890`. To include another host's data (for example the Windows home from WSL), add it with `--roots /mnt/c/Users/<you>/.omnodex` or `dashboard.roots` in `~/.omnodex/config.json`.

In a risk event detail, **Risk Library** opens the explanation for its rule at `https://docs.omnodex.com/` in a new tab. Opening it requires network access to the documentation site.

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

All data lives under `OMNODEX_HOME` (defaults to `~/.omnodex`). `detect` and `dashboard` also read and add findings to `~/.omnodex` when `OMNODEX_HOME` points elsewhere; set `OMNODEX_SINGLE_ROOT=1` to keep a run inside `OMNODEX_HOME`.

---

## CLI reference

```
omnodex install [target] [project]  install hooks and the agent's plugin
                                      targets: claude-code, codex, antigravity (or agy);
                                      without one, every agent found on this machine
                                      --everywhere          record every project
                                      --this-project        hooks in this project only
                                      --yes, -y             no questions; every project
                                      --hooks, --plugin     install only that part
                                      --plugin-version <v>  another published version, or latest
                                      --from <file>         a downloaded plugin bundle
                                                            (with --sha256 <hex> if unpublished)
                                      --debug               verbose shim logging
                                      --project-settings    (claude-code) edit
                                                            settings.json instead
                                      --mcp                 (antigravity) project MCP entry
                                                            instead of the plugin
omnodex uninstall [target] [project] remove the project's hooks; when the agent records
                                      every project, leave this project out instead
                                      --everywhere          stop recording every project
                                      --plugin              remove the agent's plugin
                                      --confirm             do not ask first
omnodex status [project]            show which hooks record the project
                                      --all                 full installation registry
                                                            with stale install warnings
omnodex update                      self-update (npm: npm update -g; source: git pull
                                      --ff-only + npm install + npm run build)
                                      --check               dry-run, show available updates
                                      --refresh-launchers   rewrite hook launchers only
                                      --refresh-plugins     bring installed agent plugins to the
                                                            versions this release pins (also
                                                            done after every update)
omnodex --version, -V               show version (source installs show branch + sha)

omnodex connect [--token <token>]   connect this host to your dashboard account.
  [--passphrase <phrase>]             Without a stored token: starts a device code flow
  [--platform <name>] [--api <url>]   (displays a code + URL, polls for authorization).
                                      With a token: prints a one-time connection link.
                                      Generates a sync passphrase on first run; the
                                      passphrase is transferred end-to-end encrypted.
omnodex sync                        encrypt the read model and upload it to the cloud.
                                      Sessions active in the last 120 days are uploaded
                                      in segments, and a sync sends only the segments
                                      that changed. Connected hosts also sync
                                      automatically in the background when a hooked
                                      session ends (at most once a minute). Turn off with
                                      "auto_sync": false in stream-config.json or
                                      OMNODEX_AUTO_SYNC=0.
omnodex live [resume]               show whether live pushes are paused. When no
                                      dashboard is watching, pushes pause for up to five
                                      minutes between probes, and go back to every event
                                      once a probe finds a dashboard. resume skips the
                                      wait. `omnodex status` shows the same state.

omnodex mcp-proxy <subcommand>      manage the MCP proxy interceptor
                                      install   generate proxy config template
                                      status    inspect the current config
                                      start     start the proxy server

omnodex spike [name]                generate synthetic sessions and real community findings
                                      --seed <integer>  reproduce a dataset (default 1)
                                      --random          pick and print a fresh seed
                                      --now <ISO>       fixed clock with timezone
                                      --sessions <N>    12-1000 sessions (default 12)
                                      --scenario-set movement  add loopback chain fixtures
omnodex detect [session]            scan event log for risks (all sessions if omitted).
                                      Hooks and the MCP proxy also run detection in the
                                      background, with or without a connected dashboard:
                                      when a session ends, and at least every 15 minutes
                                      while one runs. Turn off with OMNODEX_AUTO_DETECT=0.
                                      The hooks and the MCP proxy also judge each call as
                                      they record it (the proxy off the response path);
                                      OMNODEX_CAPTURE_DETECT=0 turns that off, and
                                      OMNODEX_CAPTURE_DETECT_TIMEOUT_MS caps it in a hook
                                      (default 1000).
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

To try synthetic data in an isolated home, run
`OMNODEX_HOME=/tmp/omnodex-demo OMNODEX_SINGLE_ROOT=1 omnodex spike --seed 42 --now 2026-10-18T12:00:00Z`,
then start `omnodex dashboard` with the same environment. No scenario commands
or requests execute. With no flags, the clock is fixed at
`2026-10-01T12:00:00.000Z`; repeated runs append sessions with distinct IDs.
See the [coverage manifest](packages/hooks-provider/SCENARIOS.md).

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
