# Development Guide

Full documentation: [docs.omnodex.com](https://docs.omnodex.com/)

## Stack

- TypeScript, Node 24 or newer (uses `node:sqlite`, available since v22.5.0)
- npm workspaces monorepo
- No native builds, no external services

## Commands

```bash
npm install
npm run build

# Run the full mock pipeline (25 events, SQLite read model, risk detection)
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js spike

# Scan for risk patterns and append risk.detected events (idempotent)
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js detect

# Replay log into a fresh read model (idempotent)
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js replay

# Print risk report
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js report

# Launch visual dashboard (auto-detects risks, then replays, default port 7890)
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js dashboard

# Dashboard with multiple roots (aggregates events from all sources)
node packages/cli/dist/index.js dashboard --roots /path/to/other/.omnodex

# Run all tests
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

# Run analyzer unit tests
cd packages/analyzer && node --test test/**/*.test.mjs test/*.test.mjs
```

## Package map

``` folder tree
packages/
  shared/                  Event schema + the Interceptor interface
  event-log/               Append-only JSONL writer/reader (source of truth)
  projection/              Projector + ReadModelStore (in-memory and SQLite)
  hooks-provider/          Interceptor implementations: MockInterceptor, ClaudeCodeInterceptor
  codex-provider/          CodexInterceptor + codex-hook-shim (OpenAI Codex)
  antigravity-provider/    AntigravityInterceptor + antigravity-hook-shim (Google Antigravity)
  mcp-proxy/               MCP proxy interceptor (agent <-> upstream MCP servers)
  analyzer/                Rule engine (RuleEngine, RuleRegistry) + 19 community rule definitions
  sync-encryptor/          Zero-knowledge AES-256-GCM sync encryption (Argon2id KDF)
  feature-extractor/       Privacy-preserving feature extraction for cloud analytics
  license-client/          License validation client (cloud API, cache, offline fallback)
  cli/                     omnodex CLI: install, uninstall, status, update, spike,
                           detect, replay, report, dashboard, mcp-proxy, license, connect, sync
                           Multi-root dashboard config (config.ts)
                           Stable hook launchers (launcher-template.ts)
                           Installation registry (registry.ts)
                           Self-update + background check (update.ts)
demo/
  project/                 Demo project with SQLite DB, config with credentials
  api-server.js            Mock enrichment API (localhost:3456)
  setup.sh                 One-step demo setup script
  DEMO.md                  How to run with test data
```

## Architectural decisions

These are load-bearing. Do not change without strong reason.

**1. Event-log-first storage.**
The append-only JSONL log under `$OMNODEX_HOME/event-log/` is the source of truth. The dashboard supports tailing multiple roots simultaneously (configured via `~/.omnodex/config.json` or `--roots` CLI flag), merging events from all sources into a single read model. SQLite (`traces.db`) is a derived read model rebuilt by replaying the log. Migrating to Postgres later is a `ReadModelStore` swap. Deleting `traces.db` and replaying must produce byte-for-byte identical output.

**2. Async by design.**
Interceptors fire-and-forget into the event log. They never block the agent's execution path. The projector and analyzer run asynchronously and are allowed to lag. Do not introduce synchronous waits in the hot path.

**3. Single Interceptor interface.**
`@omnodex/shared` defines one `Interceptor` interface. Every interception source implements it. Five implementations are complete: `ClaudeCodeInterceptor` and `MockInterceptor` (in `hooks-provider`), `CodexInterceptor` (in `codex-provider`), `AntigravityInterceptor` (in `antigravity-provider`), and `MCPProxy` (in `mcp-proxy`). Additional interceptors drop in without touching anything downstream.

**4. Token overhead target: zero.**
Hooks run out-of-band from the AI agent's context window. Do not introduce any approach that adds tokens to the customer's session.

**5. Rules are pure data.**
`RuleDefinition` objects in `packages/analyzer/src/rules/` are plain JSON - no executable code. The `RuleEngine` interprets conditions (`path_match`, `credential_match`, `outbound_call`, `command_match`, `tool_name_match`, `rate_limit`, and others). New rules are added by creating a `RuleDefinition` and registering it in the appropriate category file under `src/rules/community/`.

**6. Always add unit tests.**
Every new package and feature must include unit tests using `node:test` (`.mjs` files in the package's `test/` directory). See `packages/analyzer/test/` for the pattern. This convention was established to catch regressions early.

## Risk detection rules

The rule engine (`packages/analyzer`) evaluates declarative `RuleDefinition` objects against event logs. Rules are invoked by `omnodex detect` and `omnodex dashboard`.

**Community rules (19 rules across 8 categories):**

Credential detection:
1. **RULE_CREDENTIAL_IN_PARAMS** (MEDIUM) - flags tool calls whose parameters contain API keys, Bearer tokens, Stripe keys, GitHub PATs, Slack bot tokens, AWS access keys.
2. **RULE_CREDENTIAL_EXFIL** (CRITICAL) - flags outbound HTTP/fetch calls that carry credentials to external hosts.

Sensitive file access:
3. **RULE_SENSITIVE_PATH_READ** (HIGH) - flags reads of `/etc/passwd`, `.ssh/` keys, `.env` files, AWS/GCloud/k8s credentials, PEM files, etc.

Unexpected network destinations:
4. **RULE_OUTBOUND_KNOWN_IP** (MEDIUM) - outbound calls to raw IPv4 addresses within known cloud provider CIDR ranges (AWS, GCP, Azure, Cloudflare, Fastly).
5. **RULE_OUTBOUND_UNKNOWN_IP** (HIGH) - outbound calls to raw IPv4 addresses outside all known CIDR ranges; likely C2 callback, exfiltration, or supply chain compromise.

Wallet and key material:
6. **RULE_WALLET_CLI_DETECTED** (HIGH) - bash commands invoking known wallet key-generation CLIs (solana-keygen, ethkey, bitcoin-cli, etc.).
7. **RULE_PRIVATE_KEY_MATERIAL** (HIGH) - 256-bit hex private key patterns in labeled context.
8. **RULE_MNEMONIC_PHRASE** (HIGH) - BIP-39 mnemonic seed phrases (12+ lowercase words after a seed/mnemonic label).

Supply chain:
9. **RULE_SUPPLY_CHAIN_TOOL_SHADOW** (HIGH) - tool name collisions that could shadow legitimate tools.
10. **RULE_SUPPLY_CHAIN_NEW_MCP_SERVER** (LOW) - new MCP server registrations.
11. **RULE_SUPPLY_CHAIN_SKILL_MANIPULATION** (HIGH) - writes to skill files or plugin manifests.
12. **RULE_SUPPLY_CHAIN_DEP_CONFUSION** (MEDIUM) - dependency confusion patterns in package installs.
13. **RULE_SUPPLY_CHAIN_HOOK_CONFIG_WRITE** (HIGH) - writes to hook configuration files.
14. **RULE_SUPPLY_CHAIN_MCP_URL_MUTATION** (HIGH) - mutations to MCP server URLs or endpoints.
15. **RULE_SUPPLY_CHAIN_PKG_CONFIG_WRITE** (HIGH) - writes to package manager config files.
16. **RULE_SUPPLY_CHAIN_WORKSPACE_CONFIG_ACCESS** (MEDIUM) - access to workspace configuration files.

Unbounded consumption:
17. **RULE_UNBOUNDED_CONSUMPTION_BURST** (MEDIUM) - burst of tool calls exceeding a rate threshold.
18. **RULE_UNBOUNDED_CONSUMPTION_SUSTAINED** (HIGH) - sustained high rate of tool calls over a longer window.

Input validation:
19. **RULE_INPUT_VALIDATION_SQL_INJECTION** (HIGH) - SQL injection patterns in tool call parameters.

The detector writes `risk.detected` events back into the event log. The `dashboard` command auto-runs detection before replaying.

## Known limitations

- **Grep and Glob file read counts** are invocation counts, not individual file counts. The hook layer cannot observe how many files a Grep actually opened.
- **`duration_ms` for Codex events** is computed from wall-clock timing between PreToolUse and PostToolUse shim invocations, not from Codex itself (Codex does not send this field). Claude Code also does not send `duration_ms` in hook payloads.
- **Duplicate events from dual settings files** can occur when both `.claude/settings.json` and `.claude/settings.local.json` have hooks registered. Use `settings.local.json` exclusively (the `omnodex install claude-code` default).
- **Node version managers (nvm, fnm, etc.):** Switching Node versions only requires reinstalling hooks for **legacy installs** (`--legacy-shim`). The default stable launcher installs resolve Node from PATH at runtime and handle version switches automatically.
