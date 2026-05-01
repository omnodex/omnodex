# Development Guide

## Stack

- TypeScript, Node 22.5.0 or newer (uses `node:sqlite`, which first shipped in v22.5.0; do not downgrade)
- npm workspaces monorepo
- No native builds, no external services

## Commands

```bash
npm install
npx tsc -b

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

# Run tests
node --test packages/event-log/test/*.test.mjs \
              packages/projection/test/*.test.mjs \
              packages/cli/test/*.test.mjs
```

## Package map

```
packages/
  shared/          Event schema + the Interceptor interface
  event-log/       Append-only JSONL writer/reader (source of truth)
  projection/      Projector + ReadModelStore (in-memory and SQLite)
  hooks-provider/  Interceptor implementations: MockInterceptor, ClaudeCodeInterceptor
  cli/             omnodex CLI: spike, detect, replay, report, dashboard
demo/
  project/         Demo project with SQLite DB, config with credentials
  api-server.js    Mock enrichment API (localhost:3456)
  setup.sh         One-step demo setup script
  DEMO.md          How to run with test data
```

## Architectural decisions

These are load-bearing. Do not change without strong reason.

**1. Event-log-first storage.**
The append-only JSONL log under `$OMNODEX_HOME/event-log/` is the source of truth. SQLite (`traces.db`) is a derived read model rebuilt by replaying the log. Migrating to Postgres later is a `ReadModelStore` swap. Deleting `traces.db` and replaying must produce byte-for-byte identical output.

**2. Async by design.**
Interceptors fire-and-forget into the event log. They never block the agent's execution path. The projector and analyzer run asynchronously and are allowed to lag. Do not introduce synchronous waits in the hot path.

**3. Single Interceptor interface.**
`@omnodex/shared` defines one `Interceptor` interface. Every interception source implements it. `MockInterceptor` and `ClaudeCodeInterceptor` are the two current implementations. Additional interceptors drop in without touching anything downstream.

**4. Token overhead target: zero.**
Hooks run out-of-band from the AI agent's context window. Do not introduce any approach that adds tokens to the customer's session.

## Risk detection rules

The risk detector (`omnodex detect`) scans event logs for three rule categories:

1. **RULE_SENSITIVE_PATH_READ** (HIGH) -- flags reads of /etc/passwd, .ssh keys, .env files, AWS credentials, etc.
2. **RULE_CREDENTIAL_IN_PARAMS** (MEDIUM) -- flags tool calls whose parameters contain API keys, Bearer tokens, GitHub PATs, etc.
3. **RULE_CREDENTIAL_EXFIL** (CRITICAL) -- flags outbound HTTP/fetch calls that carry credentials to external endpoints.

The detector writes `risk.detected` events back into the event log. The `dashboard` command auto-runs detection before replaying.

## Known limitations

- **Grep and Glob file read counts** are invocation counts, not individual file counts. The hook layer cannot observe how many files a Grep actually opened.
- **`duration_ms` is always 0** -- Claude Code does not send this field in hook payloads.
- **Duplicate events from dual settings files** -- can occur when both `.claude/settings.json` and `.claude/settings.local.json` have hooks registered. Use `settings.local.json` exclusively (the `omnodex init` default).

---

Copyright (c) 2026 Omnodex, LLC. All rights reserved.
