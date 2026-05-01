# Omnodex

**Security and observability for AI agent execution.** Omnodex makes every connection, tool call, credential use, and data flow in AI agent execution traceable and auditable.

Core pipeline: **Intercept -> Trace -> Analyze -> Report.** Zero token overhead to the AI agent session.

## Layout

```
omnodex/
  package.json              npm workspaces root.
  tsconfig.base.json        shared TS config.
  tsconfig.json             root project references.
  packages/
    shared/                 event schema and the Interceptor interface
    event-log/              append-only JSONL, source of truth
    projection/             projector plus ReadModelStore (in-memory and SQLite)
    hooks-provider/         interceptors (MockInterceptor, ClaudeCodeInterceptor)
    cli/                    omnodex cli: spike, detect, replay, report, dashboard
  demo/
    project/                demo project (SQLite DB, config with credentials)
    api-server.js           mock enrichment API (localhost:3456)
    setup.sh                one-step demo setup
    DEMO.md                 how to run with test data
```

## Architecture

1. **Event-log-first storage.** The source of truth is an append-only JSONL event log under `$OMNODEX_HOME/event-log/`. SQLite is a derived read model rebuilt by replaying the log. Migrating to Postgres or any other backend later is a `ReadModelStore` implementation swap, not a rewrite.
2. **Async by design.** Interceptors fire and forget into the event log. They never block the agent's execution path. The projector and any future analyzer run asynchronously and are allowed to lag.
3. **Interceptor seam.** A single `Interceptor` interface in `@omnodex/shared` is the one boundary that every interception source implements. `MockInterceptor` and `ClaudeCodeInterceptor` are both complete and validated against a live Claude Code session. Additional interceptor implementations drop in without touching anything downstream.
4. **Zero token overhead.** The hook-based architecture runs out-of-band from the AI agent's context window. No approach that adds tokens to the customer's session is acceptable.

## Running the pipeline

Prerequisites: Node 22.5.0 or newer. The built-in `node:sqlite` module first shipped in v22.5.0. No native builds.

```
npm install
npx tsc -b
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js spike
```

This runs the full pipeline: mock interceptor emits 25 events, the event log persists them as JSONL, the projector rebuilds the SQLite read model, and the CLI prints a summary.

### Risk detection

After capturing events (via spike or a real Claude Code session with hooks), run the detector:

```
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js detect
```

The detector scans `tool.invoked` events for three risk patterns: sensitive path reads (HIGH), credential exposure in tool parameters (MEDIUM), and credential exfiltration to external endpoints (CRITICAL). It appends `risk.detected` events to the log. Running it again skips already-detected risks (idempotent).

Subsequent replays rebuild the read model from the full log (including risk events):

```
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js replay
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js report
```

### Visual dashboard

After running the spike (or capturing real hook events), launch the dashboard. It auto-runs detection before replaying:

```
OMNODEX_HOME=/tmp/omnodex-demo node packages/cli/dist/index.js dashboard
```

Open `http://localhost:7890` in a browser. The dashboard shows four panels: connection graph, credential ledger, risk events, and an event timeline with click-through detail. Pass a custom port as the first argument (e.g., `dashboard 8080`).

## Tests

```
node --test packages/event-log/test/*.test.mjs \
            packages/projection/test/*.test.mjs \
            packages/hooks-provider/test/*.test.mjs \
            packages/cli/test/*.test.mjs
```

23 tests across four suites. The integration test in `packages/cli/test/pipeline.test.mjs` asserts the rebuild-from-scratch property: delete `traces.db`, replay the log, and the read model is byte-for-byte the same. The hooks-provider suite includes a shim subprocess integration test that validates the never-block-Claude contract against malformed input.

## Known limitations

- **Grep and Glob file read counts** are invocation counts, not individual file counts. The hook layer cannot observe how many files a Grep actually opened. This is a fundamental hook-layer limitation, not a fixable mapper bug.
- **`duration_ms` is always 0** -- Claude Code does not send this field in hook payloads. Computing it from paired event timestamps is a future enhancement.
- **Duplicate events from dual settings files** -- can occur when both `.claude/settings.json` and `.claude/settings.local.json` have hooks registered. Use `settings.local.json` exclusively (the `omnodex init` default).

## Contributing

See `DEVELOPMENT.md` for build commands, package details, and architectural decisions.

---

Copyright (c) 2026 Omnodex, LLC. All rights reserved.
