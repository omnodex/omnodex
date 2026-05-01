# Demo: Running Omnodex with Test Data

This guide walks through running the full Omnodex pipeline against a realistic test scenario.

## What the demo shows

An AI agent runs a routine data pipeline. The user never asks for anything risky. Omnodex silently observes the session, then reveals: which servers were involved, what credentials were exposed, and what sensitive operations occurred that the user may not have been aware of.

## Prerequisites

- Node 22.5.0+
- Claude Code installed (for the live session option)
- Omnodex built (`npm install && npx tsc -b` from the repo root)

## Option A: Quick start with mock data

The fastest way to see the full pipeline in action. Uses pre-built mock event data:

```bash
OMNODEX_HOME=~/.omnodex node packages/cli/dist/index.js spike
OMNODEX_HOME=~/.omnodex node packages/cli/dist/index.js detect
OMNODEX_HOME=~/.omnodex node packages/cli/dist/index.js dashboard
```

Open `http://localhost:7890` in a browser. The dashboard shows all four panels with realistic data.

## Option B: Live Claude Code session

For a real end-to-end test against a live Claude Code session.

### 1. Setup

```bash
# From the repo root:
./demo/setup.sh
```

This builds Omnodex, clears prior data, and installs hooks into the demo project.

### 2. Start the mock API server (Terminal 1)

```bash
node demo/api-server.js
# => "Enrichment API listening on http://localhost:3456"
```

Leave this running.

### 3. Run a Claude Code session (Terminal 2)

```bash
cd demo/project
claude
```

Prompt Claude with:

> Run the customer enrichment pipeline as described in the README.

Claude will read the project README and config, query the SQLite database, call the enrichment API with credentials from config, and potentially read sensitive system files. Let the session complete, then exit Claude Code.

### 4. Run detection and launch the dashboard

```bash
cd ../..    # back to repo root

# Run the risk detector
OMNODEX_HOME=~/.omnodex node packages/cli/dist/index.js detect

# Launch the dashboard
OMNODEX_HOME=~/.omnodex node packages/cli/dist/index.js dashboard
```

Open `http://localhost:7890` in a browser.

## Dashboard panels

The dashboard shows four panels:

1. **Connection graph** -- Which MCP servers were called, in order, with call counts.
2. **Credential ledger** -- All API keys/tokens observed in tool parameters.
3. **Risk events** -- Flagged high-risk operations with severity ratings. Click any event to see the related tool call.
4. **Event timeline** -- Chronological view of every tool call with full parameter and response detail.

## Expected results

After running either option, you should see:

- 3 MCP server nodes on the connection graph (sqlite, fetch, builtin)
- 3+ credentials detected (Stripe key, GitHub PAT, Bearer token)
- 3+ risk events at various severity levels (credential exfiltration, sensitive path reads, credential exposure)
