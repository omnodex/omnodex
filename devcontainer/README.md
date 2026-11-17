# Omnodex devcontainer feature

Sets up sealed capture in a devcontainer, Codespace or other disposable dev box. Every hook event from Claude Code, Codex and the other supported agents is sealed to your stream's public key and sent to write-only ingest, so nothing is lost when the container is thrown away and nothing on the box can read what was captured.

```json
{
  "features": {
    "ghcr.io/devcontainers/features/node:1": {},
    "./features/omnodex": { "agents": "claude-code,codex" }
  }
}
```

Set these in the container environment (Codespaces secrets work):

| Variable | Notes |
| --- | --- |
| `OMNODEX_INGEST_PUBLIC_KEY` | Your stream's public key. Required |
| `OMNODEX_INGEST_SOURCE_ID` | One source per environment. Required |
| `OMNODEX_INGEST_API_BASE` | Defaults to `https://api.omnodex.com` |
| `OMNODEX_INGEST_TOKEN` | Optional: omit it when a proxy attaches the Authorization header. Never written to disk |

The feature installs the `omnodex` package at build time and runs `omnodex install --ephemeral` after the container is created, when secrets are available. Without the two required variables it does nothing, and a failed setup never stops the container from starting.

Codex asks you to trust new hooks the first time it runs in a project (`/hooks`).
