# @omnodex/sealed-hook

Capture for hosts that have no Omnodex install, no secret and no lasting disk: cloud agent VMs, dev servers, devcontainers. The hook maps each agent's payload to Omnodex events, seals every event to your stream's **public** key, and sends the ciphertext to write-only ingest at the end of each turn. Nothing on the host can read what it sends.

```
omnodex-sealed-hook <claude-code|copilot|cursor|codex|antigravity> [event]
```

Antigravity's hooks pass their event name as the second argument. The command always exits 0 and prints the answer each agent expects when there is nothing to decide, so a missing setting or a network failure never stops an agent.

## When it captures

It stays silent unless the host opts in:

| Setting | Effect |
| --- | --- |
| `CLAUDE_CODE_REMOTE=true` | Set by Claude Code cloud sessions; enables `claude-code` |
| `OMNODEX_SEALED=1` | Capture on this host, whatever it is |
| `OMNODEX_SEALED_WHEN=NAME` | Capture when the environment variable `NAME` is set and not `0` or `false` |
| `OMNODEX_SEALED=0` | Never capture |

## Settings

Environment variables, or a JSON file, or both (variables win):

| Variable | JSON field | Notes |
| --- | --- | --- |
| `OMNODEX_INGEST_PUBLIC_KEY` | `public_key` | Base64 X25519 public key. Required |
| `OMNODEX_INGEST_SOURCE_ID` | `source_id` | `src_...`. Required |
| `OMNODEX_INGEST_KEY_ID` | `key_id` | Derived from the key when omitted |
| `OMNODEX_INGEST_API_BASE` | `api_base` | Defaults to `https://api.omnodex.com` |
| `OMNODEX_INGEST_TOKEN` | `ingest_token` | Optional: leave it out when a proxy attaches the Authorization header |
| `OMNODEX_INGEST_REDACT=1` | `redact_parameters` | Replace tool parameter values before sealing |
| `OMNODEX_INGEST_CONFIG` | | Path to the JSON file |

The JSON file is read from `OMNODEX_INGEST_CONFIG`, then `ingest.json` in the Omnodex home (`~/.omnodex`), then `.omnodex/ingest.json` in the project; the first one found is used. A project's file cannot set `api_base`, so a repository cannot choose where the token and events are sent: set `OMNODEX_INGEST_API_BASE` or use the home's file for another server. A public key and source id are safe to commit; keep the token out of the repository.

## Build

`npm run bundle` writes one dependency-free file, `bundle/omnodex-sealed-hook.mjs`. The published `omnodex` package also ships the command as `omnodex-sealed-hook`.
