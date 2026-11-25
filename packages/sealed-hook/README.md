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

The JSON file is read from `OMNODEX_INGEST_CONFIG`, then `ingest.json` in the Omnodex home (`~/.omnodex`); the first one found is used. `OMNODEX_INGEST_CONFIG` and `OMNODEX_HOME` must be absolute paths; relative values are ignored.

A project can commit `.omnodex/ingest.json` for a host with no settings of its own, such as one where a proxy attaches the token. It is read only when neither file above exists and none of `OMNODEX_INGEST_TOKEN`, `OMNODEX_INGEST_PUBLIC_KEY`, `OMNODEX_INGEST_KEY_ID` or `OMNODEX_INGEST_SOURCE_ID` is set, and it can give only `public_key`, `key_id` and `source_id`. Every other field is ignored. A public key and source id are safe to commit; keep the token out of the repository.

When a project's file is there but ignored, the hook leaves one warning per session in `ingest/warnings.log` under the Omnodex home, and `omnodex status` shows the latest on a host with the CLI.

On such a proxy host the repository is trusted to name the key and source: whoever controls the repository decides what the events are sealed to, which can leave them unreadable to you. Set the key and source in the environment or the home's file to close that. A repository's own agent settings and hooks run with the agent and are outside what these rules can protect.

## Build

`npm run bundle` writes one dependency-free file, `bundle/omnodex-sealed-hook.mjs`. The published `omnodex` package also ships the command as `omnodex-sealed-hook`.
