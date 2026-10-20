# Synthetic scenario coverage

`buildScenarios(options)` is exported by `@omnodex/hooks-provider`. It returns
raw `TraceEvent` objects and performs no tool calls, network requests or file
operations. The CLI appends these through `EventLog`, runs the community batch
analyzer, then rebuilds SQLite and correlates hook and proxy observations.

Defaults are seed `1`, clock `2026-10-01T12:00:00.000Z`, and 12 sessions.
Pass `now` to place events in the two hours preceding another clock. Pass
`existingSessionIds` when appending: the builder reserves a new run namespace.
Identical options and existing IDs produce identical raw events. CLI session
logs, including real findings, are reproducible in fresh homes; the event-log
index has wall-clock registration timestamps and is not a fixture snapshot.

All rows below are asserted in `packages/cli/test/scenario-builder.test.mjs`
by `scenario manifest and real rule catalog`, across five seeds. The rule
catalog assertion compares to the live `COMMUNITY_RULES` export and fails
when a new rule lacks coverage.

| Scenario | Builder fixture | Assertion |
| --- | --- | --- |
| Sensitive read, credential exposure, outbound credential payload | `credentials` | Sensitive-path, credential-in-params and credential-exfil rules fire |
| Wallet CLI, private key, mnemonic | `wallet` | All three wallet rules fire |
| Known cloud IP, unknown IP, IOC host | `network` | Both outbound-IP rules and IOC-domain rule fire |
| Tool shadow, new server, skill manipulation, dependency confusion | `supply-chain` | Corresponding supply-chain rules fire |
| Hook, MCP URL, command config writes, workspace context read | `supply-chain` | Remaining supply-chain config rules fire |
| SQL injection | `sql` | SQL rule fires |
| Destructive, encoded, reverse-shell, metadata, archive, tunnel, audit, publish, API override | `commands` | Each threat-command rule fires |
| Persistence, cross-agent auth, sandbox disable, self-protection, boundary write | `configuration`, `supply-chain` | Each corresponding community rule fires |
| Burst and sustained rate | `rate` | Both rate rules fire |
| Clean work, Windows and POSIX projects | Extra sessions | Zero-risk session, project paths, and file read/write counts |
| Completed, errored, interrupted, active session | Final three plus completed fixtures | All four session states |
| Success, error, active tool | Final two sessions | All three tool states and invocation/completion pairing |
| Claude Code, Codex, Antigravity, Cowork | Round-robin sessions | All four platforms; Cowork uses proxy only |
| Correlated hook and proxy | Sessions 8 and 9 | Exactly two rows share a correlation ID |
| Prompts, titles and untitled fallbacks | Every session | Prompts with/without ID; renamed and untitled sessions |
| Subagent attribution | `credentials` | Start/stop plus attributed tool calls |
| Permission requested/denied | `credentials` | Both raw event types exist |
| Reproducibility and append safety | All | Byte equality; different seed output; unique event/call IDs across three runs |
| Real disk pipeline | CLI integration test | Byte-identical session logs, SQLite replay, append safety and random seeds |

`web` and `copilot` are unsupported because there is no interceptor.
Permission events are emitted in the log but are not projected or displayed.
Machine labels in synthetic user names distinguish fixture contexts; actual
machine identity is sync-envelope metadata, outside the raw event schema.
The generator does not invent machine fields or change capture/projection.

## Movement fixtures

`buildMovementScenarios(options)` includes ten additional chains, or use
`spike --scenario-set movement` (22 sessions minimum/default). The reusable
`MOVEMENT_SCENARIOS` export is also accepted by `buildScenarios` through
`additionalScenarios`. Every chain runs as an isolated, completed session.
Nothing is executed, and the movement set contains no secret values. Sinks
name reserved hosts that never resolve: RFC 2606 example domains, the
`.invalid` TLD and the RFC 5737 documentation range `198.51.100.0/24`.
Outbound detection treats them as external, so the chains produce real
findings. Routine counterparts use loopback or a host the session already
called. The normal community fixtures are still included separately.

| Fixture | Sequence | Routine counterpart |
| --- | --- | --- |
| `credential-body` | Credential path read, then body upload to `upload.example.org` | `provider-auth`: local provider emulator authentication on loopback |
| `credential-staged` | Credential path read, archive of that file, upload same archive to `paste.example.net` | `release-staged`: project release archive uploaded to the release host the session already called |
| `sensitive-new-destination` | Sensitive path read, then upload to `198.51.100.23` | `tests-usual-api`: earlier `api.example.com` health call, environment read, tests, same health endpoint |
| `credential-outside-write` | Credential path read, outside write | `login-config-write`: CLI login followed by config write |
| `staged-path-mismatch` | Credential archive, upload a different file to `drop.example.invalid` | Tests path linkage independently of staging presence |
| `windows-credential-copy` | Windows credential path read and outside write | Keeps Windows path semantics represented |

`packages/cli/test/movement-scenarios.test.mjs` verifies these sequences across
five seeds, checks that every normalized destination is loopback or reserved,
and pins the community findings each chain raises through the batch analyzer.
The upload to `198.51.100.23` raises the unknown-IP outbound finding; uploads
to reserved names raise no community finding of their own, since no community
rule follows data from a read into a later upload.
