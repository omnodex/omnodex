# Exporting events

`omnodex export` writes events and findings from the local event log to a
file as JSON lines. It reads local files and writes one local file. It opens
no connection, so a collector already on the machine (a SIEM forwarder, a log
agent) can tail the file and send it on.

```bash
# Everything from the last week, in Omnodex's own form
omnodex export --out events.jsonl --since 7d

# OCSF, kept running: new events are appended, the file rotates by size
omnodex export --format ocsf --follow --out /var/log/omnodex/events.ocsf.jsonl
```

## Options

| Option | Meaning |
| --- | --- |
| `--out <file>` | Required. The file to write, or `-` for standard output (messages go to standard error). A one-shot export replaces the file. |
| `--format jsonl\|ocsf` | `jsonl` (default) is Omnodex's normalized event. `ocsf` is the same event mapped to OCSF. |
| `--since <time>` | Start of the window: a date or timestamp, or an age such as `30m`, `24h` or `7d`. |
| `--until <time>` | End of the window (not included). Not with `--follow`. |
| `--follow` | Keep running. Appends new events until stopped with Ctrl+C. |
| `--include <groups>` | Content to add back, comma separated: `prompts`, `parameters`, `titles`, `errors`, or `all`. |
| `--max-size <size>` | With `--follow`: rotate the file at this size (`512k`, `50m`, `1g`, or bytes). Default `50m`. |
| `--keep <n>` | With `--follow`: rotated files to keep (`events.jsonl.1` is the newest). Default `5`. |

All roots Omnodex reads elsewhere (`OMNODEX_HOME`, the default home, and roots
named in its configuration) are exported together, oldest event first.

## What is left out

Metadata and findings are exported. Anything a person typed or a tool printed
is left out unless you ask for it:

| Group | Fields removed without it |
| --- | --- |
| `prompts` | `prompt` |
| `parameters` | `parameters` (tool calls, permission requests and denials) |
| `titles` | `title` (session names) |
| `errors` | `error_message`, `reason` |

An event that had a field removed lists it under `redacted`, so a reader can
tell a removed field from one the event never had. The event log holds no file
contents, only paths and sizes, so no export contains them. Finding
descriptions, file paths and working directories are metadata and are always
exported.

## Following

With `--follow` and a file output:

- With no `--since`, the export starts at the end of the log and carries only
  events recorded from now. With `--since`, it first exports history from that
  time.
- The command keeps `<file>.watermark.json` beside the output. After a restart
  it resumes from there, so events are neither skipped nor repeated. If the
  command stops between writing events and saving the watermark, the last batch
  can appear twice (delivery is at least once). `--since` applies only to the
  first run. Delete the watermark to start over.
- When the next write would take the file past `--max-size`, the file is
  renamed to `<file>.1`, older rotated files move up, and any beyond `--keep`
  are deleted. The file is not held open between writes, so a collector that
  follows it by name sees an ordinary rename.

## Normalized event (`jsonl`)

One JSON object per line. It is the logged event with the redaction above
applied, plus `export_schema`, and without the log's own `schema_version`:

```json
{"export_schema":"omnodex.event/1","event_id":"...","event_type":"tool.invoked",
 "session_id":"...","occurred_at":"2026-11-06T12:00:00.000Z",
 "recorded_at":"2026-11-06T12:00:00.100Z","interceptor":"claude-code-hook",
 "platform":"claude-code","tool_call_id":"...","tool_name":"Bash",
 "mcp_server":"builtin","cwd":"/home/case/repo","redacted":["parameters"]}
```

Common fields on every event: `event_id`, `event_type`, `session_id`,
`occurred_at`, `recorded_at` (ISO 8601), `interceptor`; and, when known,
`platform`, `agent_id`, `local_only`. The other fields depend on `event_type`:

| `event_type` | Fields |
| --- | --- |
| `session.started` | `user`, `project_path`, `mcp_servers`, `model`, `project_remote` |
| `session.ended` | `duration_ms`, `status` |
| `session.renamed` | `title` (with `titles`) |
| `session.model_changed` | `model`, `previous`, `source` |
| `tool.invoked` | `tool_call_id`, `tool_name`, `mcp_server`, `cwd`, `parameters` (with `parameters`) |
| `tool.completed` | `tool_call_id`, `duration_ms`, `status`, `response_bytes`, `error_message` (with `errors`) |
| `file.read`, `file.written` | `path`, `bytes` |
| `risk.detected` | `severity`, `category`, `description`, `rule_id`, `rule_tier`, `related_event_id`, `related_event_ids`, `evidence`, `enforcement`, `recommended_severity` |
| `prompt.submitted` | `prompt_id`, `prompt` (with `prompts`) |
| `permission.requested`, `permission.denied` | `tool_name`, `mcp_server`, `tool_call_id`, `parameters` (with `parameters`), `reason` (with `errors`) |
| others | Capture pause and resume, monitoring changes, subagent, sync and server events keep the fields they are logged with. |

## OCSF mapping (`ocsf`)

Each normalized event becomes one OCSF event, mapped against OCSF 1.3.0. The
mapping reads the redacted event, so content that was removed cannot appear.

| Omnodex event | OCSF class | Activity |
| --- | --- | --- |
| `tool.invoked` | API Activity (6003) | Other (99), named Invoke. `api.operation` is the tool, `api.service.name` the MCP server (`builtin` for the agent's own tools). |
| `tool.completed` | API Activity (6003) | Other (99), named Complete. `status_id` 1 for success, 2 for error. `api.request.uid` is the tool call id. |
| `file.read` | File System Activity (1001) | Read (2). `file.path`, `file.name`, `file.size`. |
| `file.written` | File System Activity (1001) | Update (3). |
| `risk.detected` | Detection Finding (2004) | Create (1). `finding_info` carries the category as title, the description, and the rule as `analytic`; `severity_id` is LOW 2, MEDIUM 3, HIGH 4, CRITICAL 5. |
| `session.started` | Application Lifecycle (6002) | Start (3). `app.name` is the agent platform. |
| `session.ended` | Application Lifecycle (6002) | Stop (4). `status_id` 2 when the session errored. |
| anything else | Base Event (0) | Other (99), named by the Omnodex event type. Its remaining fields are under `unmapped.data`. |

Common to all: `time` (epoch milliseconds of `occurred_at`),
`metadata.uid` (the event id), `metadata.logged_time`, `metadata.product`,
`actor.session.uid`, and `actor.app_name` (the agent platform). Other events
carry severity Informational.

OCSF has no field for several things Omnodex knows. They are kept under
`unmapped`: `omnodex_event_type`, `interceptor`, `platform`, `agent_id`,
`mcp_server`, `tool_call_id`, `cwd`, `model`, `local_only`, `redacted`, plus
per class details such as `duration_ms`, `project_path`, `evidence`,
`enforcement` and, with `--include parameters`, `parameters`.

The class and activity numbers were checked against the published OCSF schema.
The output has not been run through an OCSF validator.
