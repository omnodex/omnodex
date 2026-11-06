// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { EXPORT_FLAGS, EXPORT_VALUES } from "./export-command.js";
import { POLICY_ADD_FLAGS, POLICY_ADD_VALUES, POLICY_WATCH_FLAGS, POLICY_WATCH_VALUES } from "./policy-command.js";

interface CommandOptions {
  usage: string;
  description: string;
  flags?: readonly string[];
  values?: readonly string[];
  /** Install's bundle options also accept --name=value. */
  joined?: readonly string[];
  subcommands?: Record<string, CommandOptions>;
}

const pauseCommands: Record<string, CommandOptions> = {
  pause: { usage: "pause [duration]", description: "Pause until resumed, or for a duration like 30m, 1h or 2d. Requires confirmation at a terminal." },
  resume: { usage: "resume", description: "Resume this machine." },
  status: { usage: "status", description: "Show this machine's pause state." },
};

/** Accepted options and help for the commands dispatched by index.ts. */
export const COMMAND_OPTIONS: Record<string, CommandOptions> = {
  update: {
    usage: "update", description: "Check for and install updates.",
    flags: ["--check", "--refresh-launchers", "--refresh-plugins"],
  },
  install: {
    usage: "install [target] [project]", description: "Install hooks and plugins. Targets: claude-code, codex, antigravity (or agy), copilot. Without a target, detect installed agents.",
    flags: ["--everywhere", "--this-project", "--yes", "-y", "--debug", "--no-connect", "--legacy-shim", "--project-settings", "--hooks", "--plugin", "--mcp"],
    values: ["--plugin-version", "--from", "--sha256"],
    joined: ["--plugin-version", "--from", "--sha256"],
  },
  uninstall: {
    usage: "uninstall [target] [project]", description: "Remove hooks or plugins. Removing monitoring requires a person at a terminal unless --unattended is given.",
    flags: ["--confirm", "--unattended", "--everywhere", "--plugin", "--hooks"],
  },
  status: { usage: "status [project]", description: "Show installations and monitoring health.", flags: ["--all"] },
  spike: {
    usage: "spike [name]", description: "Build synthetic sessions. Scenario sets: movement or history. History requires --machine a or b.",
    flags: ["--random"], values: ["--seed", "--now", "--sessions", "--scenario-set", "--machine"],
  },
  detect: { usage: "detect [session]", description: "Scan event logs for risks across configured roots.", values: ["--roots"] },
  clear: {
    usage: "clear <session-id> | --all --confirm", description: "Permanently delete one session, or all local data. Requires a person at a terminal unless --unattended is given; scripted clears are recorded and raise a finding.",
    flags: ["--all", "--confirm", "--unattended"],
  },
  replay: { usage: "replay", description: "Rebuild the read model from configured event log roots.", values: ["--roots"] },
  report: { usage: "report", description: "Print a summary of sessions in the read model." },
  dashboard: { usage: "dashboard [port]", description: "Start the local dashboard (default port 7890).", flags: ["--no-detect"], values: ["--roots"] },
  "mcp-proxy": {
    usage: "mcp-proxy <subcommand>", description: "Manage the MCP proxy interceptor.",
    subcommands: {
      start: { usage: "start", description: "Start the proxy on stdin/stdout.", values: ["--config"] },
      serve: { usage: "serve --http <host:port>", description: "Serve Streamable HTTP. Remote access requires OMNODEX_PROXY_HTTP_TOKEN.", flags: ["--allow-remote"], values: ["--http", "--config"] },
      install: { usage: "install", description: "Create a template proxy config if missing." },
      status: { usage: "status", description: "Show configured upstream servers." },
    },
  },
  license: {
    usage: "license [clear]", description: "Show the current license tier and features.", values: ["--token", "--api"],
    subcommands: { clear: { usage: "clear", description: "Remove the cached license." } },
  },
  connect: {
    usage: "connect", description: "Connect this machine to the cloud dashboard. Without a token, start device authorization.",
    values: ["--token", "--secret", "--passphrase", "--api", "--platform"],
  },
  sync: {
    usage: "sync [pause [duration] | resume | status]", description: "Encrypt local sessions and upload them (Hosted or above), or control uploads on this machine.",
    values: ["--token", "--secret", "--passphrase", "--api", "--sessions"], subcommands: pauseCommands,
  },
  record: { usage: "record pause [duration] | resume | status", description: "Control recording on this machine.", subcommands: pauseCommands },
  enforce: {
    usage: "enforce monitor | shadow | guardrails | status", description: "Choose how Omnodex acts on calls. Leaving guardrails requires confirmation at a terminal.",
    subcommands: {
      monitor: { usage: "monitor", description: "Record and flag calls without stopping them." },
      shadow: { usage: "shadow", description: "Also record what enforcement would have stopped." },
      guardrails: { usage: "guardrails", description: "Stop or hold calls as configured (Pro)." },
      status: { usage: "status", description: "Show the current enforcement mode." },
    },
  },
  policy: {
    usage: "policy list | add | watch <path> | remove <id> | pull", description: "This machine's policy entries for findings. Allowing, muting, lowering a severity, or removing a watch or an entry that blocks, holds or raises one requires confirmation at a terminal.",
    subcommands: {
      list: { usage: "list", description: "Show every entry, the older per-rule and exception settings included." },
      add: {
        usage: "add --rule <id> | --category <name> | --severity <level> [target] [--project <root> | --here] <effect>",
        description: "Add an entry. Targets: --path, --destination, --command-prefix, --credential, --tool [--server], --reads, --writes. Effects: --block or --hold (Pro), --allow, --mute, --unmute, --set-severity <level>.",
        flags: [...POLICY_ADD_FLAGS],
        values: [...POLICY_ADD_VALUES],
      },
      watch: {
        usage: "watch <path> [--project <root> | --here] [--block | --hold] [--note <text>]",
        description: "Raise a HIGH finding when a tool call changes, moves or deletes a file, folder or glob. Reads do not count, and neither do changes a tool call does not name. --block and --hold need Pro.",
        flags: [...POLICY_WATCH_FLAGS],
        values: [...POLICY_WATCH_VALUES],
      },
      remove: { usage: "remove <id>", description: "Remove an entry by the id `policy list` shows." },
      pull: { usage: "pull", description: "Fetch the entries made for your whole account in the hosted dashboard." },
    },
  },
  export: {
    usage: "export --out <file|-> [--format jsonl|ocsf] [--since <time>] [--until <time>] [--follow]",
    description: "Write events and findings from the local event log to a file as JSON lines (jsonl) or OCSF, for a SIEM collector to read. Prompt text, tool parameters, session titles and error text are left out unless named in --include (prompts, parameters, titles, errors or all). --since takes a date or an age such as 24h or 7d. --follow keeps running, appends new events, rotates the file at --max-size (default 50m, keeping --keep files, default 5) and resumes from a watermark file after a restart.",
    flags: [...EXPORT_FLAGS],
    values: [...EXPORT_VALUES],
  },
  live: {
    usage: "live [resume | status]", description: "Show or clear the live push back-off gate.",
    subcommands: {
      resume: { usage: "resume", description: "Clear the gate so the next event pushes at once." },
      status: { usage: "status", description: "Show the current live push gate." },
    },
  },
};

function selectedOptions(command: string, args: readonly string[]): { options: CommandOptions; prefix: string } | undefined {
  const options = Object.hasOwn(COMMAND_OPTIONS, command) ? COMMAND_OPTIONS[command] : undefined;
  if (!options) return undefined;
  const sub = args[0];
  if (options.subcommands && sub && Object.hasOwn(options.subcommands, sub)) {
    return { options: options.subcommands[sub], prefix: `${command} ` };
  }
  return { options, prefix: "" };
}

/** Help is resolved before update checks, launcher refreshes or any handler. */
export function commandHelp(command: string, args: readonly string[]): string | undefined {
  const selected = selectedOptions(command, args);
  if (!selected) return undefined;
  const { options, prefix } = selected;
  const lines = [`Usage: omnodex ${prefix}${options.usage}`, "", options.description];
  if (options.subcommands) lines.push("", `Subcommands: ${Object.keys(options.subcommands).join(", ")}`);
  lines.push("", "Options:", "  --help, -h  Show help without running the command.");
  for (const flag of options.flags ?? []) lines.push(`  ${flag}`);
  for (const flag of options.values ?? []) lines.push(`  ${flag} <value>`);
  return lines.join("\n");
}

/** Reject unrecognized flags before even the CLI's startup housekeeping runs. */
export function commandOptionError(command: string, args: readonly string[]): string | undefined {
  const selected = selectedOptions(command, args);
  if (!selected) return undefined;
  const { options } = selected;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith("-")) continue;
    if (options.flags?.includes(arg)) continue;
    if (options.values?.includes(arg)) {
      const value = args[++i];
      if (value === undefined || value.startsWith("--")) return `${arg} requires a value`;
      continue;
    }
    const equals = arg.indexOf("=");
    if (equals > 0 && options.joined?.includes(arg.slice(0, equals)) && arg.length > equals + 1) continue;
    return `unknown option '${arg}' for ${command}`;
  }
  return undefined;
}
