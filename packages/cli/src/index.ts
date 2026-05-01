#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
/**
 * @omnodex/cli
 *
 * CLI that wires the full pipeline end to end:
 *
 *   interceptor  ->  event log  ->  projector  ->  SQLite read model  ->  report
 *
 * Commands:
 *
 *   omnodex spike            run a simulated session through the full pipeline
 *   omnodex replay           rebuild the SQLite read model by replaying the event log
 *   omnodex report           print a summary of sessions in the read model
 *
 * All data is written under $OMNODEX_HOME, defaulting to ~/.omnodex.
 */

import * as os from "node:os";
import * as path from "node:path";
import { promises as fs } from "node:fs";
import { EventLog, newEventId } from "@omnodex/event-log";
import {
  Projector,
  SqliteReadModelStore,
  type ReadModelStore,
} from "@omnodex/projection";
import {
  CLAUDE_HOOK_SHIM_PATH,
  ClaudeCodeInterceptor,
  MockInterceptor,
} from "@omnodex/hooks-provider";
import { startDashboardServer } from "./dashboard-server.js";
import { detectRisks } from "./detector.js";
import type { TraceEvent } from "@omnodex/shared";

interface Paths {
  home: string;
  eventLogRoot: string;
  dbPath: string;
}

function resolvePaths(): Paths {
  const home = process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
  return {
    home,
    eventLogRoot: path.join(home, "event-log"),
    dbPath: path.join(home, "traces.db"),
  };
}

async function openStore(paths: Paths): Promise<ReadModelStore> {
  const store = new SqliteReadModelStore({ dbPath: paths.dbPath });
  await store.init();
  return store;
}

async function cmdSpike(args: string[]): Promise<void> {
  const paths = resolvePaths();

  // Optional session name: `omnodex spike my-test` → sess_my-test
  // If omitted, MockInterceptor generates a unique timestamp-based ID.
  const rawName = args.find((a) => !a.startsWith("--"));
  const sessionId = rawName ? `sess_${rawName}` : undefined;

  console.log(`[spike] OMNODEX_HOME=${paths.home}`);
  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();

  const interceptor = new MockInterceptor({ sessionId });
  const events = interceptor.buildSessionEvents();
  const usedSessionId = events[0]?.session_id ?? "unknown";
  console.log(`[spike] session ID: ${usedSessionId}`);
  console.log(`[spike] mock interceptor emitted ${events.length} events`);
  for (const event of events) {
    await log.append(event);
  }
  await log.close();
  console.log(
    `[spike] appended ${events.length} events to ${log.sessionFilePath(usedSessionId)}`,
  );

  console.log(`[spike] building read model ...`);
  const store = await openStore(paths);
  const projector = new Projector(store);
  await projector.replay(iterateLog(log));
  await printReport(store);
  await store.close();
  console.log(`[spike] done`);
}

async function cmdReplay(): Promise<void> {
  const paths = resolvePaths();
  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();
  const store = await openStore(paths);
  const projector = new Projector(store);
  await projector.replay(iterateLog(log));
  console.log(`[replay] rebuilt read model at ${paths.dbPath}`);
  await store.close();
}

/**
 * Clear session data.
 *
 *   omnodex clear <session-id>          remove one session from event log + read model
 *   omnodex clear --all --confirm       PERMANENTLY delete all data under OMNODEX_HOME
 *
 * The --all flag requires --confirm to prevent accidental data loss.
 */
async function cmdClear(args: string[]): Promise<void> {
  const paths = resolvePaths();
  const sessionId = args.find((a) => !a.startsWith("--"));
  const wipeAll = args.includes("--all");
  const confirmed = args.includes("--confirm");

  if (!sessionId && !wipeAll) {
    console.error(
      `[clear] error: specify a session ID to remove, or use --all --confirm to delete everything.
` +
      `
` +
      `  omnodex clear <session-id>       remove one session
` +
      `  omnodex clear --all --confirm    !! permanently delete all data under ${paths.home}
`,
    );
    process.exitCode = 2;
    return;
  }

  if (wipeAll && !confirmed) {
    console.error(
      `[clear] !! WARNING: --all will permanently delete ALL session data at:
` +
      `         ${paths.home}
` +
      `
` +
      `         This cannot be undone. Re-run with --all --confirm to proceed.
`,
    );
    process.exitCode = 2;
    return;
  }

  if (wipeAll && confirmed) {
    // Wipe everything
    await fs.rm(paths.home, { recursive: true, force: true });
    console.log(`[clear] removed all data at ${paths.home}`);
    return;
  }

  // --- Remove a single session ---
  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();

  // 1. Delete the session's JSONL file.
  const sessionFile = log.sessionFilePath(sessionId);
  await fs.rm(sessionFile, { force: true });

  // 2. Rewrite the event log index without this session.
  const indexPath = path.join(paths.eventLogRoot, "index.jsonl");
  const raw = await fs.readFile(indexPath, "utf8").catch(() => "");
  const kept = raw
    .split("
")
    .filter((line) => {
      if (!line.trim()) return false;
      try {
        const entry = JSON.parse(line) as { session_id?: string };
        return entry.session_id !== sessionId;
      } catch {
        return true; // keep malformed lines as-is
      }
    })
    .join("
");
  await fs.writeFile(indexPath, kept ? kept + "
" : "", "utf8");
  await log.close();

  // 3. Rebuild the read model from remaining sessions.
  const store = await openStore(paths);
  const projector = new Projector(store);
  const freshLog = new EventLog({ root: paths.eventLogRoot });
  await freshLog.init();
  await projector.replay(iterateLog(freshLog));
  await freshLog.close();
  await store.close();

  console.log(`[clear] removed session ${sessionId}`);
}

async function cmdReport(): Promise<void> {
  const paths = resolvePaths();
  const store = await openStore(paths);
  await printReport(store);
  await store.close();
}

async function printReport(store: ReadModelStore): Promise<void> {
  const sessions = await store.listSessions();
  if (sessions.length === 0) {
    console.log("[report] no sessions in read model");
    return;
  }
  console.log(`[report] ${sessions.length} session(s)`);
  for (const session of sessions) {
    console.log("");
    console.log(`  session_id:      ${session.session_id}`);
    console.log(`  user:            ${session.user}`);
    console.log(`  mcp_servers:     ${session.mcp_servers.join(", ")}`);
    console.log(`  status:          ${session.status}`);
    console.log(`  duration_ms:     ${session.duration_ms ?? "?"}`);
    console.log(`  tool_calls:      ${session.tool_call_count}`);
    console.log(`  file_reads:      ${session.file_read_count}`);
    console.log(`  file_writes:     ${session.file_write_count}`);
    console.log(`  risk_score:      ${session.risk_score}`);
    const risks = await store.listRiskEvents(session.session_id);
    if (risks.length > 0) {
      console.log(`  risk_events:`);
      for (const risk of risks) {
        console.log(
          `    [${risk.severity}] ${risk.category}: ${risk.description} (rule ${risk.rule_id})`,
        );
      }
    }
  }
}

/**
 * Run the risk detector against all sessions in the event log.
 *
 *   omnodex detect              scan all sessions
 *   omnodex detect <session-id> scan one session
 *
 * Appends new risk.detected events to the log. Idempotent: re-running
 * skips risks that have already been detected for the same rule + tool call.
 */
async function cmdDetect(args: string[]): Promise<void> {
  const paths = resolvePaths();
  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();

  const targetSession = args.find((a) => !a.startsWith("--"));
  const sessionIds = targetSession
    ? [targetSession]
    : await log.listSessions();

  if (sessionIds.length === 0) {
    console.log("[detect] no sessions in event log");
    return;
  }

  let totalNew = 0;
  let totalSkipped = 0;

  for (const sessionId of sessionIds) {
    const events = await log.readSession(sessionId);
    if (events.length === 0) continue;

    const result = detectRisks(events, newEventId);
    totalSkipped += result.skipped;

    if (result.newEvents.length > 0) {
      await log.appendMany(result.newEvents);
      totalNew += result.newEvents.length;
      console.log(
        `[detect] ${sessionId}: ${result.newEvents.length} new risk(s) detected`,
      );
      for (const re of result.newEvents) {
        console.log(`  [${re.severity}] ${re.category}: ${re.description}`);
      }
    } else {
      console.log(`[detect] ${sessionId}: no new risks`);
    }
  }

  await log.close();
  console.log(
    `[detect] done. ${totalNew} new risk event(s), ${totalSkipped} already known.`,
  );

  if (totalNew > 0) {
    console.log(`[detect] run \`omnodex replay\` to rebuild the read model, or \`omnodex dashboard\` (which replays automatically).`);
  }
}

async function* iterateLog(log: EventLog): AsyncGenerator<TraceEvent> {
  for await (const event of log.readAll()) {
    yield event;
  }
}

async function cmdDashboard(args: string[]): Promise<void> {
  const paths = resolvePaths();
  const port = parseInt(args[0] ?? "7890", 10);
  const skipDetect = args.includes("--no-detect");

  // Run risk detection before replaying (unless --no-detect).
  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();

  if (!skipDetect) {
    const sessionIds = await log.listSessions();
    let detected = 0;
    for (const sessionId of sessionIds) {
      const events = await log.readSession(sessionId);
      if (events.length === 0) continue;
      const result = detectRisks(events, newEventId);
      if (result.newEvents.length > 0) {
        await log.appendMany(result.newEvents);
        detected += result.newEvents.length;
      }
    }
    if (detected > 0) {
      console.log(`[dashboard] auto-detected ${detected} new risk event(s)`);
    }
  }

  // Rebuild the read model by replaying the full log (including any new risk events).
  const store = await openStore(paths);
  const projector = new Projector(store);
  await projector.replay(iterateLog(log));

  const assetsDir = new URL(".", import.meta.url).pathname;
  startDashboardServer({ store, port, assetsDir });

  console.log(`[dashboard] open http://localhost:${port} in your browser`);
  console.log(`[dashboard] press Ctrl+C to stop`);

  // Keep process alive
  await new Promise(() => {});
}

async function cmdInit(args: string[]): Promise<void> {
  const projectPath = path.resolve(args[0] ?? process.cwd());
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const useProjectSettings = args.includes("--project-settings");

  const interceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath: CLAUDE_HOOK_SHIM_PATH,
    omnodexHome: paths.home,
    settingsFile: useProjectSettings ? "settings.json" : "settings.local.json",
    debug,
  });
  await interceptor.install();
  console.log(`[init] installed Omnodex hooks into`);
  console.log(`       ${interceptor.settingsFilePath()}`);
  console.log(`[init] shim:         ${CLAUDE_HOOK_SHIM_PATH}`);
  console.log(`[init] OMNODEX_HOME: ${paths.home}`);
  console.log(
    `[init] run \`omnodex uninit ${projectPath}\` to remove them again`,
  );
}

async function cmdUninit(args: string[]): Promise<void> {
  const projectPath = path.resolve(args[0] ?? process.cwd());
  const paths = resolvePaths();
  const useProjectSettings = args.includes("--project-settings");

  const interceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath: CLAUDE_HOOK_SHIM_PATH,
    omnodexHome: paths.home,
    settingsFile: useProjectSettings ? "settings.json" : "settings.local.json",
  });
  await interceptor.uninstall();
  console.log(`[uninit] removed Omnodex hooks from`);
  console.log(`         ${interceptor.settingsFilePath()}`);
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
    case "init":
      await cmdInit(rest);
      return;
    case "uninit":
      await cmdUninit(rest);
      return;
    case "spike":
      await cmdSpike(rest);
      return;
    case "detect":
      await cmdDetect(rest);
      return;
    case "clear":
      await cmdClear(rest);
      return;
    case "replay":
      await cmdReplay();
      return;
    case "report":
      await cmdReport();
      return;
    case "dashboard":
      await cmdDashboard(rest);
      return;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(`omnodex

commands:
  init [project]     install Claude Code hooks into the given project
                     (defaults to cwd). Flags:
                       --debug               enable verbose shim logging
                       --project-settings    edit settings.json instead of
                                             settings.local.json
  uninit [project]   remove Omnodex-managed Claude Code hooks
  spike [name]       run a simulated session through the full pipeline.
                     Optional name sets the session ID (sess_<name>); if
                     omitted a unique timestamp-based ID is generated so
                     successive runs each create a distinct session.
  detect [session]   scan event log for risk patterns and append
                     ris
