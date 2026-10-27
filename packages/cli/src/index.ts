#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
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
 *   omnodex replay           rebuild the read model by replaying every root's event log
 *   omnodex report           print a summary of sessions in the read model
 *   omnodex mcp-proxy        manage the MCP proxy interceptor (start/install/status)
 *
 * All data is written under $OMNODEX_HOME, defaulting to ~/.omnodex.
 */

import { skipConnectReason } from "./connect-prompt.js";
import { commandHelp, commandOptionError } from "./command-options.js";
import * as os from "node:os";
import * as readline from "node:readline/promises";
import * as path from "node:path";
import { promises as fs } from "node:fs";
import { EventLog, applyCapturePause, newEventId } from "@omnodex/event-log";
import { appendMarkers, captureStatusLines, processIo, runCaptureControl } from "./capture-controls.js";
import { recordMonitoringChange, setMarkerPush, setMonitoringActor } from "./monitoring-markers.js";
import { currentMode, offerShadowMode, runEnforce, type GuardrailsReadiness } from "./enforce-command.js";
import { describeGuardrails, loadGuardrailsModule } from "@omnodex/analyzer/enforcement";
import { pauseRows } from "./dashboard-model/pauses.js";
import {
  Projector,
  SqliteReadModelStore,
  inTransaction,
  runCorrelation,
  type ReadModelStore,
} from "@omnodex/projection";
import {
  CLAUDE_HOOK_SHIM_PATH,
  ClaudeCodeInterceptor,
  buildHistoryScenarios,
  buildScenarios,
  DEFAULT_SCENARIO_SEED,
} from "@omnodex/hooks-provider";
import { parseSpikeOptions } from "./spike-options.js";
import {
  CODEX_HOOK_SHIM_PATH,
  CodexInterceptor,
} from "@omnodex/codex-provider";
import {
  ANTIGRAVITY_HOOK_SHIM_PATH,
  AntigravityInterceptor,
} from "@omnodex/antigravity-provider";
import { MCPProxy, createToolListSnapshots, loadProxyConfig, parseHttpListen } from "@omnodex/mcp-proxy";
import { DashboardServer, resolveDashboardAssetsDir, shutdownDashboard } from "./dashboard-server.js";
import { advancedEntitled, advancedFindingsText, shownFindings } from "./advanced-findings.js";
import { startStreamingLoop, type StreamingRoot } from "./streaming.js";
import { resolveRoots, parseRootsFlag } from "./config.js";
import {
  COMMUNITY_RULES,
  describeRules,
  detectEventLogs,
  detectRisks,
  loadAdvancedRules,
  openMachineState,
  registryForHost,
  runBackgroundDetection,
} from "@omnodex/analyzer";
import { CAPTURE_CONTROL_SESSION_ID } from "@omnodex/shared";
import type { TraceEvent } from "@omnodex/shared";
import { validateLicense, clearCache as clearLicenseCache } from "@omnodex/license-client";
import {
  StreamingTransport,
  deriveStreamingKey,
  computeKeyId,
  AUTO_SYNC_CHILD_ENV,
  readAutoSyncState,
  recordSyncOutcome,
  syncDeferred,
  acquireSyncLock,
  SyncBlobTooLargeError,
  SyncTooSoonError,
  SYNC_BLOB_MAX_BYTES,
  runAutoSync,
  startBackgroundSync,
  readLiveGate,
  clearLiveGate,
  pushEventsToCloud,
  readAdvancedUsage,
  ADVANCED_USAGE_MAX_AGE_DAYS,
  probeStreamToken,
  collectRotatedToken,
  streamHasSecret,
  ensureSecretVerifier,
  SecretMismatchError,
  guardrailsEntitled,
  refreshGuardrailsModule,
  checkMonitoringConfig,
} from "@omnodex/sync-encryptor";
import type { AdvancedUsageState, InstallationCheck, InstallationState } from "@omnodex/sync-encryptor";
import { syncReadModel } from "@omnodex/sync-encryptor/sync-runner";
import {
  generatePassphrase,
  updateStreamConfig,
  resolveCredentials,
  readStreamConfig,
  writeStreamConfig,
} from "./stream-config.js";
import { canonicalTarget, createClaim, platformFromTarget } from "./connect.js";
import {
  writeLauncher,
  launcherPath,
  launcherHomeRelativePath,
  refreshStaleLaunchers,
  resolveLauncherShim,
  ensureLauncherResolves,
  shimFilename,
  LAUNCHER_PLATFORMS,
} from "./launcher-template.js";
import type { LauncherPlatform } from "./launcher-template.js";
import { PLUGIN_PINS } from "./plugin-pins.js";
import { SURFACE_PLUGIN, downloadsBaseUrl, installPlugin, pluginDir, resolveBundle, uninstallPlugin } from "./plugins.js";
import { SURFACE_LABELS, defaultWslProbe, detectSurfaces, detectWsl, wslNote, type Surface } from "./surfaces.js";
import { addInstallation, removeInstallation, listInstallations, findInstallations, findStaleInstallations, getInstalledVersion } from "./registry.js";
import {
  USER_SCOPE_ARG,
  addExclusion,
  exclusionFor,
  isEverywhere,
  readHookScope,
  removeExclusion,
  setEverywhere,
  userHooksFile,
} from "./hook-scope.js";
import { findMissingHookPaths } from "./hook-paths.js";
import { runUpdate, printUpdateNotification, scheduleBackgroundCheck, detectInstallMethod, getSourceInstallInfo } from "./update.js";
import { runDeviceAuthFlow } from "./device-auth.js";
import { bootstrapCloudConnection, describeBootstrap } from "./cloud-bootstrap.js";
// ValidateResult type available if needed for future use

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

/**
 * Whether hook commands can use the host-neutral `node "$HOME/..."` form.
 * That form carries no env prefix, so it needs the launcher (not a legacy
 * absolute shim path), no --debug, and the default OMNODEX_HOME, which the
 * shim falls back to by itself on each host.
 */
function canUsePortableHookCommand(
  paths: Paths,
  opts: { useLegacy: boolean; debug: boolean },
): boolean {
  return (
    !opts.useLegacy &&
    !opts.debug &&
    path.resolve(paths.home) === path.resolve(os.homedir(), ".omnodex")
  );
}

/**
 * Check that this host's launcher finds a shim, pinning the running CLI's own
 * shim in omnodex-config.json when it does not (source checkouts, installs
 * outside the usual npm locations). Without this, hooks exit 0 and record
 * nothing, which is easy to miss.
 */
async function checkLauncherShim(
  platform: LauncherPlatform,
  omnodexHome: string,
  ownShimPath: string,
): Promise<void> {
  const candidates = [ownShimPath];
  if (process.argv[1]) {
    try {
      // Published npm package: shims sit beside the CLI entry point in bin/.
      const entryDir = path.dirname(await fs.realpath(process.argv[1]));
      candidates.push(path.join(entryDir, shimFilename(platform)));
    } catch { /* entry point not on disk */ }
  }
  const check = await ensureLauncherResolves(platform, omnodexHome, candidates);
  switch (check.status) {
    case "resolved":
      console.log(`[install] launcher finds shim: ${check.shim}`);
      return;
    case "pinned":
      console.log(`[install] launcher found no shim on this host; set shim_paths.${platform} in`);
      console.log(`          ${check.configPath}`);
      console.log(`[install] launcher finds shim: ${check.shim}`);
      return;
    case "unresolved":
      console.warn(`[install] WARNING: hooks will record nothing on this host: ${check.reason}`);
      console.warn(`[install]          run \`omnodex status\` to check the launchers`);
      return;
  }
}

function logHookCommandForm(target: InstallTarget, portable: boolean, useLegacy: boolean): void {
  // Antigravity on Windows runs hooks under cmd.exe, so only its POSIX hosts share the file.
  const hosts = target === "antigravity" ? "macOS, Linux and WSL" : "Windows, WSL and other devices";
  if (portable) {
    console.log(`[install] hook command is host-neutral: the same file works on ${hosts}`);
    console.log(`          once \`omnodex install ${target}\` has been run on each of them`);
  } else if (target === "antigravity" && process.platform === "win32" && !useLegacy) {
    console.log(`[install] note: Antigravity runs hooks under cmd.exe on Windows, so this hook command`);
    console.log(`          names this machine's paths; other machines need their own install`);
  } else if (!useLegacy) {
    console.log(`[install] note: --debug or a custom OMNODEX_HOME writes a host-specific hook command;`);
    console.log(`          installing ${target} from another host in this project will replace it`);
  }
}

async function openStore(paths: Paths): Promise<ReadModelStore> {
  const store = new SqliteReadModelStore({ dbPath: paths.dbPath });
  await store.init();
  return store;
}

// ---------------------------------------------------------------------------
// The read model, and the roots that feed it
// ---------------------------------------------------------------------------

/**
 * One canonical read model, derived from every configured root.
 *
 * A root is a place event logs are written. There can be several: this
 * installation's own home, the default home a host like Cowork writes to
 * whatever OMNODEX_HOME says, and anything listed in config.json.
 *
 * The read model is not per-root. It is a derived artifact rebuilt from logs,
 * so it lives in exactly one place, the primary root, and it always holds
 * every root's sessions. Previously only `omnodex dashboard` resolved roots
 * at all, and it wrote the aggregate to the same file `omnodex replay`
 * rebuilt from the primary root alone, so replaying deleted every secondary
 * root's sessions and the next sync pushed the smaller set.
 */
interface RootLog {
  rootPath: string;
  log: EventLog;
}

/** Open an EventLog for each root. Callers close them. */
async function openRootLogs(roots: string[]): Promise<RootLog[]> {
  const logs: RootLog[] = [];
  for (const rootPath of roots) {
    const log = new EventLog({ root: path.join(rootPath, "event-log") });
    await log.init();
    logs.push({ rootPath, log });
  }
  return logs;
}

async function closeRootLogs(logs: RootLog[]): Promise<void> {
  for (const { log } of logs) await log.close();
}

/**
 * Rebuild the read model from every root, from scratch.
 *
 * Shared by `replay`, `dashboard` and anything else that reconstructs the
 * model, so the two cannot disagree about what it should contain. Each
 * session row is stamped with the root it came from, and correlation runs at
 * the end because pairing a hook call with its proxy counterpart needs the
 * whole model rather than one root's slice of it.
 */
async function rebuildReadModel(
  store: ReadModelStore,
  logs: RootLog[],
): Promise<void> {
  const projector = new Projector(store);
  await store.reset();
  // One transaction for the whole rebuild: far faster than a commit per row.
  await inTransaction(store, async () => {
    for (const { rootPath, log } of logs) {
      projector.setSourceRoot(rootPath);
      for await (const event of iterateLog(log)) {
        await projector.apply(event);
      }
    }
    projector.setSourceRoot(null);
    await runCorrelation(store);
  });
}

/**
 * Paths for the canonical read model, given a resolved root set.
 * The primary root is this installation's home, so this agrees with
 * resolvePaths() by construction.
 */
function primaryPathsFor(primary: string): Paths {
  return {
    home: primary,
    eventLogRoot: path.join(primary, "event-log"),
    dbPath: path.join(primary, "traces.db"),
  };
}

async function cmdSpike(args: string[]): Promise<void> {
  const options = parseSpikeOptions(args);
  const paths = resolvePaths();
  console.log(`[spike] OMNODEX_HOME=${paths.home}`);
  console.log(`[spike] seed: ${options.seed ?? DEFAULT_SCENARIO_SEED}`);
  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();
  try {
    const existingSessionIds = await log.listSessions();
    const events = options.history
      ? buildHistoryScenarios({ ...options, machine: options.history, existingSessionIds })
      : buildScenarios({ ...options, existingSessionIds });
    await log.appendMany(events);
    // Use the same community batch evaluator as captured traffic. Its output
    // timestamps are pinned to the triggering event for reproducible fixtures.
    const sessions = [...new Set(events.map(e => e.session_id))];
    for (const id of sessions) {
      const source = events.filter(e => e.session_id === id);
      let finding = 0;
      const result = detectRisks(source, () => `${id}_finding_${finding++}`);
      for (const risk of result.newEvents) {
        const call = source.find(e => e.event_type === "tool.invoked" && e.tool_call_id === risk.related_event_id);
        risk.occurred_at = call?.occurred_at ?? source[0].occurred_at;
        risk.recorded_at = risk.occurred_at;
      }
      await log.appendMany(result.newEvents);
    }
    console.log(`[spike] appended ${events.length} raw events in ${sessions.length} sessions`);
    const store = await openStore(paths);
    try {
      await rebuildReadModel(store, [{ rootPath: paths.home, log }]);
      await printReport(store);
    } finally { await store.close(); }
  } finally {
    await log.close();
  }
  console.log(`[spike] done`);
}

async function cmdReplay(args: string[] = []): Promise<void> {
  const { roots: cliRoots } = parseRootsFlag(args);
  const resolved = await resolveRoots(cliRoots);
  const paths = primaryPathsFor(resolved.primary);

  console.log(`[replay] roots: ${resolved.all.join(", ")}`);

  const logs = await openRootLogs(resolved.all);
  const store = await openStore(paths);
  await rebuildReadModel(store, logs);
  await closeRootLogs(logs);

  const sessions = await store.listSessions();
  console.log(`[replay] rebuilt read model at ${paths.dbPath}`);
  console.log(`[replay] ${sessions.length} session(s) from ${resolved.all.length} root(s)`);
  await store.close();
}

/**
 * Clear session data.
 *
 *   omnodex clear <session-id>          remove one session from event log + read model
 *   omnodex clear --all --confirm       PERMANENTLY delete all data under OMNODEX_HOME
 *
 * The --all flag requires --confirm to prevent accidental data loss. Clearing
 * needs a person at a terminal unless --unattended is explicitly passed.
 */
async function cmdClear(args: string[]): Promise<void> {
  const paths = resolvePaths();
  const sessionId = args.find((a) => !a.startsWith("--"));
  const wipeAll = args.includes("--all");
  const confirmed = args.includes("--confirm");
  const unattended = args.includes("--unattended");

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

  if (!unattended && !(process.stdin.isTTY && process.stdout.isTTY)) {
    console.error(
      "[clear] clearing Omnodex data needs a person at an interactive terminal, so an agent cannot erase its own history. " +
        "Run it yourself in a terminal, or pass --unattended for a scripted clear (it is recorded and raises a finding).",
    );
    process.exitCode = 1;
    return;
  }
  if (unattended) setMonitoringActor("unattended");

  if (wipeAll && confirmed) {
    // Preserve the connection just long enough to send the clear marker. The
    // connection and all other state are removed again after that best-effort
    // push; only the new event log remains.
    const streamConfig = await readStreamConfig(paths.home);
    // Wipe everything
    await fs.rm(paths.home, { recursive: true, force: true });
    if (streamConfig) await writeStreamConfig(paths.home, streamConfig);
    await recordMonitoringChange({ action: "clear" }, paths.home);
    if (streamConfig) {
      for (const entry of await fs.readdir(paths.home)) {
        if (entry !== "event-log") await fs.rm(path.join(paths.home, entry), { recursive: true, force: true });
      }
    }
    console.log(`[clear] removed all data at ${paths.home}`);
    return;
  }

  // --- Remove a single session ---
  // The session may live in any root, not just this installation's own, so
  // find it first. Deleting from the primary alone used to leave the session
  // on disk while still rebuilding the read model without it.
  const resolved = await resolveRoots();
  const logs = await openRootLogs(resolved.all);

  // sessionId is guaranteed defined here: we returned above if both sessionId
  // and wipeAll were falsy, and again if wipeAll+confirmed.
  let removedFrom: string | null = null;
  for (const { rootPath, log } of logs) {
    const sessions = await log.listSessions();
    if (!sessions.includes(sessionId!)) continue;

    // 1. Delete the session's JSONL file.
    await fs.rm(log.sessionFilePath(sessionId!), { force: true });

    // 2. Rewrite that root's event log index without this session.
    const indexPath = path.join(rootPath, "event-log", "index.jsonl");
    const raw = await fs.readFile(indexPath, "utf8").catch(() => "");
    const kept = raw
      .split("\n")
      .filter((line) => {
        if (!line.trim()) return false;
        try {
          const entry = JSON.parse(line) as { session_id?: string };
          return entry.session_id !== sessionId;
        } catch {
          return true; // keep malformed lines as-is
        }
      })
      .join("\n");
    await fs.writeFile(indexPath, kept ? kept + "\n" : "", "utf8");
    removedFrom = rootPath;
    break;
  }

  await closeRootLogs(logs);

  if (!removedFrom) {
    console.error(`[clear] session ${sessionId} not found in any root`);
    process.exitCode = 1;
    return;
  }

  // 3. Rebuild the read model from every root's remaining sessions.
  const freshLogs = await openRootLogs(resolved.all);
  const store = await openStore(primaryPathsFor(resolved.primary));
  await rebuildReadModel(store, freshLogs);
  await closeRootLogs(freshLogs);
  await store.close();

  await recordMonitoringChange({ action: "clear" }, paths.home);
  console.log(`[clear] removed session ${sessionId} from ${removedFrom}`);
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
    const all = await store.listRiskEvents(session.session_id);
    const risks = shownFindings(all);
    if (all.length > 0) {
      console.log(`  risk_events:`);
      for (const risk of risks) {
        console.log(`    [${risk.severity}] ${risk.category}: ${risk.description} (rule ${risk.rule_id})`);
      }
      if (all.length > risks.length) {
        console.log(`    ${advancedFindingsText(all.length - risks.length, advancedEntitled(resolvePaths().home))}`);
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
  const { roots: cliRoots, rest } = parseRootsFlag(args);
  const resolved = await resolveRoots(cliRoots);

  // Analysis has to cover every root a session could have been written to.
  // Scanning only the primary meant a secondary root accumulated tool calls
  // and never a single risk event.
  console.log(`[detect] roots: ${resolved.all.join(", ")}`);

  const targetSession = rest.find((a) => !a.startsWith("--"));

  const eventLogRoots = resolved.all.map((root) => path.join(root, "event-log"));
  const result = await detectEventLogs({
    roots: eventLogRoots,
    sessionId: targetSession,
    newEventId,
    registry: registryForHost("batch", resolvePaths().home),
    machineState: openMachineState(resolvePaths().home, { seedRoots: eventLogRoots }),
    onSession: ({ sessionId, newEvents }) => {
      if (newEvents.length > 0) {
        console.log(`[detect] ${sessionId}: ${newEvents.length} new risk(s) detected`);
        const shown = newEvents.filter((re) => re.rule_tier !== "advanced");
        for (const re of shown) {
          console.log(`  [${re.severity}] ${re.category}: ${re.description}`);
        }
        if (shown.length < newEvents.length) {
          console.log(`  ${advancedFindingsText(newEvents.length - shown.length, advancedEntitled(resolvePaths().home))}`);
        }
      } else {
        console.log(`[detect] ${sessionId}: no new risks`);
      }
    },
  });
  const scanned = result.scanned;
  const totalNew = result.newEvents.length;
  const totalSkipped = result.skipped;

  if (scanned === 0) {
    console.log(
      targetSession
        ? `[detect] session ${targetSession} not found in any root`
        : "[detect] no sessions in event log",
    );
    return;
  }
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
  // Parse --roots flag before consuming positional args.
  const { roots: cliRoots, rest: remainingArgs } = parseRootsFlag(args);
  const port = parseInt(remainingArgs.find((a) => !a.startsWith("--")) ?? "7890", 10);
  const skipDetect = remainingArgs.includes("--no-detect");

  // --- Resolve all roots (default home + env + config + CLI) ---
  const resolved = await resolveRoots(cliRoots);
  console.log(`[dashboard] roots: ${resolved.all.join(", ")}`);

  // Create an EventLog per root.
  const logs = await openRootLogs(resolved.all);

  // --- Historical processing (batch) ---
  // Run batch detection on any sessions that completed before the dashboard
  // was opened. The streaming loop will handle everything from this point on.
  // First-seen-on-this-machine state, shared by the batch pass and the
  // streaming loop so they agree on what is new.
  const machineState = openMachineState(resolvePaths().home, {
    seedRoots: resolved.all.map((root) => path.join(root, "event-log")),
  });
  if (!skipDetect) {
    let detected = 0;
    for (const { log } of logs) {
      const sessionIds = await log.listSessions();
      for (const sessionId of sessionIds) {
        const events = await log.readSession(sessionId);
        if (events.length === 0) continue;
        const result = detectRisks(events, newEventId, registryForHost("batch", resolvePaths().home), { machineState });
        if (result.newEvents.length > 0) {
          await log.appendMany(result.newEvents);
          detected += result.newEvents.length;
        }
      }
    }
    if (detected > 0) {
      console.log(`[dashboard] historical detection: ${detected} risk event(s) added`);
    }
  }

  // Rebuild the read model from the full log across all roots (includes any
  // newly appended risk events from the historical detection pass above).
  // Use the primary root for the SQLite database location.
  const primaryPaths = primaryPathsFor(resolved.primary);
  const store = await openStore(primaryPaths);

  // Same rebuild `omnodex replay` performs, so the two cannot disagree about
  // what the read model should hold.
  await rebuildReadModel(store, logs);

  // --- Start server ---
  const assetsDir = resolveDashboardAssetsDir(import.meta.url);
  // Capture pauses live in their own session file in each root's log.
  const pauses = async () =>
    pauseRows((await Promise.all(logs.map(({ log }) => log.readSession(CAPTURE_CONTROL_SESSION_ID)))).flat());
  // Tool lists the MCP proxy kept, in whichever root's home it ran from.
  const toolLists = resolved.all.map((root) => createToolListSnapshots(path.join(root, "proxy-tool-snapshots")));
  const toolList = (fingerprint: string) => {
    for (const lists of toolLists) {
      const tools = lists.load(fingerprint);
      if (tools) return tools;
    }
    return undefined;
  };
  const server = new DashboardServer({
    store, port, assetsDir, pauses, version: getInstalledVersion(),
    advancedEntitled: () => advancedEntitled(resolvePaths().home),
    toolList,
  });
  try {
    await server.ready;
  } catch (err) {
    await shutdownDashboard({ stopStreaming: async () => {}, server, logs, store });
    throw err;
  }

  // Validate license and show tier info
  const licenseResult = await validateLicense();
  const tierLabel = licenseResult.license.tier.toUpperCase();
  const licenseSource = licenseResult.source === "defaults" ? " (no token)" : ` (${licenseResult.source})`;
  console.log(`[dashboard] license: ${tierLabel}${licenseSource}`);
  if (licenseResult.license.tier !== "free") {
    console.log(`[dashboard] features: ${licenseResult.license.features.filter((f: string) => !["community_rules", "local_dashboard", "local_event_log"].includes(f)).join(", ")}`);
  }

  // --- Cloud streaming setup (auto-enabled when credentials are configured) ---
  let cloudTransport: StreamingTransport | null = null;
  const streamCreds = await resolveCredentials(resolved.primary);
  const streamApiToken = streamCreds?.apiToken ?? "";
  const streamPassphrase = streamCreds?.passphrase ?? "";
  const streamApiUrl = streamCreds?.apiUrl ?? "https://api.omnodex.com";

  if (streamApiToken && streamPassphrase) {
    const features = licenseResult.license.features;
    if (features.includes("live_streaming")) {
      try {
        const customerId = licenseResult.license.customer_id;
        console.log("[dashboard] deriving streaming key...");
        const streamKey = await deriveStreamingKey(streamPassphrase, customerId);
        const keyId = await computeKeyId(streamKey);
        cloudTransport = new StreamingTransport({
          apiBase: streamApiUrl,
          apiToken: streamApiToken,
          keyId,
          streamingKey: streamKey,
          home: resolved.primary,
        });
        console.log(`[dashboard] cloud streaming enabled (key_id=${keyId})`);
      } catch (err) {
        console.warn("[dashboard] cloud streaming setup failed:", err);
      }
    } else {
      console.log("[dashboard] cloud streaming not available on current tier");
    }
  } else {
    console.log("[dashboard] cloud streaming disabled (no API token/stream secret)");
  }

  console.log(`[dashboard] open http://localhost:${server.port} in your browser`);
  console.log(`[dashboard] streaming detection active -- press Ctrl+C to stop`);

  // --- Start streaming detect loop ---
  // Tails each root's session files, projects new events incrementally, runs
  // the rule engine on tool.invoked events, and pushes updates to SSE clients.
  const streamingRoots: StreamingRoot[] = logs.map(({ rootPath, log }) => ({
    rootPath,
    log,
  }));
  // Its own projector: the rebuild above owns the one it used, and the
  // streaming loop passes each event's source root as it tails.
  const streamProjector = new Projector(store);
  const { stop } = startStreamingLoop(streamingRoots, store, streamProjector, server, cloudTransport, {
    machineState,
    home: resolvePaths().home,
  });

  // --- Shutdown handling ---
  // SIGINT is Ctrl+C everywhere; SIGBREAK is Ctrl+Break and SIGHUP a closed
  // console window on Windows; SIGTERM is a service manager or `kill`. A
  // second signal while shutting down exits at once.
  const signals = ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"] as const;
  let stopping = false;
  let onSignal = (): void => {};
  await new Promise<void>((resolve) => {
    onSignal = (): void => {
      if (stopping) process.exit(130);
      stopping = true;
      console.log("[dashboard] shutting down...");
      shutdownDashboard({ stopStreaming: stop, transport: cloudTransport, server, logs, store }).finally(resolve);
    };
    for (const signal of signals) process.on(signal, onSignal);
  });
  for (const signal of signals) process.off(signal, onSignal);
}

// ---------------------------------------------------------------------------
// Stream connection
// ---------------------------------------------------------------------------

/**
 * Cache the license in this home and upload existing sessions once, so
 * hooks and the proxy stream and sync without a manual `omnodex sync`.
 */
async function finishCloudConnection(
  omnodexHome: string,
  prefix: string,
  opts: { apiToken: string; apiUrl: string; refresh: boolean },
): Promise<void> {
  try {
    const result = await bootstrapCloudConnection({ home: omnodexHome, ...opts });
    for (const line of describeBootstrap(prefix, result)) console.log(line);
  } catch (err) {
    console.warn(`[${prefix}] could not finish cloud setup: ${(err as Error).message}`);
    console.warn(`[${prefix}] run \`omnodex sync\` once to upload existing sessions`);
  }
}

/**
 * After install: run device code flow if no token exists, otherwise offer a
 * claim link. Shared by all install commands.
 */
async function connectAfterInstall(
  omnodexHome: string,
  opts: { platform?: string; projectLabel?: string; args: readonly string[] },
): Promise<void> {
  const skip = skipConnectReason(opts.args, process.stdin.isTTY);
  if (skip === "--no-connect") return;
  let creds = await resolveCredentials(omnodexHome);

  if (!creds?.apiToken && skip) {
    console.log("");
    console.log(`[connect] skipped the dashboard sign-in (${skip}). To connect this host later, run: omnodex connect`);
    return;
  }

  if (!creds?.apiToken) {
    // No token: run device code flow
    console.log("");
    console.log("No API token found. Let's connect to your dashboard.");

    const passphrase = creds?.passphrase || generatePassphrase();
    const apiUrl = creds?.apiUrl ?? "https://api.omnodex.com";

    await updateStreamConfig(omnodexHome, {
      api_token: "",
      passphrase,
      api_url: apiUrl,
      created_at: new Date().toISOString(),
    });

    try {
      const result = await runDeviceAuthFlow({
        apiUrl,
        passphrase,
      });

      await updateStreamConfig(omnodexHome, {
        api_token: result.apiToken,
        passphrase,
        api_url: result.apiUrl,
        last_used_at: new Date().toISOString(),
      });
      await finishCloudConnection(omnodexHome, "connect", {
        apiToken: result.apiToken,
        apiUrl: result.apiUrl,
        refresh: true,
      });
    } catch (err) {
      console.warn(`[connect] could not complete device authorization: ${(err as Error).message}`);
      console.warn(`[connect] you can retry with: omnodex connect`);
    }
    return;
  }

  // Token and passphrase both exist: already connected, just confirm status
  if (creds.passphrase) {
    console.log(`[connect] already connected (use \`omnodex connect\` to manage)`);
    await finishCloudConnection(omnodexHome, "connect", {
      apiToken: creds.apiToken,
      apiUrl: creds.apiUrl,
      refresh: false,
    });
    return;
  }

  // Token exists but no passphrase: auto-generate one and offer claim link,
  // unless the stream already has a secret this machine does not know.
  if ((await streamHasSecret({ apiUrl: creds.apiUrl, apiToken: creds.apiToken })) === true) {
    console.warn(`[connect] ${UNKNOWN_SECRET_MESSAGE}`);
    return;
  }
  const newPassphrase = generatePassphrase();
  await updateStreamConfig(omnodexHome, {
    api_token: creds.apiToken,
    passphrase: newPassphrase,
    api_url: creds.apiUrl,
    created_at: new Date().toISOString(),
  });
  creds.passphrase = newPassphrase;
  console.log("[install] generated a new stream secret (saved to stream-config.json)");

  await offerConnectionLink(omnodexHome, {
    apiToken: creds.apiToken,
    passphrase: creds.passphrase,
    apiUrl: creds.apiUrl,
    platform: opts.platform,
    projectLabel: opts.projectLabel,
  });
  await finishCloudConnection(omnodexHome, "connect", {
    apiToken: creds.apiToken,
    apiUrl: creds.apiUrl,
    refresh: false,
  });
}

/**
 * Offer a one-click connection link after install or on explicit `omnodex connect`.
 *
 * Auto-generates a passphrase if one does not already exist in
 * stream-config.json, encrypts it under a one-time transfer key, and
 * creates a short-lived claim token on the cloud API. The resulting URL
 * contains the transfer key in the fragment (never sent to the server).
 */
async function offerConnectionLink(
  omnodexHome: string,
  opts: {
    apiToken: string;
    passphrase: string;
    apiUrl: string;
    platform?: string;
    projectLabel?: string;
  },
): Promise<void> {
  try {
    const result = await createClaim({
      apiUrl: opts.apiUrl,
      apiToken: opts.apiToken,
      passphrase: opts.passphrase,
      platform: opts.platform,
      projectLabel: opts.projectLabel,
    });
    console.log("");
    console.log(`[connect] open this link to connect your stream to the dashboard:`);
    console.log(`          ${result.connectUrl}`);
    console.log(`[connect] this link expires at ${result.expiresAt}`);

    // Update last_used_at
    await updateStreamConfig(omnodexHome, {
      last_used_at: new Date().toISOString(),
    });
  } catch (err) {
    console.warn(`[connect] could not create connection link: ${(err as Error).message}`);
    console.warn(`[connect] you can retry with: omnodex connect`);
  }
}

/** The message for a stream that already has a secret this machine does not know. */
const UNKNOWN_SECRET_MESSAGE =
  "this stream already has a stream secret, and this machine does not have it. Reveal it in the dashboard " +
  "Settings (Stream secret), then run: omnodex connect --secret <stream secret>";

/**
 * Generate a connection link for the current machine.
 *
 *   omnodex connect [--token <omx_...>] [--secret <stream secret>]
 *                   [--api <url>] [--platform <name>]
 *
 * If no stream secret exists yet, one is auto-generated and saved to
 * stream-config.json, unless the stream already has one (then this asks for
 * it instead of switching the stream to a new secret). The secret is
 * encrypted under a one-time transfer key before being sent to the server.
 *
 * A token the cloud rejects (revoked, or rotated past collection) falls
 * through to the device flow, where the account can re-authorize the same
 * stream. A rotated token that can still be collected is swapped for the
 * new one. A token or secret passed as a flag is checked and saved.
 */
async function cmdConnect(args: string[]): Promise<void> {
  const paths = resolvePaths();

  const flagToken = readFlagValue(args, "--token");
  const flagPassphrase = readFlagValue(args, "--secret") ?? readFlagValue(args, "--passphrase");
  const flagApiUrl = readFlagValue(args, "--api");
  const rawPlatform = readFlagValue(args, "--platform");
  const flagPlatform = rawPlatform === undefined ? undefined : canonicalTarget(rawPlatform);

  // Resolve or generate credentials
  let creds = await resolveCredentials(paths.home, {
    flagToken,
    flagPassphrase,
    flagApiUrl,
  });

  if (creds?.apiToken) {
    const probe = await probeStreamToken({ apiUrl: creds.apiUrl, apiToken: creds.apiToken });
    if (probe === "rotated" && creds.passphrase && !flagToken) {
      try {
        const apiToken = await collectRotatedToken({
          home: paths.home, apiUrl: creds.apiUrl, apiToken: creds.apiToken, passphrase: creds.passphrase,
        });
        creds = { ...creds, apiToken, tokenSource: "config" };
        console.log("[connect] the stream's owner rotated this machine's token; collected the new one");
      } catch (err) {
        console.error(`[connect] ${(err as Error).message}`);
        process.exitCode = 1;
        return;
      }
    } else if (probe === "rotated" || probe === "rejected") {
      if (flagToken) {
        console.error("[connect] that token is not valid: it was revoked, rotated or mistyped. Copy the current token from the dashboard Settings.");
        process.exitCode = 1;
        return;
      }
      console.log("[connect] this machine's token no longer works: the stream was revoked, or its token was rotated.");
      console.log("[connect] sign in to authorize this machine again. To keep the stream and its history, choose it from the list.");
      creds = { ...creds, apiToken: "" };
    }
  }

  // Auto-generate passphrase if missing (needed for both flows)
  const passphrase = creds?.passphrase || generatePassphrase();
  const apiUrl = creds?.apiUrl ?? flagApiUrl ?? "https://api.omnodex.com";

  if (!creds?.apiToken) {
    // No token: run the device code flow to bootstrap one
    console.log("No API token found. Let\'s connect this installation to your account.");

    // Save the passphrase before starting the flow
    await updateStreamConfig(paths.home, {
      api_token: "",
      passphrase,
      api_url: apiUrl,
      created_at: new Date().toISOString(),
    });

    try {
      const result = await runDeviceAuthFlow({
        apiUrl,
        passphrase,
      });

      // Store the received token in stream-config.json
      await updateStreamConfig(paths.home, {
        api_token: result.apiToken,
        passphrase,
        api_url: result.apiUrl,
        last_used_at: new Date().toISOString(),
      });
      await finishCloudConnection(paths.home, "connect", {
        apiToken: result.apiToken,
        apiUrl: result.apiUrl,
        refresh: true,
      });
    } catch (err) {
      console.error(`[connect] ${(err as Error).message}`);
      process.exitCode = 1;
    }
    return;
  }

  // Token exists: ensure passphrase is saved
  if (!creds.passphrase) {
    // A stream whose secret is registered keeps it; a new one would leave
    // every linked dashboard unable to read what this machine uploads.
    if ((await streamHasSecret({ apiUrl: creds.apiUrl, apiToken: creds.apiToken })) === true) {
      console.error(`[connect] ${UNKNOWN_SECRET_MESSAGE}`);
      process.exitCode = 1;
      return;
    }
    await updateStreamConfig(paths.home, {
      api_token: creds.apiToken,
      passphrase,
      api_url: creds.apiUrl,
      created_at: new Date().toISOString(),
    });
    console.log("[connect] generated a new stream secret (saved to stream-config.json)");
    creds = (await resolveCredentials(paths.home, {
      flagToken,
      flagPassphrase,
      flagApiUrl,
    }))!;
  }

  // A token or secret given on the command line replaces the saved one,
  // so syncs use it; a secret is checked against the stream's first.
  if (creds.tokenSource === "flag" || creds.passphraseSource === "flag") {
    try {
      await ensureSecretVerifier({
        home: paths.home, apiUrl: creds.apiUrl, apiToken: creds.apiToken, passphrase: creds.passphrase,
      });
    } catch (err) {
      if (!(err instanceof SecretMismatchError)) throw err;
      console.error("[connect] that stream secret is not the one this stream uses; nothing was saved. Reveal the stream secret in the dashboard Settings.");
      process.exitCode = 1;
      return;
    }
    await updateStreamConfig(paths.home, {
      api_token: creds.apiToken,
      passphrase: creds.passphrase,
      api_url: creds.apiUrl,
    });
    console.log("[connect] saved the " + [
      creds.tokenSource === "flag" ? "token" : "",
      creds.passphraseSource === "flag" ? "stream secret" : "",
    ].filter(Boolean).join(" and ") + " to stream-config.json");
  }

  // Token exists: generate a claim link (existing behavior)
  await offerConnectionLink(paths.home, {
    apiToken: creds.apiToken,
    passphrase: creds.passphrase,
    apiUrl: creds.apiUrl,
    platform: flagPlatform,
  });
  await finishCloudConnection(paths.home, "connect", {
    apiToken: creds.apiToken,
    apiUrl: creds.apiUrl,
    // A token passed on the command line may differ from the cached one.
    refresh: Boolean(flagToken),
  });
}

const VALID_TARGETS = ["claude-code", "codex", "antigravity"] as const;
type InstallTarget = typeof VALID_TARGETS[number];

function isTargetName(arg: string): boolean {
  return VALID_TARGETS.includes(canonicalTarget(arg) as InstallTarget);
}

function resolveTarget(args: string[]): { target: InstallTarget; rest: string[] } | null {
  const targetArg = args.find((a) => !a.startsWith("--"));
  if (!targetArg || !isTargetName(targetArg)) {
    const validList = VALID_TARGETS.join(", ");
    console.error(
      targetArg
        ? `[omnodex] unknown target '${targetArg}'. Valid targets: ${validList}`
        : `[omnodex] target required. Valid targets: ${validList} (agy also works for antigravity)`,
    );
    console.error(`\n  omnodex install <target> [project]`);
    console.error(`  omnodex uninstall [target] [project]\n`);
    process.exitCode = 1;
    return null;
  }
  return {
    target: canonicalTarget(targetArg) as InstallTarget,
    rest: args.filter((a) => a !== targetArg),
  };
}

/** Install flags that take a value. */
const VALUE_FLAGS = ["--plugin-version", "--from", "--sha256"];

/**
 * `--from file` becomes `--from=file`, so a flag's value is never taken for
 * the target or the project. Read values with flagValue().
 */
function joinValueFlags(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (VALUE_FLAGS.includes(args[i]) && i + 1 < args.length) {
      out.push(`${args[i]}=${args[i + 1]}`);
      i++;
    } else {
      out.push(args[i]);
    }
  }
  return out;
}

function flagValue(args: readonly string[], name: string): string | undefined {
  const found = args.find((a) => a.startsWith(`${name}=`));
  return found === undefined ? undefined : found.slice(name.length + 1);
}

/** What an install sets up. No component flag: everything the surface supports. */
interface InstallComponents {
  hooks: boolean;
  plugin: boolean;
  /** Antigravity's project MCP entry (--mcp), the setup for running without its plugin. */
  mcp: boolean;
}

function installComponents(args: readonly string[]): InstallComponents {
  const hooks = args.includes("--hooks");
  const plugin = args.includes("--plugin");
  const mcp = args.includes("--mcp");
  if (!hooks && !plugin && !mcp) return { hooks: true, plugin: true, mcp: false };
  return { hooks, plugin, mcp };
}

async function cmdInstall(rawArgs: string[]): Promise<void> {
  // A first install offers shadow mode; reinstalls and upgrades keep the mode they have.
  const firstInstall = (await listInstallations()).length === 0;
  await installTargets(rawArgs);
  if (firstInstall && !process.exitCode) {
    await offerShadowMode({ home: resolvePaths().home, io: processIo(), yes: hasYes(rawArgs) }).catch((err: unknown) => {
      console.error(`[install] could not set the enforcement mode: ${(err as Error).message}`);
    });
  }
}

async function installTargets(rawArgs: string[]): Promise<void> {
  const args = joinValueFlags(rawArgs);
  // No target, or a project folder in its place: set up every surface found.
  const positional = args.find((a) => !a.startsWith("-"));
  if (positional === undefined || (!isTargetName(positional) && await isDirectory(positional))) {
    if (flagValue(args, "--from") !== undefined || flagValue(args, "--sha256") !== undefined) {
      console.error(`[install] --from and --sha256 install one plugin; name its target: omnodex install <target> --plugin --from <file>`);
      process.exitCode = 1;
      return;
    }
    const version = flagValue(args, "--plugin-version");
    if (version !== undefined && version !== "latest") {
      console.error(`[install] each plugin has its own version numbers; name a target to install ${version}, or use --plugin-version latest`);
      process.exitCode = 1;
      return;
    }
    await installAllSurfaces(args);
    return;
  }

  const parsed = resolveTarget(args);
  if (!parsed) return;
  const { target, rest } = parsed;

  switch (target) {
    case "claude-code":
      await installClaudeCode(rest);
      return;
    case "codex":
      await installCodex(rest);
      return;
    case "antigravity":
      await installAntigravity(rest);
      return;
  }
}

async function isDirectory(p: string): Promise<boolean> {
  try {
    return (await fs.stat(p)).isDirectory();
  } catch {
    return false;
  }
}

async function readOrNull(file: string): Promise<string | null> {
  try {
    return await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * Under a hooks file `omnodex status` lists: the paths its Omnodex hook
 * commands name that this machine does not have. Such a file usually came
 * from another machine (a shared repo or a synced folder), and its hooks
 * fail on every call.
 */
async function reportMissingHookPaths(file: string, reinstall: string): Promise<void> {
  const content = await readOrNull(file);
  if (!content) return;
  const missing = await findMissingHookPaths(content, { home: os.homedir() });
  if (missing.length === 0) return;
  console.log(`    ⚠ names paths this machine does not have, so these hooks fail on every call:`);
  for (const entry of missing) console.log(`        ${entry.path}`);
  console.log(`      it was probably written on another machine (a shared repo or synced folder);`);
  console.log(`      run \`${reinstall}\` here to rewrite it for this machine`);
}

/** The project file each surface's hooks are written to. */
function surfaceHooksFile(surface: Surface, projectPath: string, omnodexHome: string, args: readonly string[]): string {
  switch (surface) {
    case "claude-code":
      return new ClaudeCodeInterceptor({
        projectPath,
        shimPath: CLAUDE_HOOK_SHIM_PATH,
        omnodexHome,
        settingsFile: args.includes("--project-settings") ? "settings.json" : "settings.local.json",
      }).settingsFilePath();
    case "codex":
      return new CodexInterceptor({ projectPath, shimPath: CODEX_HOOK_SHIM_PATH, omnodexHome }).hooksFilePath();
    case "antigravity":
      return new AntigravityInterceptor({ projectPath, shimPath: ANTIGRAVITY_HOOK_SHIM_PATH, omnodexHome }).hooksFilePath();
  }
}

type HookScopeChoice = "everywhere" | "this-project";

const YES_FLAGS = ["--yes", "-y"];
const hasYes = (args: readonly string[]) => args.some((a) => YES_FLAGS.includes(a));

/** Ask, at a terminal, whether hooks record every project or only this one. */
async function askHookScope(projectPath: string): Promise<HookScopeChoice> {
  console.log(`[install] Where should Omnodex record?`);
  console.log(`  1) Every project you open (recommended)`);
  console.log(`  2) Only ${projectPath}`);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question("Choose 1 or 2 [1]: ")).trim();
  rl.close();
  return answer === "2" ? "this-project" : "everywhere";
}

/**
 * The hook scope for a one-target install. Flags win; a target that already
 * records every project stays that way (installing in a left-out project
 * records it again); --yes picks the recommended every-project scope; at a
 * terminal the user is asked. Without a terminal and without --yes, hooks go
 * into the project, as they always have.
 */
async function resolveHookScope(
  target: InstallTarget,
  args: readonly string[],
  projectPath: string,
  omnodexHome: string,
): Promise<HookScopeChoice | null> {
  const legacy = args.includes("--legacy-shim");
  if (args.includes("--everywhere")) {
    if (legacy) {
      console.error(`[install] --everywhere needs the stable launcher; it cannot be combined with --legacy-shim`);
      process.exitCode = 1;
      return null;
    }
    return "everywhere";
  }
  if (args.includes("--this-project") || legacy) return "this-project";
  if (isEverywhere(await readHookScope(omnodexHome), target)) return "everywhere";
  if (hasYes(args)) return "everywhere";
  if (!process.stdin.isTTY) return "this-project";
  return askHookScope(projectPath);
}

interface ProjectHooks {
  target: InstallTarget;
  label: string;
  path: string;
  uninstall: () => Promise<void>;
}

/**
 * True when a project hooks file is the agent's user-level file, which
 * happens in the home folder (~/.claude/settings.json, ~/.codex/hooks.json).
 */
const isUserLevelFile = (target: InstallTarget, file: string) =>
  path.resolve(file) === path.resolve(userHooksFile(target));

/** Omnodex hooks written into this project's own files, per agent. */
async function findProjectHooks(projectPath: string, omnodexHome: string): Promise<ProjectHooks[]> {
  const found = await findProjectHookFiles(projectPath, omnodexHome);
  return found.filter((h) => !isUserLevelFile(h.target, h.path));
}

async function findProjectHookFiles(projectPath: string, omnodexHome: string): Promise<ProjectHooks[]> {
  const found: ProjectHooks[] = [];
  for (const settingsFile of ["settings.local.json", "settings.json"] as const) {
    const interceptor = new ClaudeCodeInterceptor({ projectPath, shimPath: CLAUDE_HOOK_SHIM_PATH, omnodexHome, settingsFile });
    if (await interceptor.isInstalled()) {
      found.push({
        target: "claude-code",
        label: `Claude Code (${settingsFile})`,
        path: interceptor.settingsFilePath(),
        uninstall: () => interceptor.uninstall(),
      });
    }
  }
  const codex = new CodexInterceptor({ projectPath, shimPath: CODEX_HOOK_SHIM_PATH, omnodexHome });
  if ((await readOrNull(codex.hooksFilePath()))?.includes("omnodex")) {
    found.push({ target: "codex", label: "Codex", path: codex.hooksFilePath(), uninstall: () => codex.uninstall() });
  }
  const antigravity = new AntigravityInterceptor({ projectPath, shimPath: ANTIGRAVITY_HOOK_SHIM_PATH, omnodexHome });
  if ((await readOrNull(antigravity.hooksFilePath()))?.includes("omnodex")) {
    found.push({
      target: "antigravity",
      label: "Antigravity",
      path: antigravity.hooksFilePath(),
      uninstall: () => antigravity.uninstall(),
    });
  }
  return found;
}

/** Writes or removes a target's hooks in its user-level file. */
function userLevelHooks(
  target: InstallTarget,
  opts: { omnodexHome: string; shimPath: string; debug?: boolean; homeRelativeShimPath?: string },
): { file: string; install: () => Promise<void>; uninstall: () => Promise<void> } {
  const file = userHooksFile(target);
  const common = {
    projectPath: os.homedir(),
    shimPath: opts.shimPath,
    omnodexHome: opts.omnodexHome,
    debug: opts.debug,
    nodePath: "node",
    launcherArgs: [USER_SCOPE_ARG],
  };
  const interceptor =
    target === "claude-code"
      ? new ClaudeCodeInterceptor({ ...common, settingsPath: file, homeRelativeShimPath: opts.homeRelativeShimPath })
      : target === "codex"
        ? new CodexInterceptor({ ...common, hooksPath: file, homeRelativeShimPath: opts.homeRelativeShimPath })
        : new AntigravityInterceptor({ ...common, hooksPath: file });
  return { file, install: () => interceptor.install(), uninstall: () => interceptor.uninstall() };
}

const TARGET_SHIMS: Record<InstallTarget, string> = {
  "claude-code": CLAUDE_HOOK_SHIM_PATH,
  codex: CODEX_HOOK_SHIM_PATH,
  antigravity: ANTIGRAVITY_HOOK_SHIM_PATH,
};

/**
 * Record every project for a target: hooks in the agent's user-level file,
 * pointing at the stable launcher with the user-scope marker. Project hooks
 * already in place step aside (the launcher checks hook-scope.json), and the
 * project this runs in is recorded again if it had been left out.
 */
async function installEverywhere(target: InstallTarget, projectPath: string, args: readonly string[]): Promise<void> {
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const shimPath = await writeLauncher(target);
  const portable = canUsePortableHookCommand(paths, { useLegacy: false, debug });
  const hooks = userLevelHooks(target, {
    omnodexHome: paths.home,
    shimPath,
    debug,
    homeRelativeShimPath: portable && target !== "antigravity" ? launcherHomeRelativePath(target) : undefined,
  });
  await hooks.install();
  await setEverywhere(paths.home, target, true);
  const reincluded = await removeExclusion(paths.home, target, projectPath);
  const label = SURFACE_LABELS[target];

  console.log(`[install] ${label} now records every project. Hooks are in`);
  console.log(`          ${hooks.file}`);
  console.log(`[install] launcher:     ${shimPath}`);
  await checkLauncherShim(target, paths.home, TARGET_SHIMS[target]);
  console.log(`[install] OMNODEX_HOME: ${paths.home}`);
  if (reincluded) {
    console.log(`[install] ${reincluded} had been left out; ${label} records it again`);
  }
  if ((await findProjectHooks(projectPath, paths.home)).some((h) => h.target === target)) {
    console.log(`[install] this project also has its own ${label} hooks; they step aside so each event is recorded once`);
  }
  if (target === "codex") {
    console.log(`[install] Codex asks you to review new hooks: run /hooks in Codex and trust the Omnodex entries`);
  }
  console.log(`[install] to leave out one project, run \`omnodex uninstall ${target}\` in it;`);
  console.log(`          to stop recording every project, run \`omnodex uninstall ${target} --everywhere\``);

  await addInstallation({
    target,
    component: "hooks",
    scope: "user",
    settingsFile: hooks.file,
    installedAt: new Date().toISOString(),
    installedVersion: getInstalledVersion(),
    usesLauncher: true,
    launcherPath: shimPath,
  });
}

/** For a project-only install: say how it relates to every-project recording. */
async function noteProjectScope(target: InstallTarget, projectPath: string, omnodexHome: string): Promise<void> {
  const reincluded = await removeExclusion(omnodexHome, target, projectPath);
  if (reincluded) console.log(`[install] ${reincluded} had been left out; it is recorded again`);
  if (isEverywhere(await readHookScope(omnodexHome), target)) {
    console.log(`[install] ${SURFACE_LABELS[target]} already records every project, so these project hooks step aside`);
  }
}

/** Matches a hook command that runs an Omnodex launcher or shim. */
const OMNODEX_HOOK = /-hook-(?:launcher|shim)\.js/;

/** Same JSON content, whatever the key order (agents rewrite their own files). */
function sameContent(a: string, b: string | null): boolean {
  if (a === b) return true;
  if (b === null) return false;
  const canonical = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(canonical)
      : v && typeof v === "object"
        ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical((v as Record<string, unknown>)[k])]))
        : v;
  try {
    return JSON.stringify(canonical(JSON.parse(a))) === JSON.stringify(canonical(JSON.parse(b)));
  } catch {
    return false;
  }
}

/** What an install did to a hooks file, for the summary. */
function installOutcome(before: string | null, after: string | null): string {
  if (before === null || !OMNODEX_HOOK.test(before)) return "installed";
  return sameContent(before, after) ? "already set up, nothing changed" : "updated";
}

/**
 * Download, verify and install a surface's plugin. Never throws: a failure
 * is reported with a retry command, and hooks installed alongside it are
 * left in place.
 */
async function installPluginComponent(
  target: InstallTarget,
  args: readonly string[],
  projectPath: string,
  withHooks: boolean,
): Promise<void> {
  const paths = resolvePaths();
  const label = SURFACE_LABELS[target];
  const { name, platform } = SURFACE_PLUGIN[target];
  try {
    const bundle = await resolveBundle({
      target,
      version: flagValue(args, "--plugin-version"),
      from: flagValue(args, "--from"),
      sha256: flagValue(args, "--sha256"),
      baseUrl: downloadsBaseUrl(),
      cacheDir: path.join(paths.home, "plugins", "cache"),
    });
    const result = await installPlugin(target, bundle, {
      home: os.homedir(),
      omnodexHome: paths.home,
      env: process.env,
      projectPath,
    });
    const pinned = PLUGIN_PINS[platform].version;
    console.log(`[install] ${label} plugin ${name} ${bundle.version}${bundle.override ? ` (this CLI pins ${pinned})` : ""}`);
    console.log(`          from ${bundle.source}`);
    console.log(`          sha256 ${bundle.sha256}`);
    for (const step of result.steps) console.log(`[install] ${step}`);
    for (const warning of result.warnings) console.warn(`[install] WARNING: ${warning}`);
    if (result.registered) console.log(`[install] start a new ${label} session to load the plugin's Omnodex tools`);
    await addInstallation({
      target,
      component: "plugin",
      scope: "user",
      settingsFile: name,
      installedAt: new Date().toISOString(),
      installedVersion: getInstalledVersion(),
      usesLauncher: false,
      pluginPath: result.pluginPath,
      pluginVersion: bundle.version,
      pluginOverride: bundle.override,
    });
  } catch (err) {
    console.error(`[install] ${label} plugin not installed: ${(err as Error).message}`);
    if (withHooks) console.error(`[install] the hooks above are installed and record without it`);
    console.error(`[install] retry with \`omnodex install ${target} --plugin\`, or install a downloaded bundle with --from <file>`);
    process.exitCode = 1;
  }
}

const SURFACE_INSTALLERS: Record<Surface, (args: string[]) => Promise<void>> = {
  "claude-code": (args) => installClaudeCode(args),
  codex: (args) => installCodex(args),
  antigravity: (args) => installAntigravity(args),
};

/**
 * `omnodex install` with no target: find every supported surface on this
 * host, show what will be written, confirm once, install each, and sign in
 * to the dashboard once at the end.
 */
async function installAllSurfaces(args: string[]): Promise<void> {
  const positional = args.find((a) => !a.startsWith("-"));
  const projectPath = path.resolve(positional ?? process.cwd());
  const flags = args.filter((a) => a.startsWith("-") && !YES_FLAGS.includes(a) && a !== "--everywhere" && a !== "--this-project");
  const paths = resolvePaths();

  const detected = detectSurfaces({ home: os.homedir(), platform: process.platform, env: process.env });
  const note = wslNote(detectWsl(defaultWslProbe(process.env), projectPath));
  const printNote = () => {
    if (note.length === 0) return;
    console.log("");
    for (const line of note) console.log(line ? `[install] ${line}` : "");
  };

  if (detected.length === 0) {
    console.error(`[install] no supported agent surfaces found on this host (looked for ${Object.values(SURFACE_LABELS).join(", ")}).`);
    console.error(`[install] install one first, or name a target: omnodex install <target>`);
    printNote();
    process.exitCode = 1;
    return;
  }

  // One scope for every surface. --yes, and the plan shown without a
  // terminal, use the recommended every-project scope.
  const scope: HookScopeChoice = args.includes("--this-project") || args.includes("--legacy-shim")
    ? "this-project"
    : args.includes("--everywhere") || hasYes(args) || !process.stdin.isTTY
      ? "everywhere"
      : await askHookScope(projectPath);
  const plan = detected.map((d) => ({
    ...d,
    file: scope === "everywhere" ? userHooksFile(d.surface) : surfaceHooksFile(d.surface, projectPath, paths.home, flags),
  }));
  const width = Math.max(...plan.map((p) => SURFACE_LABELS[p.surface].length));
  const where = scope === "everywhere" ? "every project" : projectPath;
  console.log(`[install] Omnodex will set up ${plan.length === 1 ? "this agent surface" : "these agent surfaces"} to record ${where}:`);
  console.log("");
  const components = installComponents(args);
  for (const p of plan) {
    console.log(`  ${SURFACE_LABELS[p.surface].padEnd(width)}  (found: ${p.evidence})`);
    const shown = p.file.startsWith(projectPath + path.sep) ? path.relative(projectPath, p.file) : p.file;
    if (components.hooks) console.log(`  ${"".padEnd(width)}  hooks: ${shown}`);
    if (components.plugin) {
      const { name, platform } = SURFACE_PLUGIN[p.surface];
      const version = flagValue(args, "--plugin-version") ?? PLUGIN_PINS[platform].version;
      console.log(`  ${"".padEnd(width)}  plugin: ${name} ${version}`);
    }
  }
  printNote();
  console.log("");

  if (!hasYes(args)) {
    if (!process.stdin.isTTY) {
      console.error(`[install] not running in a terminal, so nothing was installed. Re-run with --yes to install.`);
      process.exitCode = 1;
      return;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = (await rl.question("Install? (Y/n) ")).trim().toLowerCase();
    rl.close();
    if (answer !== "" && answer !== "y" && answer !== "yes") {
      console.log("[install] cancelled");
      return;
    }
  }

  // Each surface skips the sign-in; it runs once below for the whole install.
  const surfaceArgs = [projectPath, ...flags.filter((f) => f !== "--no-connect"), "--no-connect", `--${scope}`];
  const outcomes: { surface: Surface; result: string; failed: boolean }[] = [];
  const priorExitCode = process.exitCode;
  for (const p of plan) {
    console.log("");
    console.log(`[install] ${SURFACE_LABELS[p.surface]}:`);
    const before = await readOrNull(p.file);
    process.exitCode = undefined;
    let error: string | null = null;
    try {
      await SURFACE_INSTALLERS[p.surface](surfaceArgs);
      if (process.exitCode) error = "install reported an error (see above)";
    } catch (err) {
      error = (err as Error).message;
      console.error(`[install] ${SURFACE_LABELS[p.surface]} failed: ${error}`);
    }
    const after = await readOrNull(p.file);
    const result = error ? `failed: ${error}` : installOutcome(before, after);
    outcomes.push({ surface: p.surface, result, failed: error !== null });
  }
  const anyFailed = outcomes.some((o) => o.failed);
  process.exitCode = anyFailed ? 1 : priorExitCode;

  console.log("");
  console.log(`[install] summary:`);
  for (const o of outcomes) console.log(`  ${SURFACE_LABELS[o.surface].padEnd(width)}  ${o.result}`);
  if (outcomes.every((o) => o.result === "already set up, nothing changed")) {
    console.log(`[install] nothing to change; Omnodex is already set up here`);
  }
  if (outcomes.some((o) => !o.failed)) {
    await connectAfterInstall(paths.home, {
      args,
      platform: detected.length === 1 ? platformFromTarget(detected[0].surface) : undefined,
      projectLabel: path.basename(projectPath),
    });
  }
}

async function installClaudeCode(args: string[]): Promise<void> {
  const projectPath = path.resolve(args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const components = installComponents(args);
  if (components.hooks && !(await installClaudeCodeHooks(args, projectPath))) return;
  if (components.plugin) await installPluginComponent("claude-code", args, projectPath, components.hooks);
  await connectAfterInstall(resolvePaths().home, {
    args,
    platform: platformFromTarget("claude-code"),
    projectLabel: path.basename(projectPath),
  });
}

/** Claude Code hooks; false when the install stopped (an error was reported). */
async function installClaudeCodeHooks(args: string[], projectPath: string): Promise<boolean> {
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const useProjectSettings = args.includes("--project-settings");
  const useLegacy = args.includes("--legacy-shim");

  const targetFile = useProjectSettings ? "settings.json" : "settings.local.json";
  const alternateFile = useProjectSettings ? "settings.local.json" : "settings.json";

  const scope = await resolveHookScope("claude-code", args, projectPath, paths.home);
  if (scope === null) return false;
  if (scope === "everywhere") {
    await installEverywhere("claude-code", projectPath, args);
    return true;
  }

  // Write (or refresh) the stable launcher and use it as the shim path.
  // The launcher resolves the actual shim at runtime, so hook commands
  // survive npm updates without re-running `omnodex install`.
  const shimPath = useLegacy
    ? CLAUDE_HOOK_SHIM_PATH
    : await writeLauncher("claude-code");

  // Warn if Omnodex hooks already exist in the alternate settings file.
  // Claude Code merges settings.json and settings.local.json; duplicate hooks
  // cause every event to be processed twice and produce double risk findings.
  const nodePath = useLegacy ? process.execPath : "node";
  const portable = canUsePortableHookCommand(paths, { useLegacy, debug });
  const homeRelativeShimPath = portable ? launcherHomeRelativePath("claude-code") : undefined;
  const alternateInterceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath,
    omnodexHome: paths.home,
    settingsFile: alternateFile,
    debug,
    nodePath,
  });
  if (await alternateInterceptor.isInstalled()) {
    console.warn(
      `[install] WARNING: Omnodex hooks already present in ` +
      `${alternateInterceptor.settingsFilePath()}`,
    );
    console.warn(
      `[install]          Hooks in both files will produce duplicate events.`,
    );
    console.warn(
      `[install]          Run \`omnodex uninstall claude-code --${useProjectSettings ? "" : "project-"}settings ${projectPath}\` to remove them from the alternate file first.`,
    );
  }

  const interceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath,
    omnodexHome: paths.home,
    settingsFile: targetFile,
    debug,
    nodePath,
    homeRelativeShimPath,
  });
  await interceptor.install();
  console.log(`[install] installed Claude Code hooks into`);
  console.log(`          ${interceptor.settingsFilePath()}`);
  if (useLegacy) {
    console.log(`[install] shim:         ${shimPath} (legacy absolute path)`);
    console.log(`[install] node:         ${nodePath}`);
    console.log(`[install] note: re-run \`omnodex install claude-code\` after npm updates or Node version changes`);
  } else {
    console.log(`[install] launcher:     ${shimPath}`);
    console.log(`[install] hooks survive npm updates — no need to re-run install after upgrading`);
  }
  if (!useLegacy) await checkLauncherShim("claude-code", paths.home, CLAUDE_HOOK_SHIM_PATH);
  logHookCommandForm("claude-code", portable, useLegacy);
  await noteProjectScope("claude-code", projectPath, paths.home);
  console.log(`[install] OMNODEX_HOME: ${paths.home}`);
  console.log(
    `[install] run \`omnodex uninstall claude-code ${projectPath}\` to remove`,
  );

  // Record in the installation registry
  await addInstallation({
    target: "claude-code",
    component: "hooks",
    scope: "project",
    projectPath,
    settingsFile: targetFile,
    installedAt: new Date().toISOString(),
    installedVersion: getInstalledVersion(),
    usesLauncher: !useLegacy,
    launcherPath: useLegacy ? undefined : shimPath,
  });
  return true;
}

async function installCodex(args: string[]): Promise<void> {
  const projectPath = path.resolve(args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const components = installComponents(args);
  if (components.hooks && !(await installCodexHooks(args, projectPath))) return;
  if (components.plugin) await installPluginComponent("codex", args, projectPath, components.hooks);
  await connectAfterInstall(resolvePaths().home, {
    args,
    platform: platformFromTarget("codex"),
    projectLabel: path.basename(projectPath),
  });
}

/** Codex hooks; false when the install stopped (an error was reported). */
async function installCodexHooks(args: string[], projectPath: string): Promise<boolean> {
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const useLegacy = args.includes("--legacy-shim");

  const scope = await resolveHookScope("codex", args, projectPath, paths.home);
  if (scope === null) return false;
  if (scope === "everywhere") {
    await installEverywhere("codex", projectPath, args);
    return true;
  }

  const shimPath = useLegacy
    ? CODEX_HOOK_SHIM_PATH
    : await writeLauncher("codex");

  const nodePath = useLegacy ? process.execPath : "node";
  const portable = canUsePortableHookCommand(paths, { useLegacy, debug });
  const interceptor = new CodexInterceptor({
    projectPath,
    shimPath,
    omnodexHome: paths.home,
    debug,
    nodePath,
    homeRelativeShimPath: portable ? launcherHomeRelativePath("codex") : undefined,
  });
  await interceptor.install();
  console.log(`[install] installed Codex hooks into`);
  console.log(`          ${interceptor.hooksFilePath()}`);
  if (useLegacy) {
    console.log(`[install] shim:         ${shimPath} (legacy absolute path)`);
    console.log(`[install] node:         ${nodePath}`);
    console.log(`[install] note: re-run \`omnodex install codex\` after npm updates or Node version changes`);
  } else {
    console.log(`[install] launcher:     ${shimPath}`);
    console.log(`[install] hooks survive npm updates — no need to re-run install after upgrading`);
  }
  if (!useLegacy) await checkLauncherShim("codex", paths.home, CODEX_HOOK_SHIM_PATH);
  logHookCommandForm("codex", portable, useLegacy);
  await noteProjectScope("codex", projectPath, paths.home);
  console.log(`[install] OMNODEX_HOME: ${paths.home}`);
  console.log(`[install] hooks are enabled by default; this project will ask you to trust new hook commands`);
  console.log(
    `[install] run \`omnodex uninstall codex ${projectPath}\` to remove`,
  );

  // Record in the installation registry
  await addInstallation({
    target: "codex",
    component: "hooks",
    scope: "project",
    projectPath,
    settingsFile: "hooks.json",
    installedAt: new Date().toISOString(),
    installedVersion: getInstalledVersion(),
    usesLauncher: !useLegacy,
    launcherPath: useLegacy ? undefined : shimPath,
  });
  return true;
}

async function installAntigravity(args: string[]): Promise<void> {
  const projectPath = path.resolve(args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const components = installComponents(args);
  if (components.hooks || components.mcp) {
    if (!(await installAntigravityHooksAndMcp(args, projectPath, components))) return;
  }
  if (components.plugin) await installPluginComponent("antigravity", args, projectPath, components.hooks);
  await connectAfterInstall(resolvePaths().home, {
    args,
    platform: platformFromTarget("antigravity"),
    projectLabel: path.basename(projectPath),
  });
}

/**
 * Antigravity hooks and the project MCP entry (--mcp); false when the
 * install stopped (an error was reported).
 */
async function installAntigravityHooksAndMcp(
  args: string[],
  projectPath: string,
  components: InstallComponents,
): Promise<boolean> {
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const useLegacy = args.includes("--legacy-shim");
  let doHooks = components.hooks;
  const doMcp = components.mcp;

  if (doHooks) {
    const scope = await resolveHookScope("antigravity", args, projectPath, paths.home);
    if (scope === null) return false;
    if (scope === "everywhere") {
      await installEverywhere("antigravity", projectPath, args);
      // Nothing more to write into the project unless --mcp asked for it.
      doHooks = false;
      if (!doMcp) return true;
    }
  }

  const shimPath = useLegacy
    ? ANTIGRAVITY_HOOK_SHIM_PATH
    : await writeLauncher("antigravity");

  const nodePath = useLegacy ? process.execPath : "node";
  // A project hooks file can reach other machines (a shared repo, a synced
  // folder), so it names the launcher by $HOME rather than this machine's
  // path. Windows hooks run under cmd.exe, which does not expand $HOME.
  const portable =
    canUsePortableHookCommand(paths, { useLegacy, debug }) && process.platform !== "win32";

  if (doHooks) {
    const interceptor = new AntigravityInterceptor({
      projectPath,
      shimPath,
      omnodexHome: paths.home,
      debug,
      nodePath,
      homeRelativeShimPath: portable ? launcherHomeRelativePath("antigravity") : undefined,
    });
    await interceptor.install();
    console.log(`[install] installed Antigravity hooks into`);
    console.log(`          ${interceptor.hooksFilePath()}`);
    if (useLegacy) {
      console.log(`[install] shim:         ${shimPath} (legacy absolute path)`);
      console.log(`[install] node:         ${nodePath}`);
      console.log(`[install] note: re-run \`omnodex install antigravity\` after npm updates or Node version changes`);
    } else {
      console.log(`[install] launcher:     ${shimPath}`);
      console.log(`[install] hooks survive npm updates — no need to re-run install after upgrading`);
    }
    console.log(`[install] OMNODEX_HOME: ${paths.home}`);
    if (!useLegacy) await checkLauncherShim("antigravity", paths.home, ANTIGRAVITY_HOOK_SHIM_PATH);
    logHookCommandForm("antigravity", portable, useLegacy);
    console.log(`[install] hooks apply to all Antigravity surfaces (CLI, Desktop, IDE)`);
    await noteProjectScope("antigravity", projectPath, paths.home);
    console.log(
      `[install] run \`omnodex uninstall antigravity ${projectPath}\` to remove`,
    );
  }

  const mcpWritten = doMcp ? await installAntigravityMcp(projectPath, paths.home, nodePath) : false;

  // Record in the installation registry, one entry per component
  const installedAt = new Date().toISOString();
  if (doHooks) {
    await addInstallation({
      target: "antigravity",
      component: "hooks",
      scope: "project",
      projectPath,
      settingsFile: "hooks.json",
      installedAt,
      installedVersion: getInstalledVersion(),
      usesLauncher: !useLegacy,
      launcherPath: useLegacy ? undefined : shimPath,
    });
  }
  if (mcpWritten) {
    await addInstallation({
      target: "antigravity",
      component: "mcp",
      scope: "project",
      projectPath,
      settingsFile: "mcp_config.json",
      installedAt,
      installedVersion: getInstalledVersion(),
      usesLauncher: !useLegacy,
      launcherPath: useLegacy ? undefined : shimPath,
    });
  }
  return true;
}

/**
 * Write the Omnodex MCP proxy server entry into the project's
 * .agents/mcp_config.json. Uses absolute paths so agy/Desktop can
 * resolve the command regardless of cwd.
 *
 * The launch-proxy.js script handles version-manager resolution and
 * locating the actual omnodex-mcp-proxy binary.
 */
async function installAntigravityMcp(
  projectPath: string,
  omnodexHome: string,
  nodePath: string,
): Promise<boolean> {
  // Locate launch-proxy.js: check plugin install dirs, then fall back
  // to the omnodex-plugins source tree.
  const candidates = [
    // agy plugin install location (observed)
    path.join(os.homedir(), ".gemini", "config", "plugins", "omnodex-antigravity", "bin", "launch-proxy.js"),
    // agy docs location
    path.join(os.homedir(), ".gemini", "antigravity-cli", "plugins", "omnodex-antigravity", "bin", "launch-proxy.js"),
  ];

  let launchProxyPath: string | null = null;
  for (const candidate of candidates) {
    try {
      await fs.access(candidate);
      launchProxyPath = candidate;
      break;
    } catch { /* not found */ }
  }

  if (!launchProxyPath) {
    console.warn(`[install] WARNING: could not find launch-proxy.js in plugin dirs.`);
    console.warn(`[install]          Install the plugin first: unzip omnodex-antigravity.plugin,`);
    console.warn(`[install]          then \`agy plugin install <dir>\``);
    console.warn(`[install]          After installing, re-run with --mcp to configure the proxy.`);
    return false;
  }

  const mcpConfigPath = path.join(projectPath, ".agents", "mcp_config.json");
  const agentsDir = path.dirname(mcpConfigPath);
  await fs.mkdir(agentsDir, { recursive: true });

  // Read existing config if present.
  let existing: Record<string, unknown> = {};
  try {
    const raw = await fs.readFile(mcpConfigPath, "utf8");
    if (raw.trim()) existing = JSON.parse(raw);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  const mcpServers = (existing.mcpServers ?? {}) as Record<string, unknown>;
  mcpServers["omnodex"] = {
    command: nodePath,
    // --platform labels the proxy's sessions as Antigravity in the dashboards.
    args: [launchProxyPath, "--platform", "antigravity"],
    env: {
      OMNODEX_HOME: omnodexHome,
    },
  };

  const next = { ...existing, mcpServers };
  await fs.writeFile(mcpConfigPath, JSON.stringify(next, null, 2) + "\n", "utf8");

  console.log(`[install] wrote MCP proxy config to`);
  console.log(`          ${mcpConfigPath}`);
  console.log(`[install] proxy launcher: ${launchProxyPath}`);
  return true;
}

async function cmdUninstall(args: string[]): Promise<void> {
  const projectPath = path.resolve(
    args.find((a) => !a.startsWith("--") && !isTargetName(a)) ?? process.cwd(),
  );
  const paths = resolvePaths();
  const confirmed = args.includes("--confirm");
  const everywhereFlag = args.includes("--everywhere");
  const pluginFlag = args.includes("--plugin");
  const hooksFlag = args.includes("--hooks") || everywhereFlag || !pluginFlag;

  const targetName = args.find((a) => isTargetName(a));
  const targetArg = targetName === undefined ? undefined : canonicalTarget(targetName) as InstallTarget;
  const targets: readonly InstallTarget[] = targetArg ? [targetArg] : VALID_TARGETS;
  const scope = await readHookScope(paths.home);

  interface Action {
    lines: string[];
    run: () => Promise<string>;
  }
  const actions: Action[] = [];
  const pluginCtx = { home: os.homedir(), omnodexHome: paths.home, env: process.env, projectPath };

  if (pluginFlag) {
    for (const target of targets) {
      const [entry] = await findInstallations({ target, component: "plugin" });
      const dir = pluginDir(target, pluginCtx);
      if (!entry && !(await isDirectory(dir))) continue;
      const name = SURFACE_PLUGIN[target].name;
      actions.push({
        lines: [`${SURFACE_LABELS[target]}: remove the ${name} plugin${entry?.pluginVersion ? ` ${entry.pluginVersion}` : ""} (all projects)`, `  ${dir}`],
        run: async () => {
          const done = await uninstallPlugin(target, pluginCtx);
          await removeInstallation(target, undefined, "plugin");
          return `removed the ${SURFACE_LABELS[target]} plugin: ${done.join("; ")}`;
        },
      });
    }
    if (actions.length === 0 && !args.includes("--hooks") && !everywhereFlag) {
      console.log(`[uninstall] no Omnodex plugin installed for ${targetArg ? SURFACE_LABELS[targetArg] : "any agent"}`);
      return;
    }
  }

  if (!hooksFlag) {
    // --plugin alone: nothing else to do.
  } else if (everywhereFlag) {
    // Stop recording every project: remove the user-level hooks.
    for (const target of targets) {
      const hooks = userLevelHooks(target, { omnodexHome: paths.home, shimPath: launcherPath(target) });
      const present = (await readOrNull(hooks.file))?.includes("omnodex") ?? false;
      if (!isEverywhere(scope, target) && !present) continue;
      actions.push({
        lines: [`${SURFACE_LABELS[target]}: stop recording every project`, `  ${hooks.file}`],
        run: async () => {
          await hooks.uninstall();
          await setEverywhere(paths.home, target, false);
          await removeInstallation(target, undefined, "hooks");
          return `removed ${SURFACE_LABELS[target]} every-project hooks from ${hooks.file}`;
        },
      });
    }
    if (actions.length === 0) {
      console.log(`[uninstall] ${targetArg ? `${SURFACE_LABELS[targetArg]} does not record` : "no agent records"} every project; nothing to remove`);
      return;
    }
  } else {
    for (const hook of (await findProjectHooks(projectPath, paths.home)).filter((h) => targets.includes(h.target))) {
      actions.push({
        lines: [`${hook.label}: remove this project's hooks`, `  ${hook.path}`],
        run: async () => {
          await hook.uninstall();
          await removeInstallation(hook.target as LauncherPlatform, projectPath, "hooks");
          return `removed ${hook.label} hooks from ${hook.path}`;
        },
      });
    }
    // With every-project recording on, leave this project out.
    for (const target of targets) {
      if (!isEverywhere(scope, target) || exclusionFor(scope, target, projectPath)) continue;
      actions.push({
        lines: [`${SURFACE_LABELS[target]}: stop recording this project (other projects are still recorded)`],
        run: async () => {
          await addExclusion(paths.home, target, projectPath);
          return `${SURFACE_LABELS[target]} no longer records ${projectPath}; run \`omnodex install ${target}\` here to record it again`;
        },
      });
    }
    if (actions.length === 0) {
      await notePluginsStay(targets);
      const leftOut = targets.filter((t) => isEverywhere(scope, t));
      if (leftOut.length > 0) {
        console.log(`[uninstall] ${projectPath} is already left out for ${leftOut.map((t) => SURFACE_LABELS[t]).join(", ")}`);
      } else if (targetArg) {
        console.log(`[uninstall] no ${targetArg} hooks found in ${projectPath}`);
      } else {
        console.log(`[uninstall] no Omnodex hooks found in ${projectPath}`);
      }
      return;
    }
  }

  console.log(`[uninstall] this will:\n`);
  for (const action of actions) {
    for (const line of action.lines) console.log(`  ${line}`);
  }
  console.log("");

  // Removing monitoring is for a person: an agent's shell has no terminal.
  const unattended = args.includes("--unattended");
  if (!unattended && !(process.stdin.isTTY && process.stdout.isTTY)) {
    console.error(
      "[uninstall] removing Omnodex needs a person at an interactive terminal, so an agent cannot switch it off. " +
        "Run it yourself in a terminal, or pass --unattended for a scripted removal (it is recorded and raises a finding).",
    );
    process.exitCode = 1;
    return;
  }
  if (unattended) setMonitoringActor("unattended");

  if (!confirmed && !unattended) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question("Proceed? (Y/n) ");
    rl.close();
    if (answer.trim() !== "Y") {
      console.log("[uninstall] cancelled");
      return;
    }
  }

  for (const action of actions) console.log(`[uninstall] ${await action.run()}`);
  if (hooksFlag && !pluginFlag) await notePluginsStay(targets);
}

/** After removing hooks: a plugin covers every project and is not removed with them. */
async function notePluginsStay(targets: readonly InstallTarget[]): Promise<void> {
  for (const target of targets) {
    const [entry] = await findInstallations({ target, component: "plugin" });
    if (!entry) continue;
    console.log(`[uninstall] the ${SURFACE_LABELS[target]} plugin stays installed for every project; \`omnodex uninstall ${target} --plugin\` removes it`);
  }
}

async function cmdStatus(_args: string[]): Promise<void> {
  const projectPath = path.resolve(_args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const paths = resolvePaths();
  const showAll = _args.includes("--all");

  // Version and environment info
  const version = getInstalledVersion();
  console.log(`[status] omnodex:      v${version}`);
  console.log(`[status] OMNODEX_HOME: ${paths.home}`);

  if (!showAll) {
    console.log(`[status] project:      ${projectPath}`);
  }

  console.log(
    `[status] rules:        ${describeRules(loadAdvancedRules(paths.home), COMMUNITY_RULES.length)}`,
  );

  await printCaptureHealth(paths.home);
  await printLauncherHealth(paths.home);
  await printAutoSyncHealth(paths.home);
  await printLivePushHealth(paths.home);
  await printMonitoringHealth(paths.home);
  await printAdvancedUsage(paths.home);
  console.log("");

  // If --all, show the full registry instead of per-project detection
  if (showAll) {
    console.log("");
    const allInstalls = await listInstallations();
    if (allInstalls.length === 0) {
      console.log(`  No installations registered.`);
      console.log(`\n  Run \`omnodex install <target>\` to get started.`);
      return;
    }
    console.log(`  Registered installations (${allInstalls.length}):\n`);
    for (const inst of allInstalls) {
      const launcherTag = inst.usesLauncher ? "launcher" : "legacy";
      const where = inst.scope === "user" ? "user-wide" : inst.projectPath;
      console.log(`  ${inst.target} ${inst.component} (${inst.scope}) — ${where}`);
      console.log(`    installed: ${inst.installedAt}  v${inst.installedVersion}  (${launcherTag})`);
      if (inst.component === "plugin") {
        const version = inst.pluginVersion ? ` v${inst.pluginVersion}` : "";
        const override = inst.pluginOverride ? " (version override)" : "";
        console.log(`    plugin: ${inst.pluginPath ?? inst.settingsFile}${version}${override}`);
      } else {
        console.log(`    settings: ${inst.settingsFile}`);
      }
    }

    const scope = await readHookScope(paths.home);
    if (scope.everywhere.length > 0) {
      console.log(`\n  Recording every project: ${scope.everywhere.map((t) => SURFACE_LABELS[t]).join(", ")}`);
      for (const [root, targets] of Object.entries(scope.excluded)) {
        console.log(`    left out: ${root} (${targets.map((t) => SURFACE_LABELS[t]).join(", ")})`);
      }
    }

    // Warn about stale (legacy) installations
    const stale = await findStaleInstallations();
    if (stale.length > 0) {
      console.log(`\n  ⚠ ${stale.length} installation(s) use legacy absolute paths and will break on npm update.`);
      console.log(`    Re-run \`omnodex install <target> <project>\` to upgrade them to stable launchers.`);
    }
    return;
  }

  let anyInstalled = false;

  // Every-project recording, and whether this project is left out.
  const scope = await readHookScope(paths.home);
  for (const target of scope.everywhere) {
    const root = exclusionFor(scope, target, projectPath);
    console.log(`  ${SURFACE_LABELS[target]}: records every project${root ? ", but this project is left out" : ""}`);
    console.log(`    ${userHooksFile(target)}`);
    await reportMissingHookPaths(userHooksFile(target), `omnodex install ${target} --everywhere`);
    if (root) {
      console.log(`    left out: ${root}; run \`omnodex install ${target}\` here to record it again`);
    }
    anyInstalled = true;
  }
  for (const plugin of await findInstallations({ component: "plugin" })) {
    const override = plugin.pluginOverride ? " (chosen version, not this CLI's pin)" : "";
    console.log(`  ${SURFACE_LABELS[plugin.target]} plugin: ${SURFACE_PLUGIN[plugin.target].name} ${plugin.pluginVersion ?? ""}${override}, for every project`);
    console.log(`    ${plugin.pluginPath ?? plugin.settingsFile}`);
    anyInstalled = true;
  }
  const stepsAside = (target: InstallTarget) => {
    if (isEverywhere(scope, target)) console.log(`    steps aside: the every-project hooks record this project`);
  };

  // Check Claude Code
  for (const settingsFile of ["settings.local.json", "settings.json"] as const) {
    const interceptor = new ClaudeCodeInterceptor({
      projectPath,
      shimPath: CLAUDE_HOOK_SHIM_PATH,
      omnodexHome: paths.home,
      settingsFile,
    });
    if (isUserLevelFile("claude-code", interceptor.settingsFilePath())) continue;
    if (await interceptor.isInstalled()) {
      console.log(`  Claude Code (${settingsFile}): installed`);
      console.log(`    ${interceptor.settingsFilePath()}`);
      stepsAside("claude-code");
      await reportMissingHookPaths(
        interceptor.settingsFilePath(),
        `omnodex install claude-code --this-project${settingsFile === "settings.json" ? " --project-settings" : ""}`,
      );
      // Hooks an older version installed lack the events added since;
      // install is idempotent and adds them.
      const missing = await interceptor.missingEvents();
      if (missing.length > 0) {
        console.log(`    missing hooks: ${missing.join(", ")} (installed by an older version)`);
        console.log(`    run \`omnodex install claude-code${settingsFile === "settings.json" ? " --project-settings" : ""}\` in this project to add them`);
      }
      anyInstalled = true;
    }
  }

  // Check Codex
  const codexInterceptor = new CodexInterceptor({
    projectPath,
    shimPath: CODEX_HOOK_SHIM_PATH,
    omnodexHome: paths.home,
  });
  try {
    const codexHooksPath = codexInterceptor.hooksFilePath();
    if (isUserLevelFile("codex", codexHooksPath)) throw new Error("user-level file");
    await fs.access(codexHooksPath);
    const fileContent = await fs.readFile(codexHooksPath, "utf8");
    if (fileContent.includes("omnodex")) {
      console.log(`  Codex: installed`);
      console.log(`    ${codexHooksPath}`);
      stepsAside("codex");
      await reportMissingHookPaths(codexHooksPath, "omnodex install codex --this-project");
      anyInstalled = true;
    }
  } catch { /* not installed */ }

  // Check Antigravity
  const antigravityInterceptor = new AntigravityInterceptor({
    projectPath,
    shimPath: ANTIGRAVITY_HOOK_SHIM_PATH,
    omnodexHome: paths.home,
  });
  try {
    const agHooksPath = antigravityInterceptor.hooksFilePath();
    await fs.access(agHooksPath);
    const fileContent = await fs.readFile(agHooksPath, "utf8");
    if (fileContent.includes("omnodex")) {
      console.log(`  Antigravity: installed`);
      console.log(`    ${agHooksPath}`);
      stepsAside("antigravity");
      await reportMissingHookPaths(agHooksPath, "omnodex install antigravity --this-project");
      anyInstalled = true;
    }
  } catch { /* not installed */ }

  if (!anyInstalled) {
    console.log(`  No Omnodex hooks installed in this project.`);
    console.log(`\n  Run \`omnodex install <target>\` to get started.`);
    console.log(`  Targets: ${VALID_TARGETS.join(", ")}`);
  }
}

const LAUNCHER_LOG_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Report whether each installed hook launcher can find its shim, and any
 * launcher failures logged recently. Launchers exit 0 when they fail so the
 * agent is never blocked, which makes this the only place a broken install
 * becomes visible.
 */
async function printLauncherHealth(omnodexHome: string): Promise<void> {
  const rows: string[] = [];
  let unresolved = 0;
  for (const platform of LAUNCHER_PLATFORMS) {
    try {
      await fs.access(launcherPath(platform));
    } catch {
      continue;
    }
    const shim = resolveLauncherShim(platform);
    if (!shim) unresolved++;
    rows.push(`    ${platform.padEnd(12)} ${shim ?? "shim not found: these hooks record nothing"}`);
  }
  if (rows.length > 0) {
    console.log(`[status] hook launchers:`);
    for (const row of rows) console.log(row);
    if (unresolved > 0) {
      console.log(`    Install omnodex with npm, or set shim_paths in ${path.join(omnodexHome, "omnodex-config.json")}.`);
    }
  }

  let logText = "";
  try {
    logText = await fs.readFile(path.join(omnodexHome, "launcher.log"), "utf8");
  } catch {
    return;
  }
  const since = Date.now() - LAUNCHER_LOG_WINDOW_MS;
  const recent = logText.split("\n").filter((line) => {
    if (!line.includes("FATAL")) return false;
    const ts = Date.parse(line.match(/^\[([^\]]+)\]/)?.[1] ?? "");
    return !Number.isNaN(ts) && ts >= since;
  });
  if (recent.length > 0) {
    console.log(`[status] launcher errors in the last 24h: ${recent.length}`);
    console.log(`    last: ${recent[recent.length - 1]}`);
    console.log(`    log:  ${path.join(omnodexHome, "launcher.log")}`);
  }
}


/**
 * Report the automatic sync that hook shims and the MCP proxy run in the
 * background. Both swallow their errors so the agent is never blocked, which
 * makes this the only place a sync that has been failing quietly shows up.
 *
 * Silent on a machine with no cloud credentials and no sync history: that is
 * the entire free tier, and it has nothing to say.
 */
async function printAutoSyncHealth(omnodexHome: string): Promise<void> {
  const state = await readAutoSyncState(omnodexHome);
  const hasHistory = Boolean(state.last_attempt_at ?? state.last_success_at);
  if (!hasHistory && !(await readStreamConfig(omnodexHome))) return;

  if (state.last_success_at) {
    const label = typeof state.last_sync_segments === "number" ? "commit" : "blob";
    const blob = state.last_blob_id ? `  ${label} ${state.last_blob_id}` : "";
    console.log(
      `[status] auto sync:   last success ${formatWhen(state.last_success_at)}${blob}`,
    );
  } else {
    console.log(`[status] auto sync:   no successful sync yet`);
  }

  if (state.last_error) {
    console.log(`    last error: ${state.last_error}`);
    if (state.last_attempt_at) {
      console.log(`    last attempt: ${formatWhen(state.last_attempt_at)}`);
    }
  }

  const blob = describeSyncBlob(state, omnodexHome);
  if (blob) console.log(`[status] ${typeof state.last_sync_segments === "number" ? "synced data:" : "sync blob:  "} ${blob}`);
}

/** At this share of the cloud's limit, status warns that the blob is close to it. */
export const SYNC_BLOB_WARN_FRACTION = 0.8;

const mb = (bytes: number) => (bytes / 1048576).toFixed(1) + " MB";

/**
 * The last sync's size against the cloud's limit, with what to do when it is
 * close to it or over it; null before any sync. A segmented sync reports its
 * total and its largest segment, which is what the limit applies to; only a
 * single very large session brings a segment near it. For a single blob, the
 * way to shrink it is to move session files out of the local event log: the
 * next sync rebuilds from what is left.
 */
export function describeSyncBlob(
  state: {
    last_blob_bytes?: number;
    blob_too_large_bytes?: number | null;
    last_sync_segments?: number | null;
    last_sync_total_bytes?: number | null;
  },
  omnodexHome: string,
): string | null {
  const limit = `${Math.round(SYNC_BLOB_MAX_BYTES / 1048576)} MB`;
  const remedy =
    `To make room, move older session files out of ${path.join(omnodexHome, "event-log", "sessions")} ` +
    `(keep a copy elsewhere); the next sync leaves them out of the blob.`;
  if (state.blob_too_large_bytes) {
    return `${mb(state.blob_too_large_bytes)}, over the ${limit} limit: sync is failing and the dashboard is not updating. ${remedy}`;
  }
  if (state.last_blob_bytes === undefined) return null;
  const pct = Math.round((state.last_blob_bytes / SYNC_BLOB_MAX_BYTES) * 100);
  if (typeof state.last_sync_segments === "number" && typeof state.last_sync_total_bytes === "number") {
    const n = state.last_sync_segments;
    const line = `${mb(state.last_sync_total_bytes)} in ${n} segment${n === 1 ? "" : "s"}, largest ${mb(state.last_blob_bytes)} of ${limit} (${pct}%)`;
    if (state.last_blob_bytes >= SYNC_BLOB_MAX_BYTES * SYNC_BLOB_WARN_FRACTION) {
      return `${line}: one session is close to the limit; sync stops at ${limit}. ${remedy}`;
    }
    return line;
  }
  const line = `${mb(state.last_blob_bytes)} of ${limit} (${pct}%)`;
  if (state.last_blob_bytes >= SYNC_BLOB_MAX_BYTES * SYNC_BLOB_WARN_FRACTION) {
    return `${line}, close to the limit; sync stops at ${limit}. ${remedy}`;
  }
  return line;
}

/**
 * Make the installed hooks that must answer before a call runs do so
 * (guardrails), or stop them doing so: Claude Code's Omnodex PreToolUse
 * entries become synchronous or async again, and Antigravity's PreToolUse
 * entry is added or removed. Codex always waits on its hooks, so nothing
 * changes there. Covers the user-level files and each project install in
 * the registry. A file another Omnodex home also uses keeps its entries
 * while that home is in guardrails. Returns the files that changed.
 */
async function setGuardrailsHooks(omnodexHome: string, on: boolean): Promise<string[]> {
  const files: Record<"claude-code" | "antigravity", Set<string>> = {
    "claude-code": new Set([userHooksFile("claude-code")]),
    antigravity: new Set([userHooksFile("antigravity")]),
  };
  for (const inst of await listInstallations()) {
    if (inst.component !== "hooks" || inst.scope !== "project" || !inst.projectPath) continue;
    if (inst.target === "claude-code") files["claude-code"].add(path.join(inst.projectPath, ".claude", inst.settingsFile));
    if (inst.target === "antigravity") files.antigravity.add(path.join(inst.projectPath, ".agents", inst.settingsFile));
  }
  const changed: string[] = [];
  for (const file of files["claude-code"]) {
    const interceptor = new ClaudeCodeInterceptor({ projectPath: path.dirname(file), shimPath: CLAUDE_HOOK_SHIM_PATH, omnodexHome, settingsPath: file });
    if (await interceptor.setPreToolUseSync(on)) changed.push(file);
  }
  for (const file of files.antigravity) {
    const interceptor = new AntigravityInterceptor({ projectPath: path.dirname(file), shimPath: ANTIGRAVITY_HOOK_SHIM_PATH, omnodexHome, hooksPath: file });
    if (await interceptor.setPreToolUse(on)) changed.push(file);
  }
  return changed;
}

/**
 * Before switching to guardrails: whether the cached license includes them,
 * and the guardrails module fetched now and opened.
 */
async function prepareGuardrails(omnodexHome: string): Promise<GuardrailsReadiness> {
  if (!(await guardrailsEntitled(omnodexHome))) {
    return { entitled: false, ready: false, detail: "not included in this plan" };
  }
  await refreshGuardrailsModule(omnodexHome, { force: true });
  const load = await loadGuardrailsModule(omnodexHome);
  return { entitled: true, ready: !load.skipped, detail: describeGuardrails(load) };
}

/** Whether recording and uploads are paused on this machine. */
async function printCaptureHealth(omnodexHome: string): Promise<void> {
  const { lines, markers } = await captureStatusLines(omnodexHome);
  await appendMarkers(omnodexHome, markers, pushEventsToCloud);
  for (const line of lines) console.log(line);
  const mode = await currentMode(omnodexHome).catch(() => "monitor");
  const module = mode === "guardrails" ? ` (${describeGuardrails(await loadGuardrailsModule(omnodexHome))})` : "";
  console.log(`[status] enforcement:  ${mode}${module}`);
}

/**
 * Report the live push gate. While the relay says no dashboard is watching,
 * every pusher on the machine holds back for a growing window, so a
 * dashboard that has just connected waits for the next probe. Silent without
 * cloud credentials, like the auto sync line.
 */
async function printLivePushHealth(omnodexHome: string): Promise<void> {
  if (!(await readStreamConfig(omnodexHome))) return;
  console.log(`[status] live push:   ${describeLiveGate(await readLiveGate(omnodexHome))}`);
}

/**
 * Run the monitoring config check now and report each platform: whether
 * every installation still matches the agent's config. A change no Omnodex
 * command made is also recorded (and raises a finding) by the check itself.
 */
async function printMonitoringHealth(omnodexHome: string): Promise<void> {
  const { checks } = await checkMonitoringConfig(omnodexHome, { force: true, push: pushEventsToCloud });
  for (const line of describeMonitoringCheck(checks)) console.log(line);
}

const MONITORING_PROBLEM_TEXT: Record<Exclude<InstallationState, "ok" | "project_gone">, string> = {
  hooks_missing: "hooks missing from",
  hooks_disabled: "hooks switched off by",
  plugin_missing: "plugin missing from",
  plugin_disabled: "plugin disabled in",
  mcp_missing: "MCP entry missing from",
};

/** Status lines for the config check: one summary, then each problem. */
export function describeMonitoringCheck(checks: readonly InstallationCheck[]): string[] {
  if (checks.length === 0) return [];
  const label = (t: string) => SURFACE_LABELS[t as Surface] ?? t;
  const byTarget = new Map<string, InstallationCheck[]>();
  for (const c of checks) byTarget.set(c.target, [...(byTarget.get(c.target) ?? []), c]);
  const summary = [...byTarget].map(([target, list]) => {
    const broken = list.filter((c) => c.state !== "ok" && c.state !== "project_gone").length;
    return `${label(target)} ${broken === 0 ? "ok" : `${broken} problem${broken === 1 ? "" : "s"}`}`;
  });
  const lines = [`[status] monitoring:   ${summary.join(", ")}`];
  for (const c of checks) {
    if (c.state === "ok") continue;
    if (c.state === "project_gone") {
      lines.push(`  project no longer exists: ${c.project_path}; \`omnodex uninstall ${c.target} "${c.project_path}"\` forgets it`);
      continue;
    }
    lines.push(`  ⚠ ${label(c.target)} ${MONITORING_PROBLEM_TEXT[c.state]} ${c.file}`);
    lines.push(`    run \`omnodex install ${c.target}\`${c.scope === "project" ? " in that project" : ""} to restore monitoring`);
  }
  return lines;
}

/** Advanced (Pro) rule usage waiting to be submitted, and any dropped. */
async function printAdvancedUsage(omnodexHome: string): Promise<void> {
  const line = describeAdvancedUsage(await readAdvancedUsage(omnodexHome));
  if (line) console.log(`[status] pro usage:   ${line}`);
}

/** One line for the advanced usage counter, or null when it has never counted. */
export function describeAdvancedUsage(state: AdvancedUsageState): string | null {
  const days = { ...(state.in_flight?.days ?? {}) };
  for (const [day, c] of Object.entries(state.pending)) {
    const d = days[day];
    days[day] = d ? { evaluated: d.evaluated + c.evaluated, findings: d.findings + c.findings } : c;
  }
  const waiting = Object.values(days).reduce((n, d) => n + d.evaluated, 0);
  if (!state.last_submitted_at && waiting === 0 && !state.dropped) return null;
  const parts = [`${waiting} advanced rule checks waiting to send`];
  if (state.last_submitted_at) parts.push(`last sent ${state.last_submitted_at}`);
  if (state.last_error) parts.push(`last error: ${state.last_error}`);
  if (state.dropped) {
    parts.push(
      `${state.dropped.evaluated} checks over ${state.dropped.days} day(s) dropped (older than ` +
        `${ADVANCED_USAGE_MAX_AGE_DAYS} days or refused), not billed`,
    );
  }
  return parts.join("; ");
}

/** One line for the live push gate's state. */
function describeLiveGate(
  state: { paused_until: number; backoff_ms: number; receiving_paused?: boolean } | null,
  now = Date.now(),
): string {
  if (state?.receiving_paused) {
    return "receiving paused by the stream's owner in the dashboard: uploads from this machine are refused until they resume it";
  }
  if (!state || now >= state.paused_until) return "open";
  const left = Math.ceil((state.paused_until - now) / 1000);
  return (
    `paused until ${new Date(state.paused_until).toISOString()} (${left}s left, ` +
    `back-off ${Math.round(state.backoff_ms / 1000)}s): the last push found no dashboard ` +
    `watching or failed. \`omnodex live resume\` pushes the next event at once.`
  );
}

/**
 * omnodex live [resume]
 *
 * Shows the live push gate, or with `resume` clears it so the next event
 * pushes at once instead of waiting out the back-off. Each OMNODEX_HOME has
 * its own gate: on Windows with WSL, run it on the side that records.
 */
async function cmdLive(args: string[]): Promise<void> {
  const home = resolvePaths().home;
  const sub = args.find((a) => !a.startsWith("--"));
  if (sub === undefined || sub === "status") {
    console.log(`[live] ${home}: ${describeLiveGate(await readLiveGate(home))}`);
    return;
  }
  if (sub === "resume") {
    const cleared = await clearLiveGate(home);
    console.log(cleared
      ? `[live] resumed: the next event in ${home} pushes at once`
      : `[live] already open in ${home}`);
    return;
  }
  console.error(`[live] unknown subcommand: ${sub}. Use \`omnodex live\` or \`omnodex live resume\`.`);
  process.exitCode = 1;
}

/** ISO timestamp plus a rough age, e.g. "2026-09-17T18:40:12Z (12m ago)". */
function formatWhen(iso: string): string {
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) return iso;
  const seconds = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (seconds < 60) return `${iso} (${seconds}s ago)`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${iso} (${minutes}m ago)`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${iso} (${hours}h ago)`;
  return `${iso} (${Math.round(hours / 24)}d ago)`;
}


// ---------------------------------------------------------------------------
// mcp-proxy subcommands
// ---------------------------------------------------------------------------

async function cmdMcpProxy(args: string[]): Promise<void> {
  const [sub, ...rest] = args;
  switch (sub) {
    case "start":
      await cmdMcpProxyStart(rest);
      return;
    case "serve":
      await cmdMcpProxyServe(rest);
      return;
    case "install":
      await cmdMcpProxyInstall(rest);
      return;
    case "status":
      await cmdMcpProxyStatus(rest);
      return;
    default:
      console.log(`omnodex mcp-proxy <subcommand>

subcommands:
  start [--config path]   start the MCP proxy server on stdin/stdout.
                          Used by Cowork / Codex plugin mcp.json configs.
                          Defaults to \${OMNODEX_HOME}/omnodex-proxy.json.
  serve --http <host:port> [--config path] [--allow-remote]
                          serve the MCP proxy over Streamable HTTP at
                          http://<host:port>/mcp until stopped. Loopback
                          only unless --allow-remote, which also requires
                          OMNODEX_PROXY_HTTP_TOKEN (clients send it as a
                          bearer token).
  install                 create a template omnodex-proxy.json in
                          \${OMNODEX_HOME} if one does not already exist.
  status                  show configured upstream servers and proxy state.
`);
      if (sub !== undefined && sub !== "help" && sub !== "--help") {
        console.error(`[mcp-proxy] unknown subcommand '${sub}'`);
        process.exitCode = 1;
      }
  }
}

async function cmdMcpProxyStart(args: string[]): Promise<void> {
  const configFlagIdx = args.indexOf("--config");
  const configPath =
    configFlagIdx !== -1 ? args[configFlagIdx + 1] : undefined;

  const config = await loadProxyConfig(configPath, { allowMissing: true });
  const paths = resolvePaths();

  const log = new EventLog({ root: path.join(paths.home, "event-log") });
  await log.init();

  // argv[1] is this CLI; main() runs a background sync when it sees
  // AUTO_SYNC_CHILD_ENV, so the proxy can re-spawn it the same way the
  // standalone omnodex-mcp-proxy binary re-spawns itself.
  const scriptPath = process.argv[1] ?? "";
  const proxy = new MCPProxy(config, {
    projectPath: process.cwd(),
    home: paths.home,
    autoSyncScriptPath: scriptPath,
  });
  const emit = async (event: TraceEvent): Promise<void> => {
    for (const e of await applyCapturePause([event], paths.home)) await log.append(e);
  };
  const stop = await proxy.start(emit);

  async function shutdown(): Promise<void> {
    await stop();
    await log.close();
    // After log.close(), so the detached child sees session.ended.
    await startBackgroundSync({ home: paths.home, scriptPath, detect: true });
  }
  // Normal end: the agent closes stdin.
  void proxy.whenClosed().then(shutdown).then(() => process.exit(0));
  process.on("SIGTERM", () => void shutdown().then(() => process.exit(0)));
  process.on("SIGINT", () => void shutdown().then(() => process.exit(0)));
}

async function cmdMcpProxyServe(args: string[]): Promise<void> {
  const httpIdx = args.indexOf("--http");
  if (httpIdx === -1 || !args[httpIdx + 1]) {
    console.error("[mcp-proxy] serve requires --http <host:port>, e.g. --http 127.0.0.1:8787");
    process.exitCode = 1;
    return;
  }
  const listen = parseHttpListen(args[httpIdx + 1]!);
  const configFlagIdx = args.indexOf("--config");
  const configPath = configFlagIdx !== -1 ? args[configFlagIdx + 1] : undefined;
  const authToken = process.env.OMNODEX_PROXY_HTTP_TOKEN || undefined;

  const config = await loadProxyConfig(configPath, { allowMissing: true });
  const paths = resolvePaths();
  const log = new EventLog({ root: path.join(paths.home, "event-log") });
  await log.init();

  const scriptPath = process.argv[1] ?? "";
  const proxy = new MCPProxy(config, {
    projectPath: process.cwd(),
    home: paths.home,
    autoSyncScriptPath: scriptPath,
    http: {
      ...listen,
      allowRemote: args.includes("--allow-remote"),
      ...(authToken ? { authToken } : {}),
    },
  });
  const stop = await proxy.start(async (event: TraceEvent) => {
    for (const e of await applyCapturePause([event], paths.home)) await log.append(e);
  });
  console.error(`[mcp-proxy] serving MCP over HTTP at ${proxy.httpUrl()} (Ctrl-C to stop)`);

  let shuttingDown: Promise<void> | undefined;
  const shutdown = (): Promise<void> =>
    (shuttingDown ??= (async () => {
      await stop();
      await log.close();
      // After log.close(), so the detached child sees session.ended.
      await startBackgroundSync({ home: paths.home, scriptPath, detect: true });
    })());
  process.on("SIGTERM", () => void shutdown().then(() => process.exit(0)));
  process.on("SIGINT", () => void shutdown().then(() => process.exit(0)));
}

async function cmdMcpProxyInstall(_args: string[]): Promise<void> {
  const paths = resolvePaths();
  const cfgPath = path.join(paths.home, "omnodex-proxy.json");

  let exists = false;
  try {
    await fs.access(cfgPath);
    exists = true;
  } catch {
    // file does not exist
  }

  if (exists) {
    console.log(`[mcp-proxy] config already exists: ${cfgPath}`);
    console.log(`[mcp-proxy] run 'omnodex mcp-proxy status' to inspect it.`);
    return;
  }

  await fs.mkdir(paths.home, { recursive: true });

  const template = {
    version: 1,
    redact_parameters: false,
    upstream_servers: [
      {
        name: "filesystem",
        transport: "stdio",
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/"],
        _comment:
          "Replace with your actual MCP servers. Each entry here replaces a " +
          "direct MCP server entry in your agent config -- point your agent at " +
          "omnodex-mcp-proxy instead and list the real servers here.",
      },
    ],
  };
  await fs.writeFile(cfgPath, JSON.stringify(template, null, 2) + "\n", "utf8");

  console.log(`[mcp-proxy] created template config: ${cfgPath}`);
  console.log();
  console.log(`Next steps:`);
  console.log(`  1. Edit ${cfgPath} to list your upstream MCP servers.`);
  console.log(`  2. In your agent MCP config, replace each upstream entry with:`);
  console.log(`       { "command": "omnodex-mcp-proxy", "args": [] }`);
  console.log(`  3. Run 'omnodex mcp-proxy status' to verify the config.`);
  console.log();
  console.log(`[omnodex] Parameters are logged locally by default.`);
  console.log(`          Set redact_parameters: true in the config to disable.`);
}

async function cmdMcpProxyStatus(_args: string[]): Promise<void> {
  const paths = resolvePaths();

  let config;
  let cfgPath = path.join(paths.home, "omnodex-proxy.json");
  try {
    config = await loadProxyConfig(cfgPath);
  } catch {
    cfgPath = path.join(process.cwd(), "omnodex-proxy.json");
    try {
      config = await loadProxyConfig(cfgPath);
    } catch {
      console.log(`[mcp-proxy] no config found.`);
      console.log(`            run 'omnodex mcp-proxy install' to create one.`);
      return;
    }
  }

  console.log(`[mcp-proxy] config:            ${cfgPath}`);
  console.log(`[mcp-proxy] redact_parameters: ${config.redact_parameters}`);
  console.log(`[mcp-proxy] upstream servers (${config.upstream_servers.length}):`);
  for (const srv of config.upstream_servers) {
    const prefix = srv.name_override
      ? `${srv.name} → ${srv.name_override}`
      : srv.name;
    if (srv.transport === "stdio") {
      const cmd = [srv.command, ...(srv.args ?? [])].join(" ");
      console.log(`              ${prefix}  [stdio]  ${cmd}`);
    } else {
      // Origin and path only: a query string can carry a credential.
      const u = new URL(srv.url);
      console.log(`              ${prefix}  [http]   ${u.origin}${u.pathname}`);
    }
    if (srv.redact_parameters !== undefined) {
      console.log(
        `                redact_parameters: ${srv.redact_parameters} (overrides global)`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// license subcommand
// ---------------------------------------------------------------------------

async function cmdLicense(args: string[]): Promise<void> {
  const [sub] = args;
  const paths = resolvePaths();

  if (sub === "clear") {
    await clearLicenseCache(paths.home);
    console.log("[license] cache cleared");
    return;
  }

  // The same token and API as sync and connect: --token, then
  // OMNODEX_API_TOKEN, then the one `omnodex connect` saved; the cache is
  // the one in this home, which background sync and live push read.
  const creds = await resolveCredentials(paths.home, {
    flagToken: readFlagValue(args, "--token"),
    flagApiUrl: readFlagValue(args, "--api"),
  });
  console.log("[license] validating...");
  const result = await validateLicense({
    apiBaseUrl: creds?.apiUrl,
    apiToken: creds?.apiToken ?? "",
    cacheDir: paths.home,
  });
  console.log(`[license] source: ${result.source}`);
  console.log(`[license] tier:   ${result.license.tier}`);
  console.log(`[license] features:`);
  for (const f of result.license.features) {
    console.log(`  - ${f}`);
  }
  if (result.license.rule_bundle) {
    const grant = result.license.rule_bundle;
    console.log(`[license] rules:  key for ${grant.channel} bundle ${grant.bundle_version} (not shown)`);
  }
  if (result.license.sync_endpoint) {
    console.log(`[license] sync:   ${result.license.sync_endpoint}`);
  }
  console.log(`[license] ttl:    ${result.license.ttl_seconds}s`);

  if (result.source === "defaults") {
    console.log("");
    console.log("  No API token configured. Run `omnodex connect`, set OMNODEX_API_TOKEN, or pass --token.");
    console.log("  Free tier features are active by default.");
  } else if (result.source === "cache_stale") {
    console.log("");
    console.log("  WARNING: using stale cached license (network unreachable).");
  }
}

/** Read a `--flag value` pair from args. */
function readFlagValue(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined;
}

/**
 * Encrypt the local read model and push it to the cloud (Hosted tier+).
 *
 *   omnodex sync [--token <omx_...>] [--passphrase <phrase>]
 *                [--api <url>] [--sessions id1,id2]
 *
 * Token/passphrase/api also read from OMNODEX_API_TOKEN,
 * OMNODEX_SYNC_PASSPHRASE, OMNODEX_API_URL. The passphrase encrypts data
 * client-side and is never sent to the server.
 */
async function cmdSync(args: string[]): Promise<void> {
  const paths = resolvePaths();

  // Resolve credentials: flag > env > stream-config.json
  const creds = await resolveCredentials(paths.home, {
    flagToken: readFlagValue(args, "--token"),
    flagPassphrase: readFlagValue(args, "--secret") ?? readFlagValue(args, "--passphrase"),
    flagApiUrl: readFlagValue(args, "--api"),
  });

  const apiToken = creds?.apiToken ?? "";
  const apiUrl = creds?.apiUrl ?? "https://api.omnodex.com";
  const passphrase = creds?.passphrase ?? "";

  if (!apiToken) {
    console.error("[sync] no API token. Set OMNODEX_API_TOKEN, pass --token <omx_...>,");
    console.error("       or run `omnodex connect` to save credentials to stream-config.json.");
    process.exitCode = 1;
    return;
  }
  if (!passphrase) {
    console.error("[sync] no stream secret. Set OMNODEX_STREAM_SECRET, pass --secret <secret>,");
    console.error("       or run `omnodex connect` to auto-generate one.");
    process.exitCode = 1;
    return;
  }

  // Validate the license + tier before doing any work.
  const license = await validateLicense({ apiBaseUrl: apiUrl, apiToken, cacheDir: paths.home });
  const { customer_id, tier, features } = license.license;
  if (!features.includes("encrypted_sync")) {
    console.error(`[sync] tier "${tier}" does not include encrypted sync. Upgrade to Hosted or above.`);
    process.exitCode = 1;
    return;
  }

  const sessionsFlag = readFlagValue(args, "--sessions");
  const sessionIds = sessionsFlag
    ? sessionsFlag.split(",").map((s) => s.trim()).filter(Boolean)
    : undefined;

  // A background pass may be syncing this home right now; both would open
  // traces.db, and the second would fail with "database is locked".
  const waitEnv = Number(process.env.OMNODEX_SYNC_LOCK_WAIT_MS);
  const release = await acquireSyncLock(paths.home, {
    waitMs: Number.isFinite(waitEnv) && waitEnv >= 0 ? waitEnv : undefined,
    onWait: () => console.log("[sync] a background sync is running on this machine; waiting for it to finish ..."),
  });
  if (!release) {
    console.error("[sync] a background sync is still running. Try again in a few minutes; `omnodex status` shows its last result.");
    process.exitCode = 1;
    return;
  }

  try {
    // The cloud sets a minimum gap between a machine's syncs; it would
    // refuse this one anyway.
    const state = await readAutoSyncState(paths.home);
    if (syncDeferred(state)) {
      console.error(`[sync] ${syncWaitMessage(Date.parse(state.sync_not_before!))}`);
      process.exitCode = 1;
      return;
    }
    console.log(`[sync] encrypting and pushing to ${apiUrl} ...`);
    let result: Awaited<ReturnType<typeof syncReadModel>>;
    try {
      result = await syncReadModel({
        home: paths.home,
        apiUrl,
        apiToken,
        passphrase,
        customerId: customer_id,
        sessionIds,
      });
    } catch (err) {
      // Recorded like a background sync, so `omnodex status` shows it too.
      await recordSyncOutcome(paths.home, err);
      if (err instanceof SyncBlobTooLargeError) {
        console.error(`[sync] ${describeSyncBlob({ blob_too_large_bytes: err.bytes }, paths.home)}`);
        process.exitCode = 1;
        return;
      }
      if (err instanceof SyncTooSoonError) {
        console.error(`[sync] ${syncWaitMessage(Date.now() + err.retryAfterSeconds * 1000)}`);
        process.exitCode = 1;
        return;
      }
      throw err;
    }
    // A partial sync (--sessions) pushes a single blob of those sessions.
    await recordSyncOutcome(paths.home, result);
    if (result.segments) {
      console.log(
        `[sync] done. commit=${result.blobId} machine=${result.machineId} sessions=${result.sessionsIncluded.length} ` +
          `segments=${result.segments.count} uploaded=${result.segments.uploaded}`,
      );
    } else {
      console.log(
        `[sync] done. blob=${result.blobId} machine=${result.machineId} sessions=${result.sessionsIncluded.length} bytes=${result.blobBytes}`,
      );
    }
    const size = describeSyncBlob({
      last_blob_bytes: result.blobBytes,
      last_sync_segments: result.segments?.count ?? null,
      last_sync_total_bytes: result.segments?.totalBytes ?? null,
    }, paths.home);
    if (size) console.log(`[sync] ${size}`);
  } finally {
    await release();
  }
}

/** What `omnodex sync` says when the cloud asks this machine to wait. */
export function syncWaitMessage(until: number, now = Date.now()): string {
  const minutes = Math.max(1, Math.ceil((until - now) / 60_000));
  const at = new Date(until).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return `the cloud asks this machine to wait between syncs; try again in ${minutes} minute(s), after ${at}. ` +
    "Nothing is lost: everything recorded meanwhile goes up with the next sync.";
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const wantsHelp = rest.some((arg) => arg === "--help" || arg === "-h") ||
    (command === "mcp-proxy" && rest[0] === "help");
  if (command && wantsHelp) {
    const help = commandHelp(command, rest);
    if (help) {
      console.log(help);
      return;
    }
  }
  if (command) {
    const error = commandOptionError(command, rest);
    if (error) {
      console.error(`[omnodex] ${error}. Run 'omnodex ${command} --help' for usage.`);
      process.exitCode = 1;
      return;
    }
  }
  setMarkerPush(pushEventsToCloud);

  // Detached sync child spawned by a running MCP proxy. Handled before
  // anything else: it has no command, and the update check below would print
  // to a stdout nobody is reading.
  if (process.env[AUTO_SYNC_CHILD_ENV] === "1") {
    const { home } = resolvePaths();
    await runAutoSync(home, { detect: () => runBackgroundDetection(home) });
    return;
  }

  // Background update check + notification (skip for update command itself)
  if (command !== "update" && command !== undefined && !["help", "--help", "-h"].includes(command)) {
    await scheduleBackgroundCheck();
    await printUpdateNotification();
    // Launchers written by an older version (for example by `omnodex update`,
    // which runs in the old process) are replaced with this version's.
    try {
      const refreshed = await refreshStaleLaunchers();
      if (refreshed.length > 0) {
        console.error(`[omnodex] refreshed hook launchers: ${refreshed.join(", ")}`);
      }
    } catch {
      // Not critical: `omnodex update --refresh-launchers` does the same
    }
  }

  switch (command) {
    case "update":
      await runUpdate({
        check: rest.includes("--check"),
        refreshLaunchers: rest.includes("--refresh-launchers"),
        refreshPlugins: rest.includes("--refresh-plugins"),
      });
      return;
    case "--version":
    case "-V": {
      const method = detectInstallMethod();
      if (method === "source") {
        const info = getSourceInstallInfo();
        if (info) {
          console.log(`${getInstalledVersion()} (source: ${info.branch} @ ${info.sha}${info.dirty ? "+" : ""})`);
        } else {
          console.log(`${getInstalledVersion()} (source)`);
        }
      } else {
        console.log(getInstalledVersion());
      }
      return;
    }
    case "install":
      await cmdInstall(rest);
      return;
    case "uninstall":
      await cmdUninstall(rest);
      return;
    case "status":
      await cmdStatus(rest);
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
      await cmdReplay(rest);
      return;
    case "report":
      await cmdReport();
      return;
    case "dashboard":
      await cmdDashboard(rest);
      return;
    case "mcp-proxy":
      await cmdMcpProxy(rest);
      return;
    case "license":
      await cmdLicense(rest);
      return;
    case "connect":
      await cmdConnect(rest);
      return;
    case "sync":
      if (["pause", "resume", "status"].includes(rest.find((a) => !a.startsWith("--")) ?? "")) {
        process.exitCode = await runCaptureControl("sync", rest, {
          home: resolvePaths().home, io: processIo(), push: pushEventsToCloud,
        });
        return;
      }
      await cmdSync(rest);
      return;
    case "record":
      process.exitCode = await runCaptureControl("record", rest, {
        home: resolvePaths().home, io: processIo(), push: pushEventsToCloud,
      });
      return;
    case "enforce":
      process.exitCode = await runEnforce(rest, {
        home: resolvePaths().home,
        io: processIo(),
        applyHookTiming: (on) => setGuardrailsHooks(resolvePaths().home, on),
        prepareGuardrails: () => prepareGuardrails(resolvePaths().home),
        describeGuardrails: async () => describeGuardrails(await loadGuardrailsModule(resolvePaths().home)),
      });
      return;
    case "live":
      await cmdLive(rest);
      return;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(`omnodex

commands:
  update             check for and install updates.
                     Flags:
                       --check               dry run — show available update
                       --refresh-launchers   just refresh launcher scripts
                       --refresh-plugins     just bring installed agent
                                             plugins to the versions this
                                             release pins (a version chosen
                                             with --plugin-version is kept
                                             until a newer one is pinned)
  install [target] [project]
                     install Omnodex hooks for an AI agent platform.
                     Targets: claude-code, codex, antigravity (or agy)
                     Without a target, finds every supported agent on
                     this machine, shows what it will write, asks once,
                     and installs them all.
                     Defaults to cwd if project is omitted.
                     Asks whether to record every project (recommended)
                     or only this one; an agent that already records every
                     project keeps doing so, and a left-out project is
                     recorded again.
                     Flags:
                       --everywhere          record every project (hooks in
                                             the agent's user-level file)
                       --this-project        hooks in this project only
                                             (the default without a terminal)
                       --yes, -y             install without asking (needed
                                             when not in a terminal); picks
                                             --everywhere unless told otherwise
                       --debug               verbose shim logging
                       --no-connect          skip the dashboard sign-in
                                             (also skipped without a terminal)
                       --legacy-shim         use legacy absolute path (not
                                             recommended — breaks on update)
                       --project-settings    (claude-code only) edit
                                             settings.json instead of
                                             settings.local.json
                     Components (default: hooks and plugin):
                       --hooks               hooks only
                       --plugin              the agent's Omnodex plugin only
                                             (its MCP proxy), downloaded from
                                             downloads.omnodex.com and checked
                                             against the sha256 this release
                                             pins
                       --plugin-version <v>  another published version, or
                                             latest, checked against its
                                             published sha256
                       --from <file>         install a downloaded bundle; it
                                             must match the pin, a published
                                             checksum, or --sha256 <hex>
                       --mcp                 (antigravity) project MCP entry in
                                             .agents/mcp_config.json instead of
                                             the plugin; combine with --hooks
  uninstall [target] [project]
                     remove Omnodex hooks from the project. If the agent
                     records every project, leaves this project out
                     instead (\`omnodex install\` here records it again).
                     If target is omitted, applies to every agent.
                     Asks first; --confirm skips the question. Needs a
                     person at an interactive terminal, so an agent cannot
                     remove its own monitoring.
                     Flags:
                       --unattended          remove without a terminal, for
                                             scripts and fleet tools; the
                                             removal is recorded and raises
                                             a finding
                       --everywhere          stop recording every project
                       --plugin              remove the agent's plugin (it
                                             covers every project, so plain
                                             uninstall leaves it)
  status [project]   show which Omnodex hooks record a project, including
                     every-project hooks and left-out projects.
                     Flags:
                       --all                 show all registered installations
  license            show current license tier and features, using the
                     token \`omnodex connect\` saved (or OMNODEX_API_TOKEN).
                     Subcommands: clear (remove cached license).
                     Flags: --token <omx_...>  --api <url>
  connect            connect this machine to the cloud dashboard. If no
                     API token exists, starts a device code flow (RFC 8628):
                     open a URL in your browser, enter the displayed code,
                     and the CLI receives a token automatically. If a token
                     already exists, generates a one-click connection link.
                     Flags: --token <omx_...>  bypass device code flow and
                                               store the given token directly
                            --secret (stream secret), --api, --platform
  sync               encrypt the local read model and push it to the cloud.
                     Credentials are resolved from flags, environment
                     variables, or stream-config.json (saved by connect
                     or install). Hosted tier or above.
  sync pause [duration] | resume | status
                     pause uploads from this machine: events are still
                     recorded and shown in the local dashboard, but stay
                     on this machine for good. Duration like 30m, 1h, 2d;
                     without one, until resumed. Pausing asks you to
                     confirm at a terminal.
  record pause [duration] | resume | status
                     pause recording on this machine: nothing is captured
                     or uploaded until it resumes. Pausing asks you to
                     confirm at a terminal.
  enforce monitor | shadow | guardrails | status
                     choose whether Omnodex acts on tool calls. monitor
                     (the default) records and flags. shadow also records,
                     on each finding, whether Omnodex would have stopped
                     the call, and never stops one. guardrails (Pro)
                     stops or holds calls your settings say to; leaving it
                     needs a person at a terminal. A first install offers
                     shadow. Rules, per-rule settings and exceptions are
                     read from the enforcement section of
                     ~/.omnodex/omnodex-config.json.
  live [resume]      show whether live pushes to the hosted dashboard are
                     paused (no dashboard was watching), or with resume,
                     push the next event at once.
  mcp-proxy <sub>   manage the MCP proxy interceptor.
                     Run 'omnodex mcp-proxy help' for subcommand details.
  spike [name]       build synthetic sessions through the real pipeline.
                     --seed <integer>  reproducible variation (default 1)
                     --random          pick and print a fresh seed
                     --now <ISO>       fixed clock with timezone
                     --sessions <N>    session count, minimum/default 12
                     --scenario-set movement  include loopback chain fixtures
                     --scenario-set history --machine <a|b>  six weeks of
                       work on one of two machines; run each machine in
                       its own home
                     Names prefix session IDs; repeated runs append new IDs.
  detect [session]   scan event logs for risk patterns and append
                     risk.detected events. Runs on all sessions if no
                     session id is given, across every configured root.
                       --roots <a,b>  scan these roots as well
  replay             rebuild the SQLite read model from every configured
                     root's event log. Roots come from OMNODEX_HOME, the
                     default home and config.json.  Flags:
                       --roots <a,b>  include these roots as well
  report             print a summary of sessions in the read model.
  dashboard [port]   start the local dashboard (default port 7890).
                     Streaming detection is active while the dashboard
                     runs -- risks are detected and pushed to the browser
                     in real time via SSE.  Flags:
                       --no-detect  skip the historical detection pass
  clear              delete event log data; requires a terminal or --unattended.
                     --unattended records the clear and raises a finding.
`);
      return;
    default:
      console.error(`[omnodex] unknown command '${command}'. Run 'omnodex help' for usage.`);
      process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
