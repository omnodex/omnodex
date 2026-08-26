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
 *   omnodex replay           rebuild the SQLite read model by replaying the event log
 *   omnodex report           print a summary of sessions in the read model
 *   omnodex mcp-proxy        manage the MCP proxy interceptor (start/install/status)
 *
 * All data is written under $OMNODEX_HOME, defaulting to ~/.omnodex.
 */

import * as os from "node:os";
import * as readline from "node:readline/promises";
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
import {
  CODEX_HOOK_SHIM_PATH,
  CodexInterceptor,
} from "@omnodex/codex-provider";
import {
  ANTIGRAVITY_HOOK_SHIM_PATH,
  AntigravityInterceptor,
} from "@omnodex/antigravity-provider";
import { MCPProxy, loadProxyConfig } from "@omnodex/mcp-proxy";
import { DashboardServer } from "./dashboard-server.js";
import { startStreamingLoop, type StreamingRoot } from "./streaming.js";
import { resolveRoots, parseRootsFlag } from "./config.js";
import { detectRisks } from "@omnodex/analyzer";
import type { TraceEvent } from "@omnodex/shared";
import { validateLicense, clearCache as clearLicenseCache } from "@omnodex/license-client";
import {
  SyncEncryptor,
  HttpSyncTransport,
  StreamingTransport,
  deriveStreamingKey,
  computeKeyId,
  computeMachineId,
  readMachineLabel,
} from "@omnodex/sync-encryptor";
import {
  generatePassphrase,
  updateStreamConfig,
  resolveCredentials,
} from "./stream-config.js";
import { createClaim, platformFromTarget } from "./connect.js";
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
  // sessionId is guaranteed defined here: we returned above if both sessionId and wipeAll were falsy,
  // and again if wipeAll+confirmed, so reaching this point means sessionId is set.
  const sessionFile = log.sessionFilePath(sessionId!);
  await fs.rm(sessionFile, { force: true });

  // 2. Rewrite the event log index without this session.
  const indexPath = path.join(paths.eventLogRoot, "index.jsonl");
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
  // Parse --roots flag before consuming positional args.
  const { roots: cliRoots, rest: remainingArgs } = parseRootsFlag(args);
  const port = parseInt(remainingArgs.find((a) => !a.startsWith("--")) ?? "7890", 10);
  const skipDetect = remainingArgs.includes("--no-detect");

  // --- Resolve all roots (default home + env + config + CLI) ---
  const resolved = await resolveRoots(cliRoots);
  console.log(`[dashboard] roots: ${resolved.all.join(", ")}`);

  // Create an EventLog per root.
  const logs: Array<{ rootPath: string; log: EventLog }> = [];
  for (const rootPath of resolved.all) {
    const log = new EventLog({ root: path.join(rootPath, "event-log") });
    await log.init();
    logs.push({ rootPath, log });
  }

  // --- Historical processing (batch) ---
  // Run batch detection on any sessions that completed before the dashboard
  // was opened. The streaming loop will handle everything from this point on.
  if (!skipDetect) {
    let detected = 0;
    for (const { log } of logs) {
      const sessionIds = await log.listSessions();
      for (const sessionId of sessionIds) {
        const events = await log.readSession(sessionId);
        if (events.length === 0) continue;
        const result = detectRisks(events, newEventId);
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
  const primaryPaths = {
    home: resolved.primary,
    eventLogRoot: path.join(resolved.primary, "event-log"),
    dbPath: path.join(resolved.primary, "traces.db"),
  };
  const store = await openStore(primaryPaths);
  const projector = new Projector(store);

  // Replay all roots into the same read model. Tag each root so the
  // projector stamps source_root on session rows.
  await store.reset();
  for (const { rootPath, log } of logs) {
    projector.setSourceRoot(rootPath);
    for await (const event of iterateLog(log)) {
      await projector.apply(event);
    }
  }

  // --- Start server ---
  const assetsDir = new URL(".", import.meta.url).pathname;
  const server = new DashboardServer({ store, port, assetsDir });

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
        });
        console.log(`[dashboard] cloud streaming enabled (key_id=${keyId})`);
      } catch (err) {
        console.warn("[dashboard] cloud streaming setup failed:", err);
      }
    } else {
      console.log("[dashboard] cloud streaming not available on current tier");
    }
  } else {
    console.log("[dashboard] cloud streaming disabled (no API token/passphrase)");
  }

  console.log(`[dashboard] open http://localhost:${port} in your browser`);
  console.log(`[dashboard] streaming detection active -- press Ctrl+C to stop`);

  // --- Start streaming detect loop ---
  // Tails each root's session files, projects new events incrementally, runs
  // the rule engine on tool.invoked events, and pushes updates to SSE clients.
  const streamingRoots: StreamingRoot[] = logs.map(({ rootPath, log }) => ({
    rootPath,
    log,
  }));
  const { stop } = startStreamingLoop(streamingRoots, store, projector, server, cloudTransport);

  // --- Shutdown handling ---
  await new Promise<void>((resolve) => {
    const shutdown = (): void => {
      stop();
      // Flush any buffered cloud events before shutting down.
      const transportFlush = cloudTransport?.stop().catch(() => {}) ?? Promise.resolve();
      transportFlush.finally(() => {
        // Close all event logs.
        for (const { log } of logs) {
          log.close().catch(() => {});
        }
        server.close();
        resolve();
      });
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });
}

// ---------------------------------------------------------------------------
// Stream connection
// ---------------------------------------------------------------------------

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

/**
 * Generate a connection link for the current machine.
 *
 *   omnodex connect [--token <omx_...>] [--passphrase <phrase>]
 *                   [--api <url>] [--platform <name>]
 *
 * If no passphrase exists yet, one is auto-generated and saved to
 * stream-config.json. The passphrase is encrypted under a one-time
 * transfer key before being sent to the server.
 */
async function cmdConnect(args: string[]): Promise<void> {
  const paths = resolvePaths();

  const flagToken = readFlagValue(args, "--token");
  const flagPassphrase = readFlagValue(args, "--passphrase");
  const flagApiUrl = readFlagValue(args, "--api");
  const flagPlatform = readFlagValue(args, "--platform");

  // Resolve or generate credentials
  let creds = await resolveCredentials(paths.home, {
    flagToken,
    flagPassphrase,
    flagApiUrl,
  });

  if (!creds?.apiToken) {
    console.error("[connect] no API token. Set OMNODEX_API_TOKEN or pass --token <omx_...>.");
    process.exitCode = 1;
    return;
  }

  // Auto-generate passphrase if missing
  if (!creds.passphrase) {
    const newPassphrase = generatePassphrase();
    await updateStreamConfig(paths.home, {
      api_token: creds.apiToken,
      passphrase: newPassphrase,
      api_url: creds.apiUrl,
      created_at: new Date().toISOString(),
    });
    console.log("[connect] generated new sync passphrase (saved to stream-config.json)");
    creds = (await resolveCredentials(paths.home, {
      flagToken,
      flagPassphrase,
      flagApiUrl,
    }))!;
  }

  await offerConnectionLink(paths.home, {
    apiToken: creds.apiToken,
    passphrase: creds.passphrase,
    apiUrl: creds.apiUrl,
    platform: flagPlatform,
  });
}

const VALID_TARGETS = ["claude-code", "codex", "antigravity"] as const;
type InstallTarget = typeof VALID_TARGETS[number];

function resolveTarget(args: string[]): { target: InstallTarget; rest: string[] } | null {
  const targetArg = args.find((a) => !a.startsWith("--"));
  if (!targetArg || !VALID_TARGETS.includes(targetArg as InstallTarget)) {
    const validList = VALID_TARGETS.join(", ");
    console.error(
      targetArg
        ? `[omnodex] unknown target '${targetArg}'. Valid targets: ${validList}`
        : `[omnodex] target required. Valid targets: ${validList}`,
    );
    console.error(`\n  omnodex install <target> [project]`);
    console.error(`  omnodex uninstall [target] [project]\n`);
    process.exitCode = 1;
    return null;
  }
  return {
    target: targetArg as InstallTarget,
    rest: args.filter((a) => a !== targetArg),
  };
}

async function cmdInstall(args: string[]): Promise<void> {
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

async function installClaudeCode(args: string[]): Promise<void> {
  const projectPath = path.resolve(args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const useProjectSettings = args.includes("--project-settings");

  const targetFile = useProjectSettings ? "settings.json" : "settings.local.json";
  const alternateFile = useProjectSettings ? "settings.local.json" : "settings.json";

  // Warn if Omnodex hooks already exist in the alternate settings file.
  // Claude Code merges settings.json and settings.local.json; duplicate hooks
  // cause every event to be processed twice and produce double risk findings.
  const nodePath = process.execPath;
  const alternateInterceptor = new ClaudeCodeInterceptor({
    projectPath,
    shimPath: CLAUDE_HOOK_SHIM_PATH,
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
    shimPath: CLAUDE_HOOK_SHIM_PATH,
    omnodexHome: paths.home,
    settingsFile: targetFile,
    debug,
    nodePath,
  });
  await interceptor.install();
  console.log(`[install] installed Claude Code hooks into`);
  console.log(`          ${interceptor.settingsFilePath()}`);
  console.log(`[install] shim:         ${CLAUDE_HOOK_SHIM_PATH}`);
  console.log(`[install] node:         ${nodePath}`);
  console.log(`[install] OMNODEX_HOME: ${paths.home}`);
  console.log(`[install] note: re-run \`omnodex install claude-code\` after changing Node versions (e.g. nvm use)`);
  console.log(
    `[install] run \`omnodex uninstall claude-code ${projectPath}\` to remove`,
  );

  // Offer a connection link if credentials are available
  const ccCreds = await resolveCredentials(paths.home);
  if (ccCreds?.apiToken) {
    if (!ccCreds.passphrase) {
      const newPassphrase = generatePassphrase();
      await updateStreamConfig(paths.home, {
        api_token: ccCreds.apiToken,
        passphrase: newPassphrase,
        api_url: ccCreds.apiUrl,
        created_at: new Date().toISOString(),
      });
      ccCreds.passphrase = newPassphrase;
      console.log("[install] generated new sync passphrase (saved to stream-config.json)");
    }
    await offerConnectionLink(paths.home, {
      apiToken: ccCreds.apiToken,
      passphrase: ccCreds.passphrase,
      apiUrl: ccCreds.apiUrl,
      platform: platformFromTarget("claude-code"),
      projectLabel: path.basename(projectPath),
    });
  }
}

async function installCodex(args: string[]): Promise<void> {
  const projectPath = path.resolve(args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const paths = resolvePaths();
  const debug = args.includes("--debug");

  const nodePath = process.execPath;
  const interceptor = new CodexInterceptor({
    projectPath,
    shimPath: CODEX_HOOK_SHIM_PATH,
    omnodexHome: paths.home,
    debug,
    nodePath,
  });
  await interceptor.install();
  console.log(`[install] installed Codex hooks into`);
  console.log(`          ${interceptor.hooksFilePath()}`);
  console.log(`[install] shim:         ${CODEX_HOOK_SHIM_PATH}`);
  console.log(`[install] node:         ${nodePath}`);
  console.log(`[install] OMNODEX_HOME: ${paths.home}`);
  console.log(`[install] note: ensure hooks = true in ~/.codex/config.toml`);
  console.log(`[install] note: re-run \`omnodex install codex\` after changing Node versions (e.g. nvm use)`);
  console.log(
    `[install] run \`omnodex uninstall codex ${projectPath}\` to remove`,
  );

  // Offer a connection link if credentials are available
  const codexCreds = await resolveCredentials(paths.home);
  if (codexCreds?.apiToken) {
    if (!codexCreds.passphrase) {
      const newPassphrase = generatePassphrase();
      await updateStreamConfig(paths.home, {
        api_token: codexCreds.apiToken,
        passphrase: newPassphrase,
        api_url: codexCreds.apiUrl,
        created_at: new Date().toISOString(),
      });
      codexCreds.passphrase = newPassphrase;
      console.log("[install] generated new sync passphrase (saved to stream-config.json)");
    }
    await offerConnectionLink(paths.home, {
      apiToken: codexCreds.apiToken,
      passphrase: codexCreds.passphrase,
      apiUrl: codexCreds.apiUrl,
      platform: platformFromTarget("codex"),
      projectLabel: path.basename(projectPath),
    });
  }
}

async function installAntigravity(args: string[]): Promise<void> {
  const projectPath = path.resolve(args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const paths = resolvePaths();
  const debug = args.includes("--debug");
  const wantHooks = args.includes("--hooks");
  const wantMcp = args.includes("--mcp");

  // Default: hooks only (backward compat). If either flag is explicit, do only what was asked.
  const doHooks = wantHooks || !wantMcp;
  const doMcp = wantMcp;

  const nodePath = process.execPath;

  if (doHooks) {
    const interceptor = new AntigravityInterceptor({
      projectPath,
      shimPath: ANTIGRAVITY_HOOK_SHIM_PATH,
      omnodexHome: paths.home,
      debug,
      nodePath,
    });
    await interceptor.install();
    console.log(`[install] installed Antigravity hooks into`);
    console.log(`          ${interceptor.hooksFilePath()}`);
    console.log(`[install] shim:         ${ANTIGRAVITY_HOOK_SHIM_PATH}`);
    console.log(`[install] node:         ${nodePath}`);
    console.log(`[install] OMNODEX_HOME: ${paths.home}`);
    console.log(`[install] note: re-run \`omnodex install antigravity\` after changing Node versions (e.g. nvm use)`);
    console.log(`[install] hooks apply to all Antigravity surfaces (CLI, Desktop, IDE)`);
  }

  if (doMcp) {
    await installAntigravityMcp(projectPath, paths.home, nodePath);
  }

  console.log(
    `[install] run \`omnodex uninstall antigravity ${projectPath}\` to remove`,
  );

  // Offer a connection link if credentials are available
  const agCreds = await resolveCredentials(paths.home);
  if (agCreds?.apiToken) {
    if (!agCreds.passphrase) {
      const newPassphrase = generatePassphrase();
      await updateStreamConfig(paths.home, {
        api_token: agCreds.apiToken,
        passphrase: newPassphrase,
        api_url: agCreds.apiUrl,
        created_at: new Date().toISOString(),
      });
      agCreds.passphrase = newPassphrase;
      console.log("[install] generated new sync passphrase (saved to stream-config.json)");
    }
    await offerConnectionLink(paths.home, {
      apiToken: agCreds.apiToken,
      passphrase: agCreds.passphrase,
      apiUrl: agCreds.apiUrl,
      platform: platformFromTarget("antigravity"),
      projectLabel: path.basename(projectPath),
    });
  }
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
): Promise<void> {
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
    return;
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
    args: [launchProxyPath],
    env: {
      OMNODEX_HOME: omnodexHome,
    },
  };

  const next = { ...existing, mcpServers };
  await fs.writeFile(mcpConfigPath, JSON.stringify(next, null, 2) + "\n", "utf8");

  console.log(`[install] wrote MCP proxy config to`);
  console.log(`          ${mcpConfigPath}`);
  console.log(`[install] proxy launcher: ${launchProxyPath}`);
}

async function cmdUninstall(args: string[]): Promise<void> {
  const projectPath = path.resolve(
    args.find((a) => !a.startsWith("--") && !VALID_TARGETS.includes(a as InstallTarget)) ?? process.cwd(),
  );
  const paths = resolvePaths();
  const confirmed = args.includes("--confirm");

  // Determine which targets to uninstall
  const targetArg = args.find((a) => VALID_TARGETS.includes(a as InstallTarget)) as InstallTarget | undefined;

  interface InstalledHook {
    target: InstallTarget;
    label: string;
    path: string;
    uninstall: () => Promise<void>;
  }

  const installed: InstalledHook[] = [];

  // Check Claude Code
  for (const settingsFile of ["settings.local.json", "settings.json"] as const) {
    const interceptor = new ClaudeCodeInterceptor({
      projectPath,
      shimPath: CLAUDE_HOOK_SHIM_PATH,
      omnodexHome: paths.home,
      settingsFile,
    });
    if (await interceptor.isInstalled()) {
      installed.push({
        target: "claude-code",
        label: `Claude Code (${settingsFile})`,
        path: interceptor.settingsFilePath(),
        uninstall: () => interceptor.uninstall(),
      });
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
    await fs.access(codexHooksPath);
    const content = await fs.readFile(codexHooksPath, "utf8");
    if (content.includes("omnodex")) {
      installed.push({
        target: "codex",
        label: "Codex",
        path: codexHooksPath,
        uninstall: () => codexInterceptor.uninstall(),
      });
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
    const content = await fs.readFile(agHooksPath, "utf8");
    if (content.includes("omnodex")) {
      installed.push({
        target: "antigravity",
        label: "Antigravity",
        path: agHooksPath,
        uninstall: () => antigravityInterceptor.uninstall(),
      });
    }
  } catch { /* not installed */ }

  // Filter to target if specified
  const toRemove = targetArg
    ? installed.filter((h) => h.target === targetArg)
    : installed;

  if (toRemove.length === 0) {
    if (targetArg) {
      console.log(`[uninstall] no ${targetArg} hooks found in ${projectPath}`);
    } else {
      console.log(`[uninstall] no Omnodex hooks found in ${projectPath}`);
    }
    return;
  }

  // Show what will be removed and require confirmation
  console.log(`[uninstall] the following Omnodex hooks will be removed:\n`);
  for (const hook of toRemove) {
    console.log(`  ${hook.label}`);
    console.log(`    ${hook.path}\n`);
  }

  if (!confirmed) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await rl.question("Proceed? (Y/n) ");
    rl.close();
    if (answer.trim() !== "Y") {
      console.log("[uninstall] cancelled");
      return;
    }
  }

  for (const hook of toRemove) {
    await hook.uninstall();
    console.log(`[uninstall] removed ${hook.label} hooks from ${hook.path}`);
  }
}

async function cmdStatus(_args: string[]): Promise<void> {
  const projectPath = path.resolve(_args.find((a) => !a.startsWith("--")) ?? process.cwd());
  const paths = resolvePaths();

  console.log(`[status] project:      ${projectPath}`);
  console.log(`[status] OMNODEX_HOME: ${paths.home}\n`);

  let anyInstalled = false;

  // Check Claude Code
  for (const settingsFile of ["settings.local.json", "settings.json"] as const) {
    const interceptor = new ClaudeCodeInterceptor({
      projectPath,
      shimPath: CLAUDE_HOOK_SHIM_PATH,
      omnodexHome: paths.home,
      settingsFile,
    });
    if (await interceptor.isInstalled()) {
      console.log(`  Claude Code (${settingsFile}): installed`);
      console.log(`    ${interceptor.settingsFilePath()}`);
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
    await fs.access(codexHooksPath);
    const content = await fs.readFile(codexHooksPath, "utf8");
    if (content.includes("omnodex")) {
      console.log(`  Codex: installed`);
      console.log(`    ${codexHooksPath}`);
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
    const content = await fs.readFile(agHooksPath, "utf8");
    if (content.includes("omnodex")) {
      console.log(`  Antigravity: installed`);
      console.log(`    ${agHooksPath}`);
      anyInstalled = true;
    }
  } catch { /* not installed */ }

  if (!anyInstalled) {
    console.log(`  No Omnodex hooks installed in this project.`);
    console.log(`\n  Run \`omnodex install <target>\` to get started.`);
    console.log(`  Targets: ${VALID_TARGETS.join(", ")}`);
  }
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

  const config = await loadProxyConfig(configPath);
  const paths = resolvePaths();

  const log = new EventLog({ root: path.join(paths.home, "event-log") });
  await log.init();

  const proxy = new MCPProxy(config, { projectPath: process.cwd() });
  const emit = log.append.bind(log);
  const stop = await proxy.start(emit);

  async function shutdown(): Promise<void> {
    await stop();
    await log.close();
  }
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
      console.log(`              ${prefix}  [http]   ${srv.url}`);
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

  if (sub === "clear") {
    await clearLicenseCache();
    console.log("[license] cache cleared");
    return;
  }

  console.log("[license] validating...");
  const result = await validateLicense();
  console.log(`[license] source: ${result.source}`);
  console.log(`[license] tier:   ${result.license.tier}`);
  console.log(`[license] features:`);
  for (const f of result.license.features) {
    console.log(`  - ${f}`);
  }
  if (result.license.rule_decryption_key) {
    console.log(`[license] rule key: present (not shown)`);
  }
  if (result.license.sync_endpoint) {
    console.log(`[license] sync:   ${result.license.sync_endpoint}`);
  }
  console.log(`[license] ttl:    ${result.license.ttl_seconds}s`);

  if (result.source === "defaults") {
    console.log("");
    console.log("  No API token configured. Set OMNODEX_API_TOKEN or pass --token.");
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
    flagPassphrase: readFlagValue(args, "--passphrase"),
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
    console.error("[sync] no passphrase. Set OMNODEX_SYNC_PASSPHRASE, pass --passphrase <phrase>,");
    console.error("       or run `omnodex connect` to auto-generate one.");
    process.exitCode = 1;
    return;
  }

  // Validate the license + tier before doing any work.
  const license = await validateLicense({ apiBaseUrl: apiUrl, apiToken });
  const { customer_id, tier, features } = license.license;
  if (!features.includes("encrypted_sync")) {
    console.error(`[sync] tier "${tier}" does not include encrypted sync. Upgrade to Hosted or above.`);
    process.exitCode = 1;
    return;
  }

  const log = new EventLog({ root: paths.eventLogRoot });
  await log.init();
  const store = await openStore(paths);
  // Rebuild the read model so we sync current data (replay is idempotent).
  await new Projector(store).replay(iterateLog(log));

  // Reuse a persisted KDF salt across syncs (it is also embedded in each blob).
  const saltPath = path.join(paths.home, "sync-salt.bin");
  let kdfSalt: Uint8Array | undefined;
  try {
    kdfSalt = new Uint8Array(await fs.readFile(saltPath));
  } catch {
    // first sync: SyncEncryptor generates a fresh salt
  }

  const sessionsFlag = readFlagValue(args, "--sessions");
  const sessionIds = sessionsFlag
    ? sessionsFlag.split(",").map((s) => s.trim()).filter(Boolean)
    : undefined;

  const machineId = computeMachineId();
  const machineLabel = await readMachineLabel(paths.home);

  const transport = new HttpSyncTransport({ baseUrl: apiUrl, apiToken });
  const encryptor = new SyncEncryptor({
    passphrase,
    customerId: customer_id,
    transport,
    store,
    eventLog: log,
    kdfSalt,
    machineId,
    machineLabel,
  });

  console.log(`[sync] encrypting and pushing to ${apiUrl} ...`);
  const result = await encryptor.sync(sessionIds);
  await fs.writeFile(saltPath, result.kdfSalt);
  console.log(
    `[sync] done. blob=${result.blobId} machine=${result.machineId} sessions=${result.sessionsIncluded.length} bytes=${result.payloadBytes}`,
  );
  await store.close();
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  switch (command) {
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
      await cmdReplay();
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
      await cmdSync(rest);
      return;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(`omnodex

commands:
  install <target> [project]
                     install Omnodex hooks for an AI agent platform.
                     Targets: claude-code, codex, antigravity
                     Defaults to cwd if project is omitted.
                     Flags:
                       --debug               verbose shim logging
                       --project-settings    (claude-code only) edit
                                             settings.json instead of
                                             settings.local.json
                       --hooks               (antigravity) hooks only
                       --mcp                 (antigravity) MCP proxy only
                                             (writes .agents/mcp_config.json)
                                             Combine: --hooks --mcp for both.
                                             Default (no flags): hooks only.
  uninstall [target] [project]
                     remove Omnodex hooks. If target is omitted, removes
                     all hooks found in the project. Requires --confirm.
  status [project]   show which Omnodex hooks are installed in a project.
  license            show current license tier and features.
                     Subcommands: clear (remove cached license).
  connect            generate a one-click connection link to pair this
                     machine with the cloud dashboard. Auto-generates a
                     sync passphrase if one does not exist.
                     Flags: --token, --passphrase, --api, --platform
  sync               encrypt the local read model and push it to the cloud.
                     Credentials are resolved from flags, environment
                     variables, or stream-config.json (saved by connect
                     or install). Hosted tier or above.
  mcp-proxy <sub>   manage the MCP proxy interceptor.
                     Run 'omnodex mcp-proxy help' for subcommand details.
  spike [name]       run a simulated session through the full pipeline.
                     Optional name sets the session ID (sess_<name>); if
                     omitted a unique timestamp-based ID is generated so
                     successive runs each create a distinct session.
  detect [session]   scan event log for risk patterns and append
                     risk.detected events. Runs on all sessions if no
                     session id is given.
  replay             rebuild the SQLite read model from the event log.
  report             print a summary of sessions in the read model.
  dashboard [port]   start the local dashboard (default port 7890).
                     Streaming detection is active while the dashboard
                     runs -- risks are detected and pushed to the browser
                     in real time via SSE.  Flags:
                       --no-detect  skip the historical detection pass
  clear              delete all event log data and the read model.
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
