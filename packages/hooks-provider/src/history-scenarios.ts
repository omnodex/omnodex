// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { createHash } from "node:crypto";
import {
  CAPTURE_CONTROL_SESSION_ID, SCHEMA_VERSION,
  type InterceptorKind, type MonitoringChangedEvent, type PlatformKind, type TraceEvent,
} from "@omnodex/shared";
import { DEFAULT_SCENARIO_NOW, DEFAULT_SCENARIO_SEED } from "./scenario-builder.js";

/**
 * Six weeks of ordinary work on two machines, for anything that compares a
 * session with the ones before it. Each machine's events go into its own
 * home, so the two arrive as separate machines. Nothing is executed or
 * fetched; hosts are reserved example names, except one known-bad host that
 * a community rule flags.
 *
 * HISTORY_EXPECTATIONS lists, per dataset, the items that must and must
 * not read as new, compared within the project (its git remote) and, for
 * tools, the platform. Item sets are fixed; the seed varies timing and the
 * files ordinary sessions read, never which hosts, servers or tools appear.
 */

export const HISTORY_MACHINES = ["a", "b"] as const;
export type HistoryMachine = (typeof HISTORY_MACHINES)[number];
/** Day 0 is this many days before `now`; the last day is the day before it. */
export const HISTORY_DAYS = 42;

export interface HistoryOptions {
  machine: HistoryMachine;
  seed?: number;
  now?: string;
  name?: string;
  /** Existing session IDs reserve namespaces when appending a repeated run. */
  existingSessionIds?: readonly string[];
}

export type HistoryItemKind = "destination" | "server" | "tool";

export interface HistoryExpectation {
  dataset: string;
  machine: HistoryMachine;
  kind: HistoryItemKind;
  key: string;
  /** The project: its normalized git remote. */
  project: string;
  /** For tools, which compare per platform. */
  platform?: PlatformKind;
  /** The day of the session the expectation is about. */
  day: number;
  /**
   * new: first time in the project (for tools, on the platform).
   * not-new: used in the project before, on this or another machine.
   * new-coverage: first seen right after this machine started seeing more.
   * held: new, and a HIGH or CRITICAL finding is raised on it.
   */
  expect: "new" | "not-new" | "new-coverage" | "held";
}

interface Call {
  tool: string;
  server?: string;
  parameters: Record<string, unknown>;
}

const bash = (command: string): Call => ({ tool: "Bash", parameters: { command } });
const curl = (url: string): Call => bash(`curl -s ${url}`);
const mcp = (server: string, tool: string, parameters: Record<string, unknown> = {}): Call => ({ tool: `mcp__${server}__${tool}`, server, parameters });

interface Track {
  dataset: string;
  machine: HistoryMachine;
  remote: string;
  folder: string;
  platform: PlatformKind;
  /** Days with a session. */
  days: readonly number[];
  routine: readonly Call[];
  /** Extra calls on given days. */
  planted?: Readonly<Record<number, readonly Call[]>>;
}

const every = (from: number, to: number, step = 1) => Array.from({ length: Math.floor((to - from) / step) + 1 }, (_, i) => from + i * step);

const SHOP = "github.com/case/shop";
const TOOLS = "github.com/case/tools";
const DOCS = "github.com/case/docs";

const TRACKS: readonly Track[] = [
  // A steady project, then a new host, server and tool on day 39, and a
  // known-bad host on day 40.
  {
    dataset: "stable-project", machine: "a", remote: SHOP, folder: "/home/case/shop", platform: "claude-code", days: every(0, 41),
    routine: [curl("https://api.example.com/v1/status"), curl("https://cdn.example.com/assets/app.js"), mcp("tracker", "list_issues", { state: "open" }), bash("npm test")],
    planted: {
      39: [curl("https://new-host.example.net/v2/items"), mcp("notes", "create_page", { title: "Release notes" }), { tool: "WebSearch", parameters: { query: "release checklist" } }],
      40: [curl("https://webhook.site/0c2f1d7e")],
    },
  },
  // The same repo on a second machine under another folder name: what the
  // first machine already used is not new here.
  {
    dataset: "shared-remote", machine: "b", remote: SHOP, folder: "C:\\src\\case-shop", platform: "claude-code", days: every(14, 41, 2),
    routine: [curl("https://api.example.com/v1/status"), mcp("tracker", "list_issues", { state: "open" }), bash("npm test")],
    planted: { 20: [curl("https://status.example.org/health")] },
  },
  // Two repos that share a folder name: one repo's history says nothing
  // about the other.
  {
    dataset: "same-folder-name", machine: "a", remote: "github.com/case/api", folder: "/home/case/api", platform: "claude-code", days: every(0, 41),
    routine: [curl("https://db.example.com/ping"), bash("npm run migrate")],
  },
  {
    dataset: "same-folder-name", machine: "b", remote: "github.com/other/api", folder: "/home/case/api", platform: "claude-code", days: every(21, 41),
    routine: [bash("npm run build")],
    planted: { 30: [curl("https://db.example.com/ping")] },
  },
  // Claude Code throughout; Codex hooks installed on day 25, after which
  // Codex sessions arrive with tools and a host never seen before.
  {
    dataset: "hook-gained", machine: "b", remote: TOOLS, folder: "/home/case/tools", platform: "claude-code", days: every(0, 41),
    routine: [curl("https://api.example.com/v1/status"), bash("make lint")],
  },
  {
    dataset: "hook-gained", machine: "b", remote: TOOLS, folder: "/home/case/tools", platform: "codex", days: every(26, 41),
    routine: [{ tool: "shell", parameters: { command: ["bash", "-lc", "curl -s https://pkg.example.dev/index.json"] } }, { tool: "apply_patch", parameters: { input: "*** Begin Patch\n*** End Patch" } }],
  },
  // A CLI update on day 33. A host first seen the next day is new coverage;
  // one first seen on day 37 is new.
  {
    dataset: "cli-update", machine: "a", remote: DOCS, folder: "/home/case/docs", platform: "claude-code", days: every(0, 41),
    routine: [curl("https://cdn.example.com/fonts.css"), bash("npm run build")],
    planted: { 34: [curl("https://assets.example.org/logo.svg")], 37: [curl("https://late.example.org/feed.xml")] },
  },
];

/** Monitoring changes, by machine: day and what changed. */
const MARKERS: Readonly<Record<HistoryMachine, readonly { day: number; change: Pick<MonitoringChangedEvent, "action" | "target" | "component" | "scope" | "from" | "to" | "cli_version"> }[]>> = {
  a: [
    { day: 0, change: { action: "install", target: "claude-code", component: "hooks", scope: "user", cli_version: "0.8.0" } },
    { day: 33, change: { action: "update", from: "0.8.0", to: "0.9.0", cli_version: "0.9.0" } },
  ],
  b: [
    { day: 0, change: { action: "install", target: "claude-code", component: "hooks", scope: "user", cli_version: "0.9.0" } },
    { day: 25, change: { action: "install", target: "codex", component: "hooks", scope: "user", cli_version: "0.9.0" } },
  ],
};

export const HISTORY_EXPECTATIONS: readonly HistoryExpectation[] = [
  { dataset: "stable-project", machine: "a", project: SHOP, day: 39, kind: "destination", key: "new-host.example.net", expect: "new" },
  { dataset: "stable-project", machine: "a", project: SHOP, day: 39, kind: "server", key: "notes", expect: "new" },
  { dataset: "stable-project", machine: "a", project: SHOP, day: 39, kind: "tool", key: "WebSearch", platform: "claude-code", expect: "new" },
  { dataset: "stable-project", machine: "a", project: SHOP, day: 39, kind: "destination", key: "api.example.com", expect: "not-new" },
  { dataset: "stable-project", machine: "a", project: SHOP, day: 39, kind: "server", key: "tracker", expect: "not-new" },
  { dataset: "stable-project", machine: "a", project: SHOP, day: 39, kind: "tool", key: "Bash", platform: "claude-code", expect: "not-new" },
  { dataset: "stable-project", machine: "a", project: SHOP, day: 40, kind: "destination", key: "webhook.site", expect: "held" },
  { dataset: "shared-remote", machine: "b", project: SHOP, day: 14, kind: "destination", key: "api.example.com", expect: "not-new" },
  { dataset: "shared-remote", machine: "b", project: SHOP, day: 14, kind: "server", key: "tracker", expect: "not-new" },
  { dataset: "shared-remote", machine: "b", project: SHOP, day: 20, kind: "destination", key: "status.example.org", expect: "new" },
  { dataset: "same-folder-name", machine: "b", project: "github.com/other/api", day: 30, kind: "destination", key: "db.example.com", expect: "new" },
  { dataset: "hook-gained", machine: "b", project: TOOLS, day: 26, kind: "destination", key: "pkg.example.dev", expect: "new-coverage" },
  { dataset: "hook-gained", machine: "b", project: TOOLS, day: 26, kind: "tool", key: "apply_patch", platform: "codex", expect: "new-coverage" },
  { dataset: "hook-gained", machine: "b", project: TOOLS, day: 26, kind: "destination", key: "api.example.com", expect: "not-new" },
  { dataset: "cli-update", machine: "a", project: DOCS, day: 34, kind: "destination", key: "assets.example.org", expect: "new-coverage" },
  { dataset: "cli-update", machine: "a", project: DOCS, day: 37, kind: "destination", key: "late.example.org", expect: "new" },
];

const INTERCEPTOR: Partial<Record<PlatformKind, InterceptorKind>> = { "claude-code": "claude-code-hook", codex: "codex-hook" };

/** One machine's six weeks of raw events, sessions and monitoring markers. */
export function buildHistoryScenarios(options: HistoryOptions): TraceEvent[] {
  const seed = options.seed ?? DEFAULT_SCENARIO_SEED;
  const now = options.now ?? DEFAULT_SCENARIO_NOW;
  if (!HISTORY_MACHINES.includes(options.machine)) throw new Error(`machine must be one of ${HISTORY_MACHINES.join(", ")}`);
  if (!Number.isSafeInteger(seed)) throw new Error("seed must be a safe integer");
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(now) || !Number.isFinite(Date.parse(now))) throw new Error("now must be an ISO timestamp with a timezone");
  if (options.name !== undefined && !/^[a-zA-Z0-9_-]{1,64}$/.test(options.name)) throw new Error("name must contain 1-64 letters, digits, underscores or hyphens");

  const identity = createHash("sha256").update(JSON.stringify([seed, new Date(now).toISOString(), options.name ?? "history", options.machine])).digest("hex").slice(0, 24);
  const prefix = `sess_${options.name ?? "history"}_${options.machine}_${identity}`;
  const existing = new Set(options.existingSessionIds ?? []);
  let run = 0;
  while ([...existing].some((id) => id.startsWith(`${prefix}_${run}_`))) run++;
  let state = seed >>> 0;
  const random = () => { state = (state + 0x6d2b79f5) >>> 0; let n = state; n = Math.imul(n ^ (n >>> 15), n | 1); n ^= n + Math.imul(n ^ (n >>> 7), n | 61); return ((n ^ (n >>> 14)) >>> 0) / 4294967296; };

  const DAY = 86_400_000;
  const dayStart = (day: number) => Date.parse(now) - (HISTORY_DAYS - day) * DAY;
  const events: TraceEvent[] = [];

  MARKERS[options.machine].forEach(({ day, change }, i) => {
    const at = new Date(dayStart(day) + 8 * 3_600_000).toISOString();
    events.push({
      schema_version: SCHEMA_VERSION, event_id: `${prefix}_${run}_marker_${i}`, session_id: CAPTURE_CONTROL_SESSION_ID,
      occurred_at: at, recorded_at: at, interceptor: "analyzer", event_type: "monitoring.changed",
      ...change, actor: "terminal", machine_label: `case-machine-${options.machine}`,
    });
  });

  const tracks = TRACKS.filter((t) => t.machine === options.machine);
  tracks.forEach((track, t) => {
    const interceptor = INTERCEPTOR[track.platform]!;
    for (const day of track.days) {
      const sessionId = `${prefix}_${run}_${t}_${day}`;
      // Each track works at its own hour, varied by a few minutes.
      let tick = dayStart(day) + (9 + t) * 3_600_000 + Math.floor(random() * 30) * 60_000;
      let seq = 0;
      const base = () => {
        const at = new Date(tick += 1000 + Math.floor(random() * 1000)).toISOString();
        return { schema_version: SCHEMA_VERSION, event_id: `${sessionId}_event_${seq++}`, session_id: sessionId, occurred_at: at, recorded_at: at, interceptor, platform: track.platform };
      };
      const sep = track.folder.includes("\\") ? "\\" : "/";
      const reads: Call[] = Array.from({ length: 1 + Math.floor(random() * 3) }, () =>
        ({ tool: "Read", parameters: { file_path: `${track.folder}${sep}src${sep}module-${Math.floor(random() * 100)}.ts` } }));
      const calls = [...track.routine, ...(track.planted?.[day] ?? []), ...reads];
      const start = tick;
      events.push({
        ...base(), event_type: "session.started", user: `case@case-machine-${options.machine}`, project_path: track.folder,
        project_remote: track.remote, mcp_servers: [...new Set(calls.map((c) => c.server ?? "builtin"))],
      });
      events.push({ ...base(), event_type: "prompt.submitted", prompt: `Continue the ${track.dataset} work` });
      calls.forEach((call, c) => {
        const id = `${sessionId}_call_${c}`;
        events.push({ ...base(), event_type: "tool.invoked", tool_call_id: id, tool_name: call.tool, mcp_server: call.server ?? "builtin", parameters: structuredClone(call.parameters), cwd: track.folder });
        const invokedAt = tick;
        events.push({ ...base(), event_type: "tool.completed", tool_call_id: id, duration_ms: tick - invokedAt, status: "success", response_bytes: 128 });
        if (call.tool === "Read") events.push({ ...base(), event_type: "file.read", path: String(call.parameters.file_path), bytes: 128 });
      });
      events.push({ ...base(), event_type: "session.ended", duration_ms: tick - start, status: "completed" });
    }
  });
  return events;
}

