// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * State that outlives a session: what this machine has already seen.
 *
 * Machine-scope first-seen rules ask "has this machine ever used this MCP
 * server?". Every MCP proxy launch is a new session, so the session-scope
 * answer re-fired on every restart. This keeps the answer in
 * $OMNODEX_HOME/known-mcp-servers.json:
 *
 *   { "version": 1, "servers": { "<name>": { "first_seen": "...",
 *       "transport": "http", "host": "api.example.com" } } }
 *
 * A server is new the first time its name is seen, and again when the
 * transport or host it was recorded with changes. Hook sessions only carry
 * the name, so for servers seen only through hooks the name is the identity.
 *
 * It also keeps the external hosts agent calls have reached, in
 * $OMNODEX_HOME/known-destinations.json:
 *
 *   { "version": 1, "hosts": { "<host>": { "first_seen": "..." } } }
 *
 * so a rule can say a call goes somewhere this machine has never sent
 * anything.
 *
 * And it keeps the last observation of each MCP server (from the proxy's
 * server.observed events), in $OMNODEX_HOME/known-server-fingerprints.json:
 *
 *   { "version": 1, "servers": { "<name>|<transport>": { "seen_at": "...",
 *       "config": "<fp>", "reported_version": "1.0.15",
 *       "installed_version": "1.0.15", "list": "<fp>",
 *       "tools": { "<tool>": "<fp>" } } } }
 *
 * so a rule can say a server changed since this machine last saw it. The
 * newest observation always replaces the record. Nothing in any of these
 * files leaves the machine.
 *
 * On first use each file is seeded from the event logs, so upgrading does
 * not report every server or host already in use as new. Writes merge with
 * what is on disk and replace the file atomically, since the proxy and the
 * background pass may both update it.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { McpServerTransport, ServerObservedEvent, ToolInvokedEvent, TraceEvent } from "@omnodex/shared";
import { normalizeAction } from "./action.js";

export const KNOWN_MCP_SERVERS_FILE = "known-mcp-servers.json";
export const KNOWN_DESTINATIONS_FILE = "known-destinations.json";
export const KNOWN_SERVER_FINGERPRINTS_FILE = "known-server-fingerprints.json";

/** How an MCP server differs from the last time this machine observed it. */
export interface ServerDrift {
  /** Reported version, before and after, when both are known and differ. */
  reportedVersion?: { from: string; to: string };
  /** Installed package version, before and after, when both are known and differ. */
  installedVersion?: { from: string; to: string };
  configChanged: boolean;
  added: string[];
  removed: string[];
  /** Tools whose description or input schema changed. */
  changed: string[];
  /** The change was announced while the server was in use. */
  midSession: boolean;
}

export type SeenResult = "new" | "changed" | "known";

export interface MachineState {
  /**
   * Record a sighting of an MCP server and say whether it is new to this
   * machine, known but reached differently than recorded, or known.
   */
  noteMcpServer(name: string, transport: McpServerTransport | undefined, at: string): SeenResult;
  /** Whether a call from this machine had reached the host before. */
  knowsDestination(host: string): boolean;
  /** Record the hosts a call reached. */
  noteDestinations(hosts: readonly string[], at: string): void;
  /**
   * Record an MCP server observation and say how the server differs from
   * the last one recorded. Null for the first observation of a server, for
   * an identical one, and for one older than the record.
   */
  noteServerObservation(event: ServerObservedEvent): ServerDrift | null;
}

/** The external hosts a call reaches: what known-destinations.json records. */
export function reachedHosts(event: ToolInvokedEvent): string[] {
  const action = normalizeAction(event);
  if (!action.outbound) return [];
  return [...new Set(action.destinations.filter((d) => d.ipClass !== "loopback").map((d) => d.host))];
}

interface ServerRecord {
  first_seen: string;
  transport?: "stdio" | "http";
  host?: string;
}

interface StateFile {
  version: 1;
  servers: Record<string, ServerRecord>;
}

function readState(file: string): StateFile | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<StateFile>;
    if (parsed?.version === 1 && parsed.servers && typeof parsed.servers === "object") {
      return { version: 1, servers: parsed.servers };
    }
  } catch {
    // Missing or unreadable.
  }
  return null;
}

function writeState(file: string, state: StateFile): void {
  // Merge with whatever another process wrote since we loaded.
  const onDisk = readState(file);
  const merged: StateFile = { version: 1, servers: { ...(onDisk?.servers ?? {}), ...state.servers } };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(merged, null, 2) + "\n");
  fs.renameSync(tmp, file);
}

function differs(record: ServerRecord, transport: McpServerTransport): boolean {
  if (record.transport === undefined) return false;
  return record.transport !== transport.transport || (record.host ?? "") !== (transport.host ?? "");
}

/** Server sightings in one session's events, for seeding. */
function sightings(events: TraceEvent[], into: Record<string, ServerRecord>): void {
  const transports = new Map<string, McpServerTransport>();
  for (const e of events) {
    if (e.event_type === "session.started") {
      for (const t of e.mcp_server_transports ?? []) transports.set(t.name, t);
    }
  }
  for (const e of events) {
    if (e.event_type !== "tool.invoked" || !e.mcp_server || e.mcp_server === "builtin") continue;
    const record = (into[e.mcp_server] ??= { first_seen: e.occurred_at });
    if (e.occurred_at < record.first_seen) record.first_seen = e.occurred_at;
    const t = transports.get(e.mcp_server);
    if (t && record.transport === undefined) {
      record.transport = t.transport;
      if (t.host) record.host = t.host;
    }
  }
}

/** Each session's events in the event logs under these roots. */
function eachLoggedSession(roots: readonly string[], visit: (events: TraceEvent[]) => void): void {
  for (const root of roots) {
    const dir = path.join(root, "sessions");
    let files: string[] = [];
    try {
      files = fs.readdirSync(dir).filter((f) => f.endsWith(".jsonl"));
    } catch {
      continue;
    }
    for (const f of files) {
      let raw = "";
      try {
        raw = fs.readFileSync(path.join(dir, f), "utf8");
      } catch {
        continue;
      }
      const events: TraceEvent[] = [];
      for (const line of raw.split("\n")) {
        if (!line.trim()) continue;
        try {
          events.push(JSON.parse(line) as TraceEvent);
        } catch {
          // Partial trailing write.
        }
      }
      visit(events);
    }
  }
}

function seedServers(roots: readonly string[]): Record<string, ServerRecord> {
  const servers: Record<string, ServerRecord> = {};
  eachLoggedSession(roots, (events) => sightings(events, servers));
  return servers;
}

interface HostRecord {
  first_seen: string;
}

interface HostsFile {
  version: 1;
  hosts: Record<string, HostRecord>;
}

function seedHosts(roots: readonly string[]): Record<string, HostRecord> {
  const hosts: Record<string, HostRecord> = {};
  eachLoggedSession(roots, (events) => {
    for (const e of events) {
      if (e.event_type !== "tool.invoked") continue;
      for (const host of reachedHosts(e)) {
        const record = (hosts[host] ??= { first_seen: e.occurred_at });
        if (e.occurred_at < record.first_seen) record.first_seen = e.occurred_at;
      }
    }
  });
  return hosts;
}

function readHosts(file: string): HostsFile | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<HostsFile>;
    if (parsed?.version === 1 && parsed.hosts && typeof parsed.hosts === "object") {
      return { version: 1, hosts: parsed.hosts };
    }
  } catch {
    // Missing or unreadable.
  }
  return null;
}

function writeHosts(file: string, hosts: Record<string, HostRecord>): void {
  const onDisk = readHosts(file);
  const merged: HostsFile = { version: 1, hosts: { ...(onDisk?.hosts ?? {}), ...hosts } };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(merged, null, 2) + "\n");
  fs.renameSync(tmp, file);
}

interface FingerprintRecord {
  seen_at: string;
  config: string;
  reported_version?: string;
  installed_version?: string;
  list: string;
  tools: Record<string, string>;
}

interface FingerprintsFile {
  version: 1;
  servers: Record<string, FingerprintRecord>;
}

function serverKey(event: ServerObservedEvent): string {
  return `${event.mcp_server}|${event.transport}`;
}

function toFingerprintRecord(event: ServerObservedEvent): FingerprintRecord {
  return {
    seen_at: event.occurred_at,
    config: event.config_fingerprint,
    ...(event.reported?.version ? { reported_version: event.reported.version } : {}),
    ...(event.installed_version ? { installed_version: event.installed_version } : {}),
    list: event.tool_list_fingerprint,
    tools: Object.fromEntries(event.tools.map((t) => [t.name, t.fingerprint])),
  };
}

/** How `now` differs from `before`, or null when nothing compared differs. */
export function compareObservations(before: FingerprintRecord, now: FingerprintRecord, midSession: boolean): ServerDrift | null {
  const version = (from?: string, to?: string) => (from && to && from !== to ? { from, to } : undefined);
  const reportedVersion = version(before.reported_version, now.reported_version);
  const installedVersion = version(before.installed_version, now.installed_version);
  const configChanged = before.config !== now.config;
  const added = Object.keys(now.tools).filter((t) => !Object.hasOwn(before.tools, t)).sort();
  const removed = Object.keys(before.tools).filter((t) => !Object.hasOwn(now.tools, t)).sort();
  const changed = Object.keys(now.tools)
    .filter((t) => Object.hasOwn(before.tools, t) && before.tools[t] !== now.tools[t])
    .sort();
  if (!reportedVersion && !installedVersion && !configChanged && !added.length && !removed.length && !changed.length) {
    return null;
  }
  return {
    ...(reportedVersion ? { reportedVersion } : {}),
    ...(installedVersion ? { installedVersion } : {}),
    configChanged,
    added,
    removed,
    changed,
    midSession,
  };
}

function seedFingerprints(roots: readonly string[]): Record<string, FingerprintRecord> {
  const servers: Record<string, FingerprintRecord> = {};
  eachLoggedSession(roots, (events) => {
    for (const e of events) {
      if (e.event_type !== "server.observed") continue;
      const key = serverKey(e);
      if (!servers[key] || servers[key].seen_at <= e.occurred_at) servers[key] = toFingerprintRecord(e);
    }
  });
  return servers;
}

function readFingerprints(file: string): FingerprintsFile | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as Partial<FingerprintsFile>;
    if (parsed?.version === 1 && parsed.servers && typeof parsed.servers === "object") {
      return { version: 1, servers: parsed.servers };
    }
  } catch {
    // Missing or unreadable.
  }
  return null;
}

function writeFingerprints(file: string, changed: Record<string, FingerprintRecord>): void {
  const onDisk = readFingerprints(file);
  const merged: FingerprintsFile = { version: 1, servers: { ...(onDisk?.servers ?? {}) } };
  // Another process may have recorded a newer observation since we loaded.
  for (const [key, record] of Object.entries(changed)) {
    const current = merged.servers[key];
    if (!current || current.seen_at <= record.seen_at) merged.servers[key] = record;
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(merged, null, 2) + "\n");
  fs.renameSync(tmp, file);
}

/**
 * The machine state for an installation. A file that does not exist yet
 * is seeded from the event logs under `seedRoots` (event-log root
 * directories) and written.
 */
export function openMachineState(
  home: string,
  opts: { seedRoots?: readonly string[] } = {},
): MachineState {
  const roots = opts.seedRoots ?? [path.join(home, "event-log")];
  const file = path.join(home, KNOWN_MCP_SERVERS_FILE);
  let state = readState(file);
  if (!state) {
    state = { version: 1, servers: seedServers(roots) };
    try {
      writeState(file, state);
    } catch {
      // Unwritable home: keep working in memory.
    }
  }
  const hostsFile = path.join(home, KNOWN_DESTINATIONS_FILE);
  let hosts = readHosts(hostsFile)?.hosts;
  if (!hosts) {
    hosts = seedHosts(roots);
    try {
      writeHosts(hostsFile, hosts);
    } catch {
      // Unwritable home: keep working in memory.
    }
  }
  const fingerprintsFile = path.join(home, KNOWN_SERVER_FINGERPRINTS_FILE);
  let fingerprints = readFingerprints(fingerprintsFile)?.servers;
  if (!fingerprints) {
    fingerprints = seedFingerprints(roots);
    try {
      writeFingerprints(fingerprintsFile, fingerprints);
    } catch {
      // Unwritable home: keep working in memory.
    }
  }
  const knownFingerprints = fingerprints;
  return makeState(
    state.servers,
    (name) => writeState(file, { version: 1, servers: { [name]: state.servers[name] } }),
    hosts,
    (added) => writeHosts(hostsFile, added),
    knownFingerprints,
    (key) => writeFingerprints(fingerprintsFile, { [key]: knownFingerprints[key]! }),
  );
}

/** An in-memory machine state, for tests and hosts with nowhere to persist. */
export function memoryMachineState(): MachineState {
  return makeState({}, () => undefined, {}, () => undefined, {}, () => undefined);
}

function makeState(
  servers: Record<string, ServerRecord>,
  persist: (name: string) => void,
  hosts: Record<string, HostRecord>,
  persistHosts: (added: Record<string, HostRecord>) => void,
  fingerprints: Record<string, FingerprintRecord>,
  persistFingerprint: (key: string) => void,
): MachineState {
  return {
    noteServerObservation(event): ServerDrift | null {
      const key = serverKey(event);
      const before = fingerprints[key];
      const now = toFingerprintRecord(event);
      if (before && event.occurred_at < before.seen_at) return null;
      fingerprints[key] = now;
      try {
        persistFingerprint(key);
      } catch {
        // Keep the in-memory answer; the next writer will persist it.
      }
      return before ? compareObservations(before, now, event.trigger === "list_changed") : null;
    },

    knowsDestination(host): boolean {
      return Object.hasOwn(hosts, host.toLowerCase());
    },

    noteDestinations(reached, at): void {
      const added: Record<string, HostRecord> = {};
      for (const h of reached) {
        const host = h.toLowerCase();
        if (Object.hasOwn(hosts, host)) continue;
        hosts[host] = added[host] = { first_seen: at };
      }
      if (Object.keys(added).length === 0) return;
      try {
        persistHosts(added);
      } catch {
        // Keep the in-memory answer; the next writer will persist it.
      }
    },

    noteMcpServer(name, transport, at): SeenResult {
      const record = servers[name];
      let result: SeenResult;
      if (!record) {
        servers[name] = { first_seen: at };
        if (transport) setTransport(servers[name], transport);
        result = "new";
      } else if (transport && differs(record, transport)) {
        setTransport(record, transport);
        result = "changed";
      } else if (transport && record.transport === undefined) {
        setTransport(record, transport);
        result = "known";
      } else {
        return "known";
      }
      try {
        persist(name);
      } catch {
        // Keep the in-memory answer; the next writer will persist it.
      }
      return result;
    },
  };
}

function setTransport(record: ServerRecord, transport: McpServerTransport): void {
  record.transport = transport.transport;
  if (transport.host) record.host = transport.host;
  else delete record.host;
}
