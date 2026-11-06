// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The record `omnodex export` writes.
 *
 * Every exported event goes through one path: the logged event is redacted
 * into a normalized event, and the OCSF form is mapped from that normalized
 * event. Mapping never sees the original, so a field that redaction removed
 * cannot reappear in either format.
 */

import type { TraceEvent } from "@omnodex/shared";

/** Names the normalized event format, so a parser can tell versions apart. */
export const EXPORT_SCHEMA = "omnodex.event/1";

/** The OCSF release the mapping was written against. */
export const OCSF_VERSION = "1.3.0";

/**
 * Fields that carry what a person typed or what a tool printed, and so are
 * left out unless asked for. Metadata and findings are always exported.
 * Event logs hold no file contents, so there is no group for them.
 */
export const CONTENT_GROUPS = {
  /** The text of each prompt. */
  prompts: ["prompt"],
  /** The arguments of tool calls and permission requests. */
  parameters: ["parameters"],
  /** Session titles, which people write and agent runtimes derive from prompts. */
  titles: ["title"],
  /** Error text from tools and the runtime's reason for a denied permission. */
  errors: ["error_message", "reason"],
} as const;

export type ContentGroup = keyof typeof CONTENT_GROUPS;

export const CONTENT_GROUP_NAMES = Object.keys(CONTENT_GROUPS) as ContentGroup[];

/** A logged event with content removed, as exported in the jsonl format. */
export type NormalizedEvent = Record<string, unknown> & {
  export_schema: typeof EXPORT_SCHEMA;
  event_id: string;
  event_type: string;
  session_id: string;
  occurred_at: string;
  recorded_at: string;
  /** Names of the fields redaction removed from this event. */
  redacted?: string[];
};

/**
 * Parse `--include`: a comma-separated list of content groups, or `all`.
 * Returns the groups, or an error message naming what was not recognized.
 */
export function parseInclude(value: string | undefined): { groups: Set<ContentGroup> } | { error: string } {
  const groups = new Set<ContentGroup>();
  if (value === undefined) return { groups };
  for (const raw of value.split(",")) {
    const name = raw.trim().toLowerCase();
    if (!name) continue;
    if (name === "all") {
      for (const g of CONTENT_GROUP_NAMES) groups.add(g);
    } else if (Object.hasOwn(CONTENT_GROUPS, name)) {
      groups.add(name as ContentGroup);
    } else {
      return { error: `unknown content group '${name}' (use ${CONTENT_GROUP_NAMES.join(", ")} or all)` };
    }
  }
  return { groups };
}

/**
 * Redact an event into its normalized form. Fields in a group that was not
 * included are removed and listed under `redacted`, so a reader can tell a
 * redacted field from one the event never had.
 */
export function normalizeEvent(event: TraceEvent, include: ReadonlySet<ContentGroup> = new Set()): NormalizedEvent {
  const blocked = new Set<string>();
  for (const group of CONTENT_GROUP_NAMES) {
    if (include.has(group)) continue;
    for (const field of CONTENT_GROUPS[group]) blocked.add(field);
  }
  const out: Record<string, unknown> = { export_schema: EXPORT_SCHEMA };
  const redacted: string[] = [];
  for (const [key, value] of Object.entries(event)) {
    if (key === "schema_version") continue;
    if (blocked.has(key)) {
      redacted.push(key);
      continue;
    }
    out[key] = value;
  }
  if (redacted.length > 0) out.redacted = redacted.sort();
  return out as NormalizedEvent;
}

// ---------------------------------------------------------------------------
// OCSF
// ---------------------------------------------------------------------------

const SEVERITY_ID: Record<string, number> = { LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
const SEVERITY_NAME: Record<number, string> = { 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical" };

interface ClassInfo {
  category_uid: number;
  category_name: string;
  class_uid: number;
  class_name: string;
}

const API_ACTIVITY: ClassInfo = { category_uid: 6, category_name: "Application Activity", class_uid: 6003, class_name: "API Activity" };
const APP_LIFECYCLE: ClassInfo = { category_uid: 6, category_name: "Application Activity", class_uid: 6002, class_name: "Application Lifecycle" };
const FILE_ACTIVITY: ClassInfo = { category_uid: 1, category_name: "System Activity", class_uid: 1001, class_name: "File System Activity" };
const DETECTION_FINDING: ClassInfo = { category_uid: 2, category_name: "Findings", class_uid: 2004, class_name: "Detection Finding" };
const BASE_EVENT: ClassInfo = { category_uid: 0, category_name: "Uncategorized", class_uid: 0, class_name: "Base Event" };

/** Epoch milliseconds for an ISO timestamp; 0 when it does not parse. */
function epochMs(iso: unknown): number {
  const ms = typeof iso === "string" ? Date.parse(iso) : NaN;
  return Number.isNaN(ms) ? 0 : ms;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function fileName(p: string): string {
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

/** Drop keys whose value is undefined, so mapped objects stay compact. */
function compact<T extends Record<string, unknown>>(obj: T): T {
  for (const key of Object.keys(obj)) {
    if (obj[key] === undefined) delete obj[key];
  }
  return obj;
}

/**
 * Map a normalized event to an OCSF event. Tool calls become API Activity,
 * file reads and writes File System Activity, findings Detection Finding and
 * session start and end Application Lifecycle. Every other event type is a
 * Base Event that names its Omnodex type. Fields OCSF has no home for (agent,
 * model, MCP server, interceptor, working directory) go under `unmapped`.
 */
export function toOcsf(event: NormalizedEvent): Record<string, unknown> {
  const e = event as Record<string, unknown>;
  const type = event.event_type;
  const platform = str(e.platform);
  const unmapped: Record<string, unknown> = compact({
    omnodex_event_type: type,
    interceptor: str(e.interceptor),
    platform,
    agent_id: str(e.agent_id),
    local_only: e.local_only === true ? true : undefined,
    mcp_server: str(e.mcp_server),
    tool_call_id: str(e.tool_call_id),
    cwd: str(e.cwd),
    model: str(e.model),
    redacted: Array.isArray(e.redacted) ? e.redacted : undefined,
  });

  let info: ClassInfo = BASE_EVENT;
  let activityId = 99;
  let activityName = type;
  let severityId = 1;
  let statusId: number | undefined;
  let message: string | undefined;
  const extra: Record<string, unknown> = {};

  switch (type) {
    case "tool.invoked": {
      info = API_ACTIVITY;
      activityName = "Invoke";
      extra.api = { operation: str(e.tool_name) ?? "unknown", service: { name: str(e.mcp_server) ?? "unknown" } };
      if (e.parameters !== undefined) unmapped.parameters = e.parameters;
      break;
    }
    case "tool.completed": {
      info = API_ACTIVITY;
      activityName = "Complete";
      statusId = e.status === "error" ? 2 : 1;
      extra.api = { request: { uid: str(e.tool_call_id) } };
      unmapped.duration_ms = num(e.duration_ms);
      unmapped.response_bytes = num(e.response_bytes);
      message = str(e.error_message);
      break;
    }
    case "file.read":
    case "file.written": {
      info = FILE_ACTIVITY;
      activityId = type === "file.read" ? 2 : 3;
      activityName = type === "file.read" ? "Read" : "Update";
      const p = str(e.path);
      extra.file = compact({ path: p, name: p ? fileName(p) : undefined, size: num(e.bytes) });
      break;
    }
    case "risk.detected": {
      info = DETECTION_FINDING;
      activityId = 1;
      activityName = "Create";
      severityId = SEVERITY_ID[String(e.severity)] ?? 1;
      const related = [str(e.related_event_id), ...(Array.isArray(e.related_event_ids) ? e.related_event_ids.map(str) : [])]
        .filter((v, i, all): v is string => v !== undefined && all.indexOf(v) === i);
      extra.finding_info = compact({
        uid: event.event_id,
        title: str(e.category) ?? str(e.rule_id),
        desc: str(e.description),
        types: str(e.category) ? [e.category] : undefined,
        analytic: compact({ name: str(e.rule_id), uid: str(e.rule_id), type_id: 1, type: "Rule" }),
        related_events: related.length ? related.map((uid) => ({ uid })) : undefined,
      });
      unmapped.rule_tier = str(e.rule_tier);
      unmapped.recommended_severity = str(e.recommended_severity);
      unmapped.evidence = e.evidence;
      unmapped.enforcement = e.enforcement;
      unmapped.credential_fingerprints = e.credential_fingerprints;
      message = str(e.description);
      break;
    }
    case "session.started": {
      info = APP_LIFECYCLE;
      activityId = 3;
      activityName = "Start";
      extra.app = compact({ name: platform ?? str(e.interceptor) ?? "agent" });
      unmapped.project_path = str(e.project_path);
      unmapped.project_remote = str(e.project_remote);
      unmapped.mcp_servers = e.mcp_servers;
      break;
    }
    case "session.ended": {
      info = APP_LIFECYCLE;
      activityId = 4;
      activityName = "Stop";
      statusId = e.status === "errored" ? 2 : 1;
      extra.app = compact({ name: platform ?? str(e.interceptor) ?? "agent" });
      unmapped.duration_ms = num(e.duration_ms);
      unmapped.session_status = str(e.status);
      break;
    }
    default: {
      // Remaining fields of an unmapped type are kept so no information is
      // lost between the two formats.
      const skip = new Set(["export_schema", "event_id", "event_type", "session_id", "occurred_at", "recorded_at", "interceptor", "platform", "agent_id", "local_only", "redacted"]);
      const rest: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(e)) if (!skip.has(k)) rest[k] = v;
      if (Object.keys(rest).length > 0) unmapped.data = rest;
    }
  }

  const base: Record<string, unknown> = {
    ...info,
    activity_id: activityId,
    activity_name: activityName,
    type_uid: info.class_uid * 100 + activityId,
    type_name: `${info.class_name}: ${activityName}`,
    time: epochMs(event.occurred_at),
    severity_id: severityId,
    severity: SEVERITY_NAME[severityId],
    status_id: statusId,
    message,
    metadata: {
      version: OCSF_VERSION,
      product: { name: "Omnodex", vendor_name: "Omnodex" },
      uid: event.event_id,
      logged_time: epochMs(event.recorded_at),
      original_time: event.occurred_at,
    },
    actor: compact({ app_name: platform, session: { uid: event.session_id }, user: str(e.user) ? { name: e.user } : undefined }),
    ...extra,
    unmapped,
  };
  return compact(base);
}

// ---------------------------------------------------------------------------
// Time filters
// ---------------------------------------------------------------------------

const UNIT_MS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 };

/**
 * Parse a time argument: an ISO date or timestamp, or an age such as 30m,
 * 24h or 7d meaning that long before `now`. Returns epoch milliseconds, or
 * undefined when the text is neither.
 */
export function parseTimeArg(text: string, now: number = Date.now()): number | undefined {
  const age = /^(\d+)([smhdw])$/i.exec(text.trim());
  if (age) return now - Number(age[1]) * UNIT_MS[age[2].toLowerCase()];
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? undefined : ms;
}

/** Whether an event falls in [since, until). An event with no usable time passes. */
export function inWindow(event: TraceEvent, since?: number, until?: number): boolean {
  if (since === undefined && until === undefined) return true;
  let ms = Date.parse(event.occurred_at);
  if (Number.isNaN(ms)) ms = Date.parse(event.recorded_at);
  if (Number.isNaN(ms)) return true;
  if (since !== undefined && ms < since) return false;
  if (until !== undefined && ms >= until) return false;
  return true;
}
