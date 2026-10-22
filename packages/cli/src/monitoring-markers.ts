// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Markers for every change Omnodex makes to its own monitoring.
 *
 * Installing, removing, leaving a project out, updating, connecting and
 * changing enforcement each append a monitoring.changed event to the
 * capture-control session. A hook entry that disappears, or a machine that
 * goes quiet, with no marker to explain it is then unexplained rather than
 * just absent. Markers carry no captured content.
 *
 * Writing a marker never fails the change it describes: errors are
 * swallowed. Pushing it to the hosted dashboard is best effort.
 */

import * as os from "node:os";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import {
  CAPTURE_CONTROL_SESSION_ID,
  SCHEMA_VERSION,
  type MonitoringActor,
  type MonitoringChangedEvent,
  type RiskDetectedEvent,
  type TraceEvent,
} from "@omnodex/shared";
import { appendMarkers } from "./capture-controls.js";
import { getInstalledVersion } from "./registry.js";

/** What a caller says about a change; the rest is filled in here. */
export type MonitoringChange = Pick<
  MonitoringChangedEvent,
  "action" | "target" | "component" | "scope" | "project_path" | "from" | "to"
>;

type Push = (events: TraceEvent[], home: string) => Promise<unknown>;

let push: Push | undefined;
let actorOverride: MonitoringActor | undefined;

/** Send markers to the hosted dashboard as well (set once by the CLI entry point). */
export function setMarkerPush(fn: Push | undefined): void {
  push = fn;
}

/** Mark every change in this process as made by this actor (for --unattended). */
export function setMonitoringActor(actor: MonitoringActor | undefined): void {
  actorOverride = actor;
}

/** A person at an interactive terminal, unless told otherwise. */
export function currentActor(): MonitoringActor {
  if (actorOverride) return actorOverride;
  return process.stdin.isTTY && process.stdout.isTTY ? "terminal" : "unattended";
}

/** Changes that take monitoring away; made unattended, they raise a finding. */
const REMOVALS = new Set<MonitoringChange["action"]>(["uninstall", "exclude", "everywhere_off"]);

function defaultHome(): string {
  return process.env.OMNODEX_HOME ?? path.join(os.homedir(), ".omnodex");
}

/** Append one marker. Returns it, or null if it could not be written. */
export async function recordMonitoringChange(
  change: MonitoringChange,
  home: string = defaultHome(),
): Promise<MonitoringChangedEvent | null> {
  try {
    const now = new Date().toISOString();
    const marker: MonitoringChangedEvent = {
      schema_version: SCHEMA_VERSION,
      event_id: randomUUID(),
      session_id: CAPTURE_CONTROL_SESSION_ID,
      occurred_at: now,
      recorded_at: now,
      interceptor: "analyzer",
      event_type: "monitoring.changed",
      ...withoutUndefined(change),
      cli_version: getInstalledVersion(),
      actor: currentActor(),
      machine_label: os.hostname(),
    };
    await appendMarkers(home, [marker], push);
    if (actorOverride === "unattended" && REMOVALS.has(change.action)) await recordUnattendedRemoval(marker, home);
    return marker;
  } catch {
    return null;
  }
}

/** Rule id of the finding an unattended removal raises. */
export const UNATTENDED_REMOVAL_RULE_ID = "RULE_SELF_PROTECTION_UNATTENDED_REMOVAL";

/**
 * A MEDIUM finding for a removal made without a terminal: on record, and
 * visible, even when it was a legitimate scripted removal.
 */
export async function recordUnattendedRemoval(
  marker: MonitoringChangedEvent,
  home: string = defaultHome(),
): Promise<void> {
  try {
    const now = new Date().toISOString();
    const what = [marker.target, marker.component].filter(Boolean).join(" ");
    const where = marker.scope === "user" ? "every project" : marker.project_path ?? "a project";
    const finding: RiskDetectedEvent = {
      schema_version: SCHEMA_VERSION,
      event_id: randomUUID(),
      session_id: CAPTURE_CONTROL_SESSION_ID,
      occurred_at: now,
      recorded_at: now,
      interceptor: "analyzer",
      event_type: "risk.detected",
      severity: "MEDIUM",
      category: "self_protection",
      description:
        `Omnodex ${marker.action === "exclude" ? "stopped recording" : "removed"} ${what ? `${what} ` : ""}for ${where} ` +
        "without a person at a terminal (--unattended). Confirm a script or administrator made this change, not an agent.",
      related_event_id: marker.event_id,
      rule_id: UNATTENDED_REMOVAL_RULE_ID,
      rule_tier: "community",
    };
    await appendMarkers(home, [finding], push);
  } catch {
    // A finding that cannot be written must not stop the removal.
  }
}

function withoutUndefined<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;
}
