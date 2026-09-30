// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

/** Time and number formatting for the local dashboard. */

import { riskBandFor, type RiskSeverity } from "@omnodex/shared";

/** A clock time with milliseconds: HH:MM:SS.mmm, local or UTC. */
export function formatTime(iso: string | null | undefined, utc: boolean): string {
  if (!iso) return "n/a";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  if (utc) {
    return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)}`;
  }
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

/** A date and time with its zone: the browser's zone abbreviation, or UTC. */
export function formatWithTz(iso: string | null | undefined, utc: boolean): string {
  if (!iso) return "n/a";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  if (utc) return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "") + " UTC";
  const zone = localZoneName(d);
  return d.toLocaleString() + (zone ? ` ${zone}` : "");
}

/** The browser's short zone name, such as "EDT", when it has one. */
export function localZoneName(d: Date = new Date()): string | null {
  return d.toLocaleTimeString("en-US", { timeZoneName: "short" }).match(/\s([A-Z]{2,5})$/)?.[1] ?? null;
}

export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "";
  const sec = Math.floor((now - new Date(iso).getTime()) / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  return `${Math.floor(hr / 24)}d ago`;
}

/** Scores are sums of tenths, so they are rounded before display. */
export function formatRisk(score: number | null | undefined): string {
  return (Math.round((score || 0) * 100) / 100).toString();
}

/** The band a score shows as. Nothing fired reads as LOW, as before. */
export function riskBandLabel(score: number | null | undefined): RiskSeverity {
  return riskBandFor(score || 0) ?? "LOW";
}
