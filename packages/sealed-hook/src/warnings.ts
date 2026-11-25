// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * The warning left on a host when a project's settings file was ignored, so a
 * person who expected it to apply can find out why. One line per session, in
 * the Omnodex home; `omnodex status` shows the latest. Nothing is printed to
 * the agent.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { ingestDir } from "@omnodex/hooks-provider";

const LOG = "warnings.log";
const SEEN = "warned";
const MAX_LOG_BYTES = 64 * 1024;

export function ignoredProjectWarning(file: string, home: string, recording: boolean): string {
  // The path comes from the repository: keep it on one line.
  const shown = file.replace(/[\u0000-\u001f\u007f]/g, "?");
  const what = recording
    ? `Omnodex ignored the ingest settings in ${shown} because this host has its own.`
    : `Omnodex is not recording: it ignored the ingest settings in ${shown} because this host has its own, and those are incomplete or invalid.`;
  return (
    `${what} To change them, set OMNODEX_INGEST_PUBLIC_KEY and OMNODEX_INGEST_SOURCE_ID ` +
    `in the environment, or put the settings in ${path.join(home, "ingest.json")}.`
  );
}

/** Records the warning the first time a session meets it. Never throws. */
export function recordIngestWarning(home: string, sessionId: string, message: string, now: number): void {
  try {
    const seen = path.join(ingestDir(home), SEEN);
    fs.mkdirSync(seen, { recursive: true });
    const mark = path.join(seen, createHash("sha256").update(sessionId).digest("hex").slice(0, 32));
    // Fails when the mark exists, which also settles two hooks running at once.
    fs.writeFileSync(mark, "", { flag: "wx" });
    const log = path.join(ingestDir(home), LOG);
    const line = `${new Date(now).toISOString()} ${message}\n`;
    const full = fs.existsSync(log) && fs.statSync(log).size > MAX_LOG_BYTES;
    if (full) fs.writeFileSync(log, line);
    else fs.appendFileSync(log, line);
  } catch {
    // Already warned, or the home cannot be written. Capture goes on either way.
  }
}

/** The latest warning, or null when there has been none. */
export function lastIngestWarning(home: string): { at: string; message: string } | null {
  try {
    const last = fs.readFileSync(path.join(ingestDir(home), LOG), "utf8").trimEnd().split("\n").pop() ?? "";
    const space = last.indexOf(" ");
    return space > 0 ? { at: last.slice(0, space), message: last.slice(space + 1) } : null;
  } catch {
    return null;
  }
}
