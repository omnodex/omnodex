#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

// Keep the receipt path free of analyzer imports. Claude Code can cancel
// async hooks on exit, so installed monitor hooks acknowledge a local spool
// write, then leave mapping, analysis and network work to a detached process.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";

// Recording pauses must also keep payloads out of the durable handoff.
// Guardrails PreToolUse never takes this background branch.
function recordingPaused(home: string): boolean {
  try {
    const { record } = JSON.parse(readFileSync(join(home, "pause-state.json"), "utf8"));
    if (!record || typeof record.pause_id !== "string" || typeof record.paused_at !== "string") return false;
    const until = typeof record.until === "string" ? Date.parse(record.until) : NaN;
    return Number.isNaN(until) || Date.now() < until;
  } catch {
    return false;
  }
}

if (process.argv.includes("--background") && process.env.OMNODEX_AUTO_SYNC_CHILD !== "1") {
  try {
    const raw = readFileSync(0, "utf8");
    if (raw.trim()) {
      const payload: unknown = JSON.parse(raw);
      if (payload && typeof payload === "object" && "hook_event_name" in payload) {
        const home = process.env.OMNODEX_HOME ?? join(homedir(), ".omnodex");
        if (recordingPaused(home)) process.exit(0);
        const spool = join(home, "hook-spool");
        mkdirSync(spool, { recursive: true, mode: 0o700 });
        const id = randomUUID();
        writeFileSync(join(spool, `${id}.json`), raw, { flag: "wx", mode: 0o600 });
        const child = spawn(process.execPath, [process.argv[1]!, "--capture-worker", id], {
          detached: true, windowsHide: true, stdio: "ignore", env: process.env,
        });
        child.on("error", (err) => console.error(`[omnodex-hook] capture retained for recovery: ${err.message}`));
        child.unref();
      }
    }
  } catch (err) {
    console.error(`[omnodex-hook] capture handoff failed: ${(err as Error).message}`);
  }
} else {
  // Guardrails still answer synchronously. The same branch also runs the
  // detached receipt worker and the existing background sync entry point.
  void import("./claude-hook-worker.js");
}
