#!/usr/bin/env node
// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * omnodex-sealed-hook <provider> [event]
 *
 * Hook command for hosts that have no Omnodex install, secret or lasting
 * disk: cloud agent VMs, dev servers, devcontainers. Providers: claude-code,
 * copilot, cursor, codex, antigravity (which also takes its event name).
 *
 * Reads one hook payload from stdin, seals each event to the stream public
 * key and sends the batch to write-only ingest at the end of the turn. It
 * captures only on a host that opts in (see the gates in config) and only
 * with complete settings; everywhere else it prints the agent's "no
 * decision" answer and exits.
 *
 * Contract: always exits 0, so a missing config or a network failure can
 * never stop a teammate's agent.
 */

import { runSealedHook } from "../index.js";

const MAX_STDIN_BYTES = 5 * 1024 * 1024;

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= MAX_STDIN_BYTES) chunks.push(c);
    });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", () => resolve(""));
  });
}

async function main(): Promise<void> {
  const provider = process.argv[2] ?? process.env.OMNODEX_SEALED_PROVIDER;
  const stdin = await readStdin();
  const out = await runSealedHook({ provider, eventName: process.argv[3], stdin, env: process.env });
  if (out) process.stdout.write(out);
}

main()
  .catch(() => undefined)
  .finally(() => process.exit(0));
