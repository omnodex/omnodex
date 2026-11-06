// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/** `omnodex seal` and `omnodex verify`. */

import { promises as fs } from "node:fs";
import { loadOrCreateKey, sealPending } from "./seal.js";
import { formatReport, verifyBundle } from "./verify.js";

export interface EvidenceIo {
  log(line: string): void;
  error(line: string): void;
}

export async function runSeal(args: readonly string[], deps: { home: string; roots: string[]; io: EvidenceIo }): Promise<number> {
  if (args[0] === "key") {
    const key = await loadOrCreateKey(deps.home);
    deps.io.log(`key id      ${key.key_id}`);
    deps.io.log(`public key  ${key.public_key}`);
    return 0;
  }
  if (args.length > 0) {
    deps.io.error(`[seal] unexpected argument '${args[0]}'. Run 'omnodex seal --help' for usage.`);
    return 1;
  }
  const result = await sealPending({ home: deps.home, roots: deps.roots });
  if (result.sealed) {
    deps.io.log(`[seal] sealed ${result.count} event(s) as seal ${result.seq}; head ${result.head}`);
  } else if (result.reason === "busy") {
    deps.io.log("[seal] another seal is running; try again in a moment.");
  } else {
    deps.io.log("[seal] nothing new since the last seal.");
  }
  return 0;
}

/** Exit codes: 0 valid, 2 a problem was found, 1 the command could not run. */
export async function runVerify(args: readonly string[], deps: { io: EvidenceIo }): Promise<number> {
  const trusted: string[] = [];
  let json = false;
  let file: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") json = true;
    else if (arg === "--key") trusted.push(args[++i]);
    else if (arg.startsWith("-")) {
      deps.io.error(`[verify] unknown option '${arg}'. Run 'omnodex verify --help' for usage.`);
      return 1;
    } else if (!file) file = arg;
    else {
      deps.io.error("[verify] give one bundle file.");
      return 1;
    }
  }
  if (!file) {
    deps.io.error("[verify] give the bundle file to check. Run 'omnodex verify --help' for usage.");
    return 1;
  }
  let text: string;
  try {
    text = await fs.readFile(file, "utf8");
  } catch (err) {
    deps.io.error(`[verify] cannot read ${file}: ${(err as Error).message}`);
    return 1;
  }
  const report = verifyBundle(text, trusted.length > 0 ? { trustedKeys: trusted } : {});
  if (json) deps.io.log(JSON.stringify(report, null, 2));
  else for (const line of formatReport(report, trusted.length > 0)) deps.io.log(line);
  return report.ok ? 0 : 2;
}
