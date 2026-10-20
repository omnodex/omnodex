// Points HOME and OMNODEX_HOME at a fresh temporary folder for the importing
// test file, so a developer's real Omnodex home (a Pro bundle, a license, a
// guardrails module) neither changes results nor gets written to. Import it
// first, before anything that reads either variable. Each test file runs in
// its own process, so this stays within that file.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "omnodex-test-home-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.env.OMNODEX_HOME = join(home, ".omnodex");
process.env.OMNODEX_SINGLE_ROOT = "1";
process.on("exit", () => rmSync(home, { recursive: true, force: true }));
