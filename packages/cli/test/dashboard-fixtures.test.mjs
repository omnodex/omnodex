/**
 * Dashboard conformance fixtures, local page side: each session's source
 * label matches what the fixture expects. The hosted dashboard checks its
 * labels against the same files.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { runtimeLabel } from "../dist/dashboard-model/index.js";

const DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "projection", "test", "fixtures", "dashboard");

for (const file of readdirSync(DIR).filter((f) => f.endsWith(".json"))) {
  test(`fixture ${file}: session labels`, () => {
    const { snapshot, expected } = JSON.parse(readFileSync(path.join(DIR, file), "utf8"));
    for (const [id, want] of Object.entries(expected.sessions)) {
      const s = snapshot.sessions.find((x) => x.session_id === id);
      assert.equal(runtimeLabel(s), want.label, id);
    }
  });
}
