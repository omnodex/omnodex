// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { opencodeDecision } from "../dist/index.js";

test("nothing to say when the call runs", () => {
  assert.equal(opencodeDecision(null), undefined);
});

test("a deny carries the reason", () => {
  assert.deepEqual(opencodeDecision({ decision: "deny", reason: "r", other: 1 }), { decision: "deny", reason: "r" });
});

test("any other answer from the module still stops the call", () => {
  assert.deepEqual(opencodeDecision({ test_decision: "deny" }), { decision: "deny" });
  assert.deepEqual(opencodeDecision({ reason: "" }), { decision: "deny" });
});
