// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cursorDecision } from "../dist/index.js";

const deny = { permission: "deny", user_message: "u", agent_message: "a", decision: "deny", reason: "r", extra: "x" };
const ask = { permission: "ask", user_message: "u", agent_message: "a", decision: "deny", reason: "r (ask your user)" };

test("nothing to say when the call runs", () => {
  assert.equal(cursorDecision("preToolUse", null), undefined);
  assert.equal(cursorDecision("beforeShellExecution", null), undefined);
});

test("permission hooks print the permission shape and nothing else", () => {
  assert.deepEqual(cursorDecision("beforeShellExecution", deny), { permission: "deny", user_message: "u", agent_message: "a" });
  assert.deepEqual(cursorDecision("beforeMCPExecution", ask), { permission: "ask", user_message: "u", agent_message: "a" });
  assert.deepEqual(cursorDecision("beforeReadFile", ask), { permission: "ask", user_message: "u", agent_message: "a" });
});

test("preToolUse prints a deny with the reason; it never asks", () => {
  assert.deepEqual(cursorDecision("preToolUse", deny), { decision: "deny", reason: "r" });
  assert.deepEqual(cursorDecision("preToolUse", ask), { decision: "deny", reason: "r (ask your user)" });
});

test("a tool with its own permission hook leaves a confirm verdict to that hook", () => {
  assert.equal(cursorDecision("preToolUse", ask, { hasPermissionHook: true }), undefined);
  assert.deepEqual(cursorDecision("preToolUse", deny, { hasPermissionHook: true }), { decision: "deny", reason: "r" });
});

test("a module answer in some other shape still stops the call rather than printing it", () => {
  assert.deepEqual(cursorDecision("beforeShellExecution", { test_decision: "deny" }), { permission: "deny" });
  assert.deepEqual(cursorDecision("preToolUse", { test_decision: "deny" }), { decision: "deny" });
});
