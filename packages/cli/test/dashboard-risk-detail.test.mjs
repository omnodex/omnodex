// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { test } from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { registerHooks, createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const ts = createRequire(import.meta.url)("typescript");

// Test the actual TSX without requiring a platform-specific esbuild binary.
const hooks = registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith(".") && specifier.endsWith(".js") && context.parentURL?.includes("/src/")) {
      for (const ext of [".ts", ".tsx"]) {
        const url = new URL(specifier.slice(0, -3) + ext, context.parentURL);
        if (existsSync(fileURLToPath(url))) return {url: url.href, shortCircuit: true};
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (/\.tsx?$/.test(url) && url.includes("/src/")) {
      const source = ts.transpileModule(readFileSync(fileURLToPath(url), "utf8"), {compilerOptions: {module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX}}).outputText;
      return {format: "module", source, shortCircuit: true};
    }
    return nextLoad(url, context);
  },
});
const { DetailPanel } = await import("../src/dashboard/components/Panels.tsx");
hooks.deregister();

const risk = {event_id: "r1", session_id: "s1", related_event_id: "t1", severity: "HIGH", category: "sensitive_path_read", description: "Fictional path access", rule_id: "RULE_SENSITIVE_PATH_READ", detected_at: "2026-10-09T12:00:00Z"};
const call = {tool_call_id: "t1", session_id: "s1", tool_name: "read_file", mcp_server: "filesystem", parameters_json: '{"path":"/home/case/.env"}', started_at: risk.detected_at, ended_at: risk.detected_at, duration_ms: 1, status: "success", response_bytes: 12, error_message: null};
const view = {session: null, sessions: [], toolCalls: [], fileEvents: [], riskEvents: [risk], prompts: [], subagents: []};
const render = (calls = [], event = risk) => renderToStaticMarkup(React.createElement(DetailPanel, {view: {...view, toolCalls: calls}, utc: true, detail: {kind: "risk", event}}));

test("Risk Library is the last detail row before related calls, with external-link behavior", () => {
  const html = render([call]);
  assert.ok(html.includes('href="https://docs.omnodex.com/risk-library/rule/' + risk.rule_id + '"'));
  assert.ok(html.includes('target="_blank"'));
  assert.ok(html.includes('rel="noopener noreferrer"'));
  assert.ok(html.includes('Learn more about this risk type (opens in a new tab)'));
  const start = html.indexOf('Risk Library');
  assert.ok(start > html.indexOf('Related Event'));
  assert.ok(start < html.indexOf('Related Tool Call'));
  assert.ok(html.slice(start).includes('<svg'));
});
test("a risk without a related call still links to its rule", () => {
  const html = render([], {...risk, rule_id: "RULE_ADV_CREDENTIAL_READ_THEN_OUTBOUND"});
  assert.ok(html.includes('/risk-library/rule/RULE_ADV_CREDENTIAL_READ_THEN_OUTBOUND'));
  assert.ok(!html.includes('Related Tool Call'));
});
test("ordinary call details have no Risk Library row", () => {
  const html = renderToStaticMarkup(React.createElement(DetailPanel, {view: {...view, toolCalls: [call]}, utc: true, detail: {kind: "call", id: call.tool_call_id}}));
  assert.ok(!html.includes('Risk Library'));
});
