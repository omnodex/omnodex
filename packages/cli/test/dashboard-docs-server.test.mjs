// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DashboardServer } from "../dist/dashboard-server.js";
import { InMemoryReadModelStore } from "../../projection/dist/index.js";

async function page(options) {
  const assetsDir = await mkdtemp(join(tmpdir(), "omnodex-docs-host-"));
  await writeFile(join(assetsDir, "dashboard.html"), '<!doctype html><head><title>Dashboard</title></head><body>test</body>');
  const server = new DashboardServer({store: new InMemoryReadModelStore(), port: 0, assetsDir, ...options});
  try {
    await server.ready;
    const response = await fetch('http://127.0.0.1:' + server.port);
    assert.equal(response.status, 200);
    return await response.text();
  } finally {
    await server.close();
    await rm(assetsDir, {recursive: true, force: true});
  }
}
test("configured docs host is available in page metadata before its scripts", async () => {
  const html = await page({docsHost: 'https://docs.example.com/white-label/'});
  assert.ok(html.includes('<meta name="omnodex-docs-host" content="https://docs.example.com/white-label/">'));
  assert.ok(html.indexOf('omnodex-docs-host') < html.indexOf('</head>'));
});
test("OMNODEX_DOCS_HOST is read at startup and an explicit option takes precedence", async () => {
  const previous = process.env.OMNODEX_DOCS_HOST;
  process.env.OMNODEX_DOCS_HOST = 'http://localhost:4321/docs';
  try {
    assert.ok((await page({})).includes('content="http://localhost:4321/docs/"'));
    assert.ok((await page({docsHost: 'https://tenant.example/'})).includes('content="https://tenant.example/"'));
  } finally {
    if (previous === undefined) delete process.env.OMNODEX_DOCS_HOST;
    else process.env.OMNODEX_DOCS_HOST = previous;
  }
});
test("unsafe docs host cannot inject markup or create executable links", async () => {
  const html = await page({docsHost: 'javascript:alert(1)"/><script>bad</script>'});
  assert.ok(!html.includes('javascript:'));
  assert.ok(!html.includes('<script>'));
  assert.ok(!html.includes('omnodex-docs-host'));
});
