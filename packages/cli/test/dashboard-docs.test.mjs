// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_DOCS_HOST, normalizeDocsHost, riskLibraryUrl } from "../dist/dashboard-model/docs.js";

test("risk links use the stable community and advanced rule routes", () => {
  for (const id of ["RULE_SENSITIVE_PATH_READ", "RULE_ADV_CREDENTIAL_READ_THEN_OUTBOUND", "RULE_CUSTOM_NOT_IN_LIBRARY"]) {
    assert.equal(riskLibraryUrl(id), DEFAULT_DOCS_HOST + "risk-library/rule/" + id);
  }
});
test("docs host supports white-label hosts, deployment paths, ports and loopback", () => {
  for (const [host, base] of [["https://docs.example.com", "https://docs.example.com/"], ["https://docs.example.com/beta///", "https://docs.example.com/beta/"], ["http://localhost:4321", "http://localhost:4321/"], ["http://[::1]:4321/docs", "http://[::1]:4321/docs/"]]) {
    assert.equal(normalizeDocsHost(host), base);
    assert.equal(riskLibraryUrl("RULE_X", host), base + "risk-library/rule/RULE_X");
  }
});
test("missing or unsafe docs hosts fall back to the configured default", () => {
  for (const host of [undefined, null, "", "  ", "not a URL", "//example.com", "javascript:alert(1)", "data:text/html,test", "file:///tmp/docs", "https://user:password@example.com", "https://example.com/?token=secret", "https://example.com/#fragment"]) {
    assert.equal(normalizeDocsHost(host), DEFAULT_DOCS_HOST);
  }
});
test("rule text cannot inject a query, fragment, or another path", () => {
  const id = 'custom/rule?payload=<script>#secret';
  const url = new URL(riskLibraryUrl(id));
  assert.equal(url.origin, "https://docs.omnodex.com");
  assert.equal(url.pathname, "/risk-library/rule/" + encodeURIComponent(id));
  assert.equal(url.search, "");
  assert.equal(url.hash, "");
});
test("empty and dot-segment rule IDs go to the rule index", () => {
  for (const id of ["", "  ", ".", ".."]) assert.equal(riskLibraryUrl(id), DEFAULT_DOCS_HOST + "risk-library/rule-index/");
});
