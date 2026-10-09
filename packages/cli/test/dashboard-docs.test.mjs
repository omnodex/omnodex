// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_DOCS_HOST, riskLibraryUrl } from "../dist/dashboard-model/docs.js";

test("risk links use the stable community and advanced rule routes", () => {
  for (const id of ["RULE_SENSITIVE_PATH_READ", "RULE_ADV_CREDENTIAL_READ_THEN_OUTBOUND", "RULE_CUSTOM_NOT_IN_LIBRARY"]) {
    assert.equal(riskLibraryUrl(id), DEFAULT_DOCS_HOST + "risk-library/rule/" + id);
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
