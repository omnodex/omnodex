// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * The analyzer as the dashboard page needs it in the browser: the credential
 * patterns and matcher only. The build points "@omnodex/analyzer" here so the
 * page never pulls in the analyzer's Node-only modules.
 */

export { findCredentials } from "../../../analyzer/src/conditions/credential-match.js";
export { CREDENTIAL_PATTERNS } from "../../../analyzer/src/rules/community/credential-in-params.js";
