// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

/**
 * The analyzer as the dashboard page needs it in the browser: the credential
 * patterns and matcher only. The build points "@omnodex/analyzer" here so the
 * page never pulls in the analyzer's Node-only modules.
 */

export { findCredentials } from "../../../analyzer/src/conditions/credential-match.js";
export { CREDENTIAL_PATTERNS } from "../../../analyzer/src/rules/community/credential-in-params.js";
