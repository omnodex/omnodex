// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
export { evaluatePathMatch, extractPaths } from "./path-match.js";
export { evaluateCredentialMatch, findCredentialTypes } from "./credential-match.js";
export { evaluateOutboundCall, isOutboundCall } from "./outbound-call.js";
export { evaluateIpDestination, extractRawIps, isInKnownCidrs } from "./ip-destination.js";
export { evaluateToolNameMatch } from "./tool-name-match.js";
export { evaluateSessionFirstSeen } from "./session-first-seen.js";

export { evaluateRateThreshold, createRateThresholdState, type RateThresholdState } from "./rate-threshold.js";
export { evaluateDomainMatch, extractDomains } from "./domain-match.js";

export { evaluateCwdBoundary } from "./cwd-boundary.js";
