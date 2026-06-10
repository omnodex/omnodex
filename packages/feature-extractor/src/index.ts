// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
export { FeatureExtractor } from "./feature-extractor.js";
export type { FeatureExtractorOptions, ExtractionResult } from "./feature-extractor.js";

export { extractSessionFeatures } from "./extractor.js";
export type { ExtractionInput } from "./extractor.js";

export { importHmacKey, hmacSha256, hmacBatch, generateLocalSalt } from "./hasher.js";

export { HttpFeatureTransport } from "./transport.js";
export type {
  FeatureTransport,
  FeatureSubmitResponse,
  HttpFeatureTransportOptions,
} from "./transport.js";
