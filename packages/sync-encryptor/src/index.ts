// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
export { SyncEncryptor } from "./sync-encryptor.js";
export type { SyncEncryptorOptions, SyncResult } from "./sync-encryptor.js";

export { deriveKey, encrypt, decrypt, sha256Hex, randomSalt, randomIv, KDF_PARAMS } from "./crypto.js";

export { serializeReadModel, encodePayload } from "./serializer.js";
export type { SyncPayload } from "./serializer.js";

export { HttpSyncTransport } from "./transport.js";
export type {
  SyncTransport,
  SyncPushRequest,
  SyncPushResponse,
  HttpSyncTransportOptions,
} from "./transport.js";
