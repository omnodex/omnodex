// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/feature-extractor -- transport
 *
 * Pluggable transport for submitting anonymized feature batches to the
 * Omnodex cloud API. The default HttpFeatureTransport calls
 * POST /api/v1/features/submit; tests use a mock.
 */

import type { FeatureBatch } from "@omnodex/shared";

export interface FeatureSubmitResponse {
  /** Server-generated receipt ID for audit trail. */
  receipt_id: string;
  /** Anomaly score if available (async scoring returns null). */
  anomaly_score: number | null;
}

/** Transport interface for feature batch submission. */
export interface FeatureTransport {
  submit(batch: FeatureBatch): Promise<FeatureSubmitResponse>;
}

export interface HttpFeatureTransportOptions {
  /** Base URL for the cloud API (e.g. "https://api.omnodex.com"). */
  baseUrl: string;
  /** API token for authentication. */
  apiToken: string;
  /** Request timeout in ms. Default: 15000. */
  timeoutMs?: number;
}

/**
 * HTTP transport that calls POST /api/v1/features/submit on the cloud API.
 */
export class HttpFeatureTransport implements FeatureTransport {
  private readonly baseUrl: string;
  private readonly apiToken: string;
  private readonly timeoutMs: number;

  constructor(options: HttpFeatureTransportOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiToken = options.apiToken;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  async submit(batch: FeatureBatch): Promise<FeatureSubmitResponse> {
    const url = this.baseUrl + "/api/v1/features/submit";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + this.apiToken,
        },
        body: JSON.stringify(batch),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(
          "feature submit failed: HTTP " + res.status + " " + text.slice(0, 200),
        );
      }

      return (await res.json()) as FeatureSubmitResponse;
    } finally {
      clearTimeout(timer);
    }
  }
}
