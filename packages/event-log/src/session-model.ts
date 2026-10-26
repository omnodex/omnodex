// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * Session models for hook shims.
 *
 * Some platforms name the model in every hook payload; others only in their
 * own files. A shim checks it at turn boundaries and emits
 * `session.model_changed` only when it differs from the last model it
 * recorded for the session, so the event log gains one event per change
 * rather than one per turn. A model that session.started already carries is
 * recorded without an event.
 *
 * Only what the platform reports is recorded: the model is never probed.
 *
 * The last recorded model lives in <home>/session-models/<session>.json.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import type { InterceptorKind, SessionModelChangedEvent } from "@omnodex/shared";
import { SCHEMA_VERSION } from "@omnodex/shared";

/** Models longer than this are not a model name; they are ignored. */
const MAX_MODEL_LENGTH = 128;

export interface SessionModelOptions {
  home: string;
  sessionId: string;
  interceptor: InterceptorKind;
  source: SessionModelChangedEvent["source"];
  newEventId: () => string;
  nowIso?: () => string;
  /** session.started in the same batch already carries this model. */
  announced?: boolean;
}

/** Trimmed, or null when it is not a usable model name. */
export function cleanModel(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const model = value.trim();
  if (!model || model.length > MAX_MODEL_LENGTH || /[\r\n]/.test(model)) return null;
  return model;
}

function statePath(home: string, sessionId: string): string {
  return path.join(home, "session-models", `${sessionId.replace(/[^a-zA-Z0-9_.-]/g, "_")}.json`);
}

/**
 * A `session.model_changed` event when `reported` is a new model for the
 * session, otherwise null. Records it either way. Never throws: a model is
 * not worth failing a hook.
 */
export async function sessionModelChangedIfChanged(
  reported: unknown,
  options: SessionModelOptions,
): Promise<SessionModelChangedEvent | null> {
  const model = cleanModel(reported);
  if (!model || !options.sessionId) return null;
  let previous: string | undefined;
  try {
    const file = statePath(options.home, options.sessionId);
    try {
      const last = JSON.parse(await fs.readFile(file, "utf8")) as { model?: unknown };
      if (typeof last.model === "string") previous = last.model;
    } catch {
      // No model recorded yet.
    }
    if (previous === model) return null;
    await fs.mkdir(path.dirname(file), { recursive: true });
    await fs.writeFile(file, JSON.stringify({ model }), "utf8");
  } catch {
    return null;
  }
  if (previous === undefined && options.announced) return null;
  const now = (options.nowIso ?? (() => new Date().toISOString()))();
  return {
    schema_version: SCHEMA_VERSION,
    event_id: options.newEventId(),
    event_type: "session.model_changed",
    session_id: options.sessionId,
    occurred_at: now,
    recorded_at: now,
    interceptor: options.interceptor,
    model,
    ...(previous !== undefined ? { previous } : {}),
    source: options.source,
  };
}
