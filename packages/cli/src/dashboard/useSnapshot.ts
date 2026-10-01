// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * The page's data: /api/snapshot, reloaded shortly after any change the
 * server announces on /api/events. The snapshot is already collapsed, so a
 * reload settles every panel on the numbers a fresh load would show.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReadModelSnapshot } from "../dashboard-model/view.js";

const EMPTY: ReadModelSnapshot = { sessions: [], tool_calls: {}, file_events: {}, risk_events: {} };
/** How long after a change to reload: long enough to batch a burst of events. */
const RELOAD_DELAY_MS = 250;
const RETRY_MS = 3000;
/** How long a newly arrived call stays highlighted. */
const NEW_ARRIVAL_MS = 1500;

export interface SnapshotState {
  snapshot: ReadModelSnapshot;
  loading: boolean;
  error: string | null;
  /** True while the live event stream is connected. */
  live: boolean;
  /** Tool calls that arrived in the latest reload, for a brief highlight. */
  newCallIds: ReadonlySet<string>;
}

function callIds(snapshot: ReadModelSnapshot): Set<string> {
  const ids = new Set<string>();
  for (const rows of Object.values(snapshot.tool_calls)) for (const row of rows) ids.add(row.tool_call_id);
  return ids;
}

export function useSnapshot(): SnapshotState {
  const [state, setState] = useState<SnapshotState>({
    snapshot: EMPTY, loading: true, error: null, live: false, newCallIds: new Set(),
  });
  const known = useRef<Set<string> | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/snapshot");
      if (!res.ok) throw new Error(`API ${res.status}`);
      const snapshot = (await res.json()) as ReadModelSnapshot;
      const ids = callIds(snapshot);
      const previous = known.current;
      const fresh = previous ? new Set([...ids].filter((id) => !previous.has(id))) : new Set<string>();
      known.current = ids;
      setState((s) => ({ ...s, snapshot, loading: false, error: null, newCallIds: fresh }));
      if (fresh.size > 0) {
        setTimeout(() => setState((s) => (s.newCallIds === fresh ? { ...s, newCallIds: new Set() } : s)), NEW_ARRIVAL_MS);
      }
    } catch (err) {
      setState((s) => ({ ...s, loading: false, error: err instanceof Error ? err.message : String(err) }));
    }
  }, []);

  useEffect(() => {
    void load();
    let source: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let reload: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      source = new EventSource("/api/events");
      source.onopen = () => setState((s) => ({ ...s, live: true }));
      source.onerror = () => {
        setState((s) => ({ ...s, live: false }));
        source?.close();
        source = null;
        if (!closed && !retry) {
          retry = setTimeout(() => {
            retry = null;
            connect();
            // Catch up on anything missed while disconnected.
            void load();
          }, RETRY_MS);
        }
      };
      source.onmessage = (evt) => {
        let type: string | undefined;
        try {
          type = (JSON.parse(evt.data) as { type?: string }).type;
        } catch {
          return;
        }
        if (type === "heartbeat" || type === "connected") return;
        if (reload) clearTimeout(reload);
        reload = setTimeout(() => {
          reload = null;
          void load();
        }, RELOAD_DELAY_MS);
      };
    };
    connect();

    return () => {
      closed = true;
      source?.close();
      if (retry) clearTimeout(retry);
      if (reload) clearTimeout(reload);
    };
  }, [load]);

  return state;
}
