// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

/**
 * The local dashboard page, served by `omnodex dashboard` as one static file.
 * Reads the collapsed read model from /api/snapshot and reloads it when the
 * server announces a change.
 */

import React, { useEffect, useMemo, useState } from "react";
import { ALL_SESSIONS, listedSessions, selectView } from "../dashboard-model/view.js";
import { localZoneName, projectName, runtimeLabel, shortSessionId, timeAgo } from "../dashboard-model/index.js";
import type { SessionRow } from "../dashboard-model/view.js";
import { useSnapshot } from "./useSnapshot.js";
import { Logo } from "./components/Logo.js";
import {
  ConnectionGraph, CredentialLedger, DetailPanel, RiskEvents, SessionDetails, StatsRow, Timeline, type Detail,
} from "./components/Panels.js";

const TZ_KEY = "omnodex_tz";

function readUtcPreference(): boolean {
  try {
    return localStorage.getItem(TZ_KEY) === "utc";
  } catch {
    return false;
  }
}

function sessionOptionLabel(s: SessionRow): string {
  const prefix = s.status === "in_progress" ? "● " : "";
  const source = s.interceptor ? `[${runtimeLabel(s)}] ` : "";
  const name = projectName(s.project_path) || shortSessionId(s.session_id);
  const when = s.last_event_at ? `  ·  ${timeAgo(s.last_event_at)}` : "";
  return prefix + source + name + when;
}

function Header({ utc, setUtc, live }: { utc: boolean; setUtc: (v: boolean) => void; live: boolean }): React.JSX.Element {
  const zone = localZoneName() ?? "Local";
  return (
    <header>
      <div className="logo"><Logo /></div>
      <div className="header-meta">dashboard</div>
      <div style={{ display: "flex", alignItems: "center" }}>
        <div className="tz-toggle">
          <button className={utc ? "tz-btn" : "tz-btn active"} onClick={() => setUtc(false)}>{zone}</button>
          <button className={utc ? "tz-btn active" : "tz-btn"} onClick={() => setUtc(true)}>UTC</button>
        </div>
        <div className={`live-badge ${live ? "live" : "offline"}`} title="Real-time detection status">
          <span className="live-dot" />
          <span className="live-label">{live ? "LIVE" : "OFFLINE"}</span>
        </div>
      </div>
    </header>
  );
}

export function App(): React.JSX.Element {
  const { snapshot, loading, error, live, newCallIds } = useSnapshot();
  const [utc, setUtcState] = useState(readUtcPreference);
  const [selection, setSelection] = useState<string | null>(null);
  const [detail, setDetail] = useState<Detail>(null);

  const setUtc = (value: boolean) => {
    setUtcState(value);
    try {
      localStorage.setItem(TZ_KEY, value ? "utc" : "local");
    } catch {
      // Private windows can refuse storage; the choice lasts for this page.
    }
  };

  const listed = useMemo(() => listedSessions(snapshot), [snapshot]);

  // Start on all sessions; keep the choice while it still exists.
  useEffect(() => {
    if (snapshot.sessions.length === 0) return;
    const stillThere = selection === ALL_SESSIONS
      ? listed.length > 0
      : selection !== null && snapshot.sessions.some((s) => s.session_id === selection);
    if (!stillThere) setSelection(listed.length > 0 ? ALL_SESSIONS : snapshot.sessions[0]!.session_id);
  }, [snapshot, listed, selection]);

  const view = useMemo(() => selectView(snapshot, selection ?? ALL_SESSIONS), [snapshot, selection]);

  let main: React.ReactNode;
  if (loading) {
    main = <div className="loading"><span>Loading sessions...</span></div>;
  } else if (error && snapshot.sessions.length === 0) {
    main = <div className="loading"><div style={{ color: "var(--red)" }}>Failed to load: {error}</div></div>;
  } else if (snapshot.sessions.length === 0) {
    main = (
      <div className="loading">
        <div className="empty-state">
          <div className="icon">📭</div>
          No sessions found. Run <code style={{ color: "var(--cyan)" }}>omnodex spike</code> to generate demo data, then refresh.
        </div>
      </div>
    );
  } else {
    main = (
      <div>
        <div className="session-bar">
          <label htmlFor="session-select">Session</label>
          <select
            id="session-select"
            value={selection ?? ""}
            onChange={(e) => {
              setSelection(e.target.value);
              setDetail(null);
            }}
          >
            {listed.length > 0 && <option value={ALL_SESSIONS}>▶ All Sessions ({listed.length})</option>}
            {listed.map((s) => <option key={s.session_id} value={s.session_id}>{sessionOptionLabel(s)}</option>)}
          </select>
        </div>
        <SessionDetails view={view} utc={utc} />
        <StatsRow view={view} />
        <div className="panels">
          <ConnectionGraph view={view} sessions={snapshot.sessions} />
          <CredentialLedger view={view} onSelect={setDetail} />
          <RiskEvents view={view} utc={utc} detail={detail} onSelect={setDetail} />
          <Timeline view={view} sessions={snapshot.sessions} utc={utc} detail={detail} newCallIds={newCallIds} onSelect={setDetail} />
          <DetailPanel view={view} utc={utc} detail={detail} />
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="app">
        <Header utc={utc} setUtc={setUtc} live={live} />
        {main}
      </div>
      <footer className="page-footer">© 2026 Omnodex, LLC. All rights reserved.</footer>
    </>
  );
}
