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
import { ALL_SESSIONS, listedSessions, rowTotals, selectView, viewTotals } from "../dashboard-model/view.js";
import {
  NO_FILTERS, filterOptions, filterSessions, localZoneName, narrowView, projectName, runtimeLabel, shortSessionId, timeAgo,
  type DashboardFilters,
} from "../dashboard-model/index.js";
import type { SessionRow } from "../dashboard-model/view.js";
import { useSnapshot } from "./useSnapshot.js";
import { Logo } from "./components/Logo.js";
import { DetailPanel, RiskEvents, SessionDetails, StatsRow, Timeline, type Detail } from "./components/Panels.js";
import { ConnectionTree, CredentialLedger, FileEventsPanel, FilterBar, ToolCallsPanel } from "./components/Views.js";

// Per-browser preferences. Never sent anywhere; a page that cannot store
// them (a private window) simply starts from the defaults each time.
const TZ_KEY = "omnodex_tz";
const THEME_KEY = "omnodex_theme";
const HIDDEN_KEY = "omnodex_hidden_sessions";

function readStored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage refused; the choice lasts for this page.
  }
}

function readHidden(): string[] {
  try {
    const v = JSON.parse(readStored(HIDDEN_KEY) ?? "[]") as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

type ThemeMode = "system" | "light" | "dark";
const NEXT_THEME: Record<ThemeMode, ThemeMode> = { system: "light", light: "dark", dark: "system" };
const THEME_LABEL: Record<ThemeMode, string> = { system: "System", light: "Light", dark: "Dark" };

function readTheme(): ThemeMode {
  const v = readStored(THEME_KEY);
  return v === "light" || v === "dark" ? v : "system";
}

/** Applies a theme to the page, following the system setting in "system" mode. */
function useTheme(mode: ThemeMode): void {
  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: light)");
    const apply = () => {
      const light = mode === "light" || (mode === "system" && media.matches);
      document.documentElement.setAttribute("data-theme", light ? "light" : "dark");
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [mode]);
}

function sessionOptionLabel(s: SessionRow): string {
  const prefix = s.status === "in_progress" ? "● " : "";
  const source = s.interceptor ? `[${runtimeLabel(s)}] ` : "";
  const name = projectName(s.project_path) || shortSessionId(s.session_id);
  const when = s.last_event_at ? `  ·  ${timeAgo(s.last_event_at)}` : "";
  return prefix + source + name + when;
}

function Header({ utc, setUtc, live, theme, setTheme }: {
  utc: boolean; setUtc: (v: boolean) => void; live: boolean; theme: ThemeMode; setTheme: (t: ThemeMode) => void;
}): React.JSX.Element {
  const zone = localZoneName() ?? "Local";
  return (
    <header>
      <div className="logo"><Logo /></div>
      <div className="header-meta">dashboard</div>
      <div className="header-controls">
        <button className="theme-btn" onClick={() => setTheme(NEXT_THEME[theme])} title="Theme: system, light or dark">
          {THEME_LABEL[theme]}
        </button>
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
  const [utc, setUtcState] = useState(() => readStored(TZ_KEY) === "utc");
  const [theme, setThemeState] = useState<ThemeMode>(readTheme);
  const [filters, setFilters] = useState<DashboardFilters>(() => ({ ...NO_FILTERS, hidden: readHidden() }));
  const [selection, setSelection] = useState<string | null>(null);
  const [detail, setDetail] = useState<Detail>(null);
  useTheme(theme);

  const setUtc = (value: boolean) => {
    setUtcState(value);
    writeStored(TZ_KEY, value ? "utc" : "local");
  };
  const setTheme = (mode: ThemeMode) => {
    setThemeState(mode);
    writeStored(THEME_KEY, mode);
  };
  const updateFilters = (next: DashboardFilters) => {
    setFilters(next);
    if (next.hidden !== filters.hidden) writeStored(HIDDEN_KEY, JSON.stringify(next.hidden));
    setDetail(null);
  };
  const toggleHidden = (sessionId: string) => {
    const hidden = filters.hidden.includes(sessionId) ? filters.hidden.filter((id) => id !== sessionId) : [...filters.hidden, sessionId];
    updateFilters({ ...filters, hidden });
  };

  // Recomputed each render: the time range is relative to now.
  const now = Date.now();
  const options = useMemo(() => filterOptions(snapshot.sessions), [snapshot]);
  const filtered = useMemo(() => ({ ...snapshot, sessions: filterSessions(snapshot.sessions, filters, now) }), [snapshot, filters, now]);
  const listed = useMemo(() => listedSessions(filtered), [filtered]);
  const hiddenCount = useMemo(() => snapshot.sessions.filter((s) => filters.hidden.includes(s.session_id)).length, [snapshot, filters.hidden]);

  // Start on all sessions; keep a single session while the filters still show it.
  useEffect(() => {
    if (selection !== null && selection !== ALL_SESSIONS && !listed.some((s) => s.session_id === selection)) setSelection(ALL_SESSIONS);
    if (selection === null && snapshot.sessions.length > 0) setSelection(ALL_SESSIONS);
  }, [snapshot, listed, selection]);

  const selected = useMemo(() => selectView(filtered, selection ?? ALL_SESSIONS), [filtered, selection]);
  const view = useMemo(() => narrowView(selected, filters, now), [selected, filters, now]);
  // The graph keeps its full shape while a node is selected, so the selection
  // can be moved or cleared from it.
  const graphView = useMemo(() => narrowView(selected, { ...filters, graph: null }, now), [selected, filters, now]);
  // Session totals unless a time range or graph selection covers part of a session.
  const totals = filters.time !== "all" || filters.graph ? rowTotals(view) : viewTotals(view.sessions);

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
            value={selection ?? ALL_SESSIONS}
            onChange={(e) => {
              setSelection(e.target.value);
              setDetail(null);
            }}
          >
            <option value={ALL_SESSIONS}>▶ All Sessions ({listed.length})</option>
            {listed.map((s) => (
              <option key={s.session_id} value={s.session_id}>
                {filters.hidden.includes(s.session_id) ? "(hidden) " : ""}{sessionOptionLabel(s)}
              </option>
            ))}
          </select>
        </div>
        <FilterBar filters={filters} options={options} hiddenCount={hiddenCount} onChange={updateFilters} />
        <SessionDetails
          view={view}
          utc={utc}
          hidden={view.session ? filters.hidden.includes(view.session.session_id) : false}
          onToggleHidden={toggleHidden}
        />
        <StatsRow view={view} totals={totals} />
        <div className="panels">
          <ConnectionTree view={graphView} graph={filters.graph} onSelect={(graph) => updateFilters({ ...filters, graph })} />
          <RiskEvents view={view} utc={utc} detail={detail} onSelect={setDetail} />
          <Timeline view={view} sessions={snapshot.sessions} utc={utc} detail={detail} newCallIds={newCallIds} onSelect={setDetail} />
          <CredentialLedger view={view} utc={utc} onSelect={setDetail} />
          <FileEventsPanel view={view} utc={utc} />
          <ToolCallsPanel view={view} utc={utc} detail={detail} onSelect={setDetail} />
          <DetailPanel view={view} utc={utc} detail={detail} />
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="app">
        <Header utc={utc} setUtc={setUtc} live={live} theme={theme} setTheme={setTheme} />
        {main}
      </div>
      <footer className="page-footer">© 2026 Omnodex, LLC. All rights reserved.</footer>
    </>
  );
}
