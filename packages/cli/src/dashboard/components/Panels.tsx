// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import React, { useEffect, useRef } from "react";
import {
  displayStatus,
  formatRisk,
  formatTime,
  formatWithTz,
  interceptorTone,
  riskBandLabel,
  runtimeLabel,
  sessionName,
  sourcesLabel,
  timeAgo,
  parseParameters,
  type SourceTone,
  type ViewTotals,
} from "../../dashboard-model/index.js";
import { ParamView } from "./Views.js";
import type { CollapsedToolCallRow, RiskEventRow, SessionRow, SessionView } from "../../dashboard-model/view.js";

/** What the detail panel shows: a tool call, or a finding. */
export type Detail = { kind: "call"; id: string } | { kind: "risk"; event: RiskEventRow } | null;

const BAND_COLOR: Record<string, string> = {
  CRITICAL: "var(--red)", HIGH: "var(--orange)", MEDIUM: "var(--yellow)", LOW: "var(--mint)",
};

function toneStyle(tone: SourceTone): React.CSSProperties {
  return { background: `var(--${tone}-dim)`, color: `var(--${tone})` };
}

function SourceBadge({ session }: { session: SessionRow | null | undefined }): React.JSX.Element {
  if (!session?.interceptor) return <span className="source-badge" style={toneStyle("slate")}>unknown</span>;
  return <span className="source-badge" style={toneStyle(interceptorTone(session.interceptor))}>{runtimeLabel(session)}</span>;
}

function Row({ label, mono, children }: { label: string; mono?: boolean; children: React.ReactNode }): React.JSX.Element {
  return (
    <div className="sd-row">
      <span className="sd-label">{label}</span>
      <span className={mono ? "sd-value sd-mono" : "sd-value"}>{children}</span>
    </div>
  );
}

const STATUS_COLOR: Record<string, string> = {
  in_progress: "var(--mint)", errored: "var(--red)", interrupted: "var(--yellow)",
};

export function SessionDetails({ view, utc, hidden, onToggleHidden }: {
  view: SessionView; utc: boolean; hidden?: boolean; onToggleHidden?: (sessionId: string) => void;
}): React.JSX.Element {
  const s = view.session;
  if (!s) {
    const counts = new Map<string, { n: number; session: SessionRow }>();
    const servers = new Set<string>();
    let latest = "";
    for (const ss of view.sessions) {
      const label = runtimeLabel(ss);
      const entry = counts.get(label);
      if (entry) entry.n += 1;
      else counts.set(label, { n: 1, session: ss });
      for (const srv of ss.mcp_servers ?? []) servers.add(srv);
      if (ss.last_event_at && ss.last_event_at > latest) latest = ss.last_event_at;
    }
    return (
      <div className="session-details">
        <div className="sd-col">
          <Row label="Sessions">{view.sessions.length} total</Row>
          <Row label="Types">
            {[...counts].map(([label, { n, session }]) => (
              <span key={label} className="source-badge" style={{ ...toneStyle(interceptorTone(session.interceptor)), marginRight: 6 }}>
                {label} ({n})
              </span>
            ))}
          </Row>
        </div>
        <div className="sd-col">
          <Row label="Last Event">{latest ? `${formatWithTz(latest, utc)} (${timeAgo(latest)})` : "n/a"}</Row>
          {servers.size > 0 && <Row label="MCP Servers" mono>{[...servers].sort().join(", ")}</Row>}
        </div>
      </div>
    );
  }

  const transports = new Map((s.mcp_server_transports ?? []).map((t) => [t.name, t]));
  const serverText = (s.mcp_servers ?? [])
    .map((name) => {
      const t = transports.get(name);
      return t ? `${name} (${t.transport}${t.host ? `: ${t.host}` : ""})` : name;
    })
    .join(", ");
  return (
    <div className="session-details">
      <div className="sd-col">
        {s.title && <Row label="Title">{s.title}</Row>}
        <Row label="Session ID" mono>{s.session_id}</Row>
        <Row label="Type"><SourceBadge session={s} /></Row>
        <Row label="Status">
          <span style={{ color: STATUS_COLOR[s.status] ?? "var(--slate)" }}>{displayStatus(s.status)}</span>
          {onToggleHidden && (
            <button className="filter-link hide-btn" onClick={() => onToggleHidden(s.session_id)} title="Hidden sessions stay in your data; this browser just leaves them out">
              {hidden ? "Unhide session" : "Hide session"}
            </button>
          )}
        </Row>
        <Row label="User">{s.user}</Row>
        {s.project_path && <Row label="Project" mono>{s.project_path}</Row>}
      </div>
      <div className="sd-col">
        <Row label="Started">{formatWithTz(s.started_at, utc)}</Row>
        <Row label="Last Event">{s.last_event_at ? `${formatWithTz(s.last_event_at, utc)} (${timeAgo(s.last_event_at)})` : "n/a"}</Row>
        {serverText && <Row label="MCP Servers" mono>{serverText}</Row>}
      </div>
    </div>
  );
}

function StatCard({ label, value, tone, sub }: { label: string; value: React.ReactNode; tone: string; sub: React.ReactNode }): React.JSX.Element {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${tone}`}>{value}</div>
      <div className="stat-sub">{sub}</div>
    </div>
  );
}

export function StatsRow({ view, totals }: { view: SessionView; totals: ViewTotals }): React.JSX.Element {
  const t = totals;
  const band = riskBandLabel(t.risk);
  const s = view.session;
  return (
    <div className="stats-row">
      <StatCard label="Tool Calls" value={t.toolCalls} tone="cyan" sub={`${t.mcpServers} MCP servers`} />
      <StatCard label="File Reads" value={t.fileReads} tone="mint" sub={`${t.fileWrites} writes`} />
      <StatCard label="Risk Score" value={formatRisk(t.risk)} tone="orange" sub={<span style={{ color: BAND_COLOR[band] }}>{band}</span>} />
      {s ? (
        <StatCard label="Duration" value={s.duration_ms != null ? `${(s.duration_ms / 1000).toFixed(1)}s` : "active"} tone="cyan" sub={displayStatus(s.status)} />
      ) : (
        <StatCard label="Sessions" value={t.sessions} tone="cyan" sub="in view" />
      )}
    </div>
  );
}

function Panel({ title, badge, badgeTone, full, scroll, children }: {
  title: string; badge?: string; badgeTone?: SourceTone | "red"; full?: boolean; scroll?: boolean; children: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className={full ? "panel panel-full" : "panel"}>
      <div className="panel-header">
        <div className="panel-title">{title}</div>
        {badge !== undefined && (
          <div className="panel-badge" style={{ background: `var(--${badgeTone}-dim)`, color: `var(--${badgeTone})` }}>{badge}</div>
        )}
      </div>
      <div className={scroll ? "panel-body-scroll" : "panel-body"}>{children}</div>
    </div>
  );
}

function Empty({ icon, children }: { icon: string; children: React.ReactNode }): React.JSX.Element {
  return <div className="empty-state"><div className="icon">{icon}</div>{children}</div>;
}

function riskKey(r: RiskEventRow): string {
  return `${r.rule_id}::${r.related_event_id}`;
}

export function RiskEvents({ view, utc, detail, onSelect }: {
  view: SessionView; utc: boolean; detail: Detail; onSelect: (d: Detail) => void;
}): React.JSX.Element {
  const selectedCall = detail?.kind === "call" ? detail.id : detail?.kind === "risk" ? detail.event.related_event_id : null;
  const selectedRisk = detail?.kind === "risk" ? riskKey(detail.event) : null;
  return (
    <Panel title="Risk Events" badge={`${view.riskEvents.length} flagged`} badgeTone="red" scroll>
      {view.riskEvents.length === 0 ? (
        <Empty icon="✅">No risk events detected in this session.</Empty>
      ) : (
        <ul className="risk-list">
          {view.riskEvents.map((r) => {
            const selected = selectedRisk ? selectedRisk === riskKey(r) : selectedCall === r.related_event_id;
            return (
              <li key={riskKey(r)} className={selected ? "risk-item selected" : "risk-item"} onClick={() => onSelect({ kind: "risk", event: r })}>
                <span className={`severity-badge severity-${r.severity}`}>{r.severity}</span>
                <div>
                  <div className="risk-desc">{r.description}</div>
                  <div className="risk-meta">{r.category} / {r.rule_id} / {formatTime(r.detected_at, utc)}</div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

export function Timeline({ view, sessions, utc, detail, newCallIds, onSelect }: {
  view: SessionView; sessions: readonly SessionRow[]; utc: boolean; detail: Detail;
  newCallIds: ReadonlySet<string>; onSelect: (d: Detail) => void;
}): React.JSX.Element {
  const flagged = new Set(view.riskEvents.map((r) => r.related_event_id));
  const selected = detail?.kind === "call" ? detail.id : detail?.kind === "risk" ? detail.event.related_event_id : null;
  const bySession = new Map(sessions.map((s) => [s.session_id, s]));
  const selectedRef = useRef<HTMLLIElement>(null);
  useEffect(() => {
    if (detail?.kind === "risk") selectedRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [detail]);

  return (
    <Panel title="Event Timeline" badge={`${view.toolCalls.length} calls`} badgeTone="mint" scroll>
      {view.toolCalls.length === 0 ? (
        <Empty icon="⏳">No tool calls in this session.</Empty>
      ) : (
        <ul className="timeline">
          {view.toolCalls.map((tc) => {
            const isFlagged = flagged.has(tc.tool_call_id);
            const isSelected = selected === tc.tool_call_id;
            const owner = view.session ? null : bySession.get(tc.session_id);
            const classes = ["timeline-item", isFlagged && "risk-flagged", isSelected && "selected", newCallIds.has(tc.tool_call_id) && "new-arrival"]
              .filter(Boolean).join(" ");
            return (
              <li key={tc.tool_call_id} ref={isSelected ? selectedRef : undefined} className={classes} onClick={() => onSelect({ kind: "call", id: tc.tool_call_id })}>
                <div className="timeline-time">{formatTime(tc.started_at, utc)}</div>
                <div className="timeline-content">
                  {owner && (
                    <span className="timeline-session-badge" style={toneStyle(interceptorTone(owner.interceptor))}>
                      {sessionName(owner)}
                    </span>
                  )}
                  <span className="timeline-tool">{tc.tool_name}</span>
                  <span className="timeline-server">{tc.mcp_server}</span>
                  <span className={`timeline-status ${tc.status || "in_progress"}`}>{tc.status}</span>
                  {isFlagged && <span className="risk-flag-icon" title="Risk event flagged">⚠️</span>}
                  {tc.duration_ms != null && <div className="timeline-detail">{tc.duration_ms}ms / {tc.response_bytes || 0} bytes</div>}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }): React.JSX.Element {
  return <div className="detail-row"><div className="detail-key">{label}</div><div className="detail-val">{children}</div></div>;
}

const HEADING: React.CSSProperties = {
  fontFamily: "var(--mono)", fontSize: 12, textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 16,
};

function CallDetail({ tc, utc }: { tc: CollapsedToolCallRow; utc: boolean }): React.JSX.Element {
  return (
    <>
      <h4 style={{ ...HEADING, color: "var(--cyan)" }}>Tool Call Detail</h4>
      <DetailRow label="Tool Call ID">{tc.tool_call_id}</DetailRow>
      <DetailRow label="Tool">{tc.tool_name}</DetailRow>
      <DetailRow label="MCP Server">{tc.mcp_server}</DetailRow>
      {tc.sources && tc.sources.length > 1 && <DetailRow label="Observed by">{sourcesLabel(tc.sources)}</DetailRow>}
      <DetailRow label="Status"><span className={`timeline-status ${tc.status}`}>{tc.status}</span></DetailRow>
      <DetailRow label="Started">{formatWithTz(tc.started_at, utc)}</DetailRow>
      <DetailRow label="Ended">{tc.ended_at ? formatWithTz(tc.ended_at, utc) : "n/a"}</DetailRow>
      <DetailRow label="Duration">{tc.duration_ms != null ? `${tc.duration_ms} ms` : "n/a"}</DetailRow>
      <DetailRow label="Response">{tc.response_bytes != null ? `${tc.response_bytes} bytes` : "n/a"}</DetailRow>
      {tc.error_message && <DetailRow label="Error"><span style={{ color: "var(--red)" }}>{tc.error_message}</span></DetailRow>}
      <DetailRow label="Parameters"><ParamView node={parseParameters(tc.parameters_json)} raw={tc.parameters_json} /></DetailRow>
    </>
  );
}

export function DetailPanel({ view, utc, detail }: { view: SessionView; utc: boolean; detail: Detail }): React.JSX.Element {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (detail) box.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [detail]);
  const call = (id: string) => view.toolCalls.find((t) => t.tool_call_id === id);

  let body: React.ReactNode = <Empty icon="🔍">Click any tool call or risk event above to inspect its full context.</Empty>;
  if (detail?.kind === "call") {
    const tc = call(detail.id);
    if (tc) body = <CallDetail tc={tc} utc={utc} />;
  } else if (detail?.kind === "risk") {
    const r = detail.event;
    const related = call(r.related_event_id);
    body = (
      <>
        <h4 style={{ ...HEADING, color: "var(--cyan)" }}>Risk Event Detail</h4>
        <DetailRow label="Severity"><span className={`severity-badge severity-${r.severity}`}>{r.severity}</span></DetailRow>
        <DetailRow label="Category">{r.category}</DetailRow>
        <DetailRow label="Description">{r.description}</DetailRow>
        <DetailRow label="Rule">{r.rule_id}</DetailRow>
        <DetailRow label="Tier">{r.rule_tier === "advanced" ? "Advanced" : "Community"}</DetailRow>
        <DetailRow label="Detected">{formatWithTz(r.detected_at, utc)}</DetailRow>
        <DetailRow label="Related Event">{r.related_event_id}</DetailRow>
        {r.related_event_ids && r.related_event_ids.length > 1 && (
          <DetailRow label="Pattern">
            {r.related_event_ids.map((id) => {
              const c = call(id);
              return <div key={id}>{c ? `${c.tool_name} (${formatTime(c.started_at, utc)})` : id}</div>;
            })}
          </DetailRow>
        )}
        {related && (
          <div style={{ marginTop: 16, paddingTop: 16, borderTop: "1px solid var(--navy-border)" }}>
            <h4 style={{ ...HEADING, color: "var(--orange)", marginBottom: 12 }}>Related Tool Call</h4>
            <DetailRow label="Tool">{related.tool_name}</DetailRow>
            <DetailRow label="Server">{related.mcp_server}</DetailRow>
            <DetailRow label="Parameters"><ParamView node={parseParameters(related.parameters_json)} raw={related.parameters_json} /></DetailRow>
          </div>
        )}
      </>
    );
  }

  return (
    <div ref={box} className="panel panel-full">
      <div className="panel-header"><div className="panel-title">Event Detail</div></div>
      <div className="panel-body">{body}</div>
    </div>
  );
}
