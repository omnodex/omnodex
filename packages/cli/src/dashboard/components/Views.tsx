// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.

import React, { useEffect, useRef, useState } from "react";
import {
  TIME_RANGES,
  connectionTree,
  formatTime,
  formatWithTz,
  groupedLedger,
  isFiltered,
  sortCalls,
  type CallSortKey,
  type DashboardFilters,
  type GraphNode,
  type GraphPath,
  type ParamNode,
  type RiskFloor,
  type SortDir,
  type TimeRangeKey,
} from "../../dashboard-model/index.js";
import type { SessionRow, SessionView } from "../../dashboard-model/view.js";
import type { Detail } from "./Panels.js";

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

const TIME_LABELS: Record<TimeRangeKey, string> = {
  "1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", all: "All time",
};
const RISK_LABELS: Record<RiskFloor, string> = {
  any: "Any risk", LOW: "Low and above", MEDIUM: "Medium and above", HIGH: "High and above", CRITICAL: "Critical only",
};
const STATUS_LABELS: Record<string, string> = {
  in_progress: "Active", completed: "Completed", errored: "Errored", interrupted: "Interrupted",
};

function MultiSelect({ label, options, selected, onChange, display }: {
  label: string; options: string[]; selected: readonly string[]; onChange: (v: string[]) => void; display?: (v: string) => string;
}): React.JSX.Element {
  const summary = selected.length === 0 ? `All ${label}` : selected.length === 1 ? (display ?? String)(selected[0]!) : `${selected.length} ${label}`;
  return (
    <details className="filter-menu">
      <summary>{summary}</summary>
      <div className="filter-options">
        {options.map((o) => (
          <label key={o}>
            <input
              type="checkbox"
              checked={selected.includes(o)}
              onChange={(e) => onChange(e.target.checked ? [...selected, o] : selected.filter((s) => s !== o))}
            />
            {(display ?? String)(o)}
          </label>
        ))}
      </div>
    </details>
  );
}

export function FilterBar({ filters, options, hiddenCount, onChange }: {
  filters: DashboardFilters;
  options: { runtimes: string[]; statuses: string[]; roots: string[] };
  hiddenCount: number;
  onChange: (f: DashboardFilters) => void;
}): React.JSX.Element {
  const set = (patch: Partial<DashboardFilters>) => onChange({ ...filters, ...patch });
  const g = filters.graph;
  return (
    <div className="filter-bar" role="group" aria-label="Filters">
      <span>Filter</span>
      <MultiSelect label="runtimes" options={options.runtimes} selected={filters.runtimes} onChange={(runtimes) => set({ runtimes })} />
      <MultiSelect label="statuses" options={options.statuses} selected={filters.statuses} onChange={(statuses) => set({ statuses })} display={(s) => STATUS_LABELS[s] ?? s} />
      <select aria-label="Risk" value={filters.risk} onChange={(e) => set({ risk: e.target.value as RiskFloor })}>
        {(Object.keys(RISK_LABELS) as RiskFloor[]).map((k) => <option key={k} value={k}>{RISK_LABELS[k]}</option>)}
      </select>
      <select aria-label="Time range" value={filters.time} onChange={(e) => set({ time: e.target.value as TimeRangeKey })}>
        {(Object.keys(TIME_RANGES) as TimeRangeKey[]).map((k) => <option key={k} value={k}>{TIME_LABELS[k]}</option>)}
      </select>
      {options.roots.length > 1 && (
        <MultiSelect label="roots" options={options.roots} selected={filters.roots} onChange={(roots) => set({ roots })} />
      )}
      {g && (
        <button className="filter-chip" onClick={() => set({ graph: null })} title="Clear the graph selection">
          {[g.runtime, g.server, g.tool].filter(Boolean).join(" › ")} ✕
        </button>
      )}
      {hiddenCount > 0 && (
        <label>
          <input type="checkbox" checked={filters.showHidden} onChange={(e) => set({ showHidden: e.target.checked })} /> Show {hiddenCount} hidden
        </label>
      )}
      {isFiltered(filters) && (
        <button className="filter-link" onClick={() => onChange({ ...filters, runtimes: [], statuses: [], risk: "any", time: "all", roots: [], graph: null })}>
          Clear filters
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Connection tree
// ---------------------------------------------------------------------------

const CHAR_PX = 6.7;
const MAX_TOOLS = 5;

function fit(text: string, width: number): string {
  const max = Math.max(4, Math.floor(width / CHAR_PX));
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function samePath(a: GraphPath | null, b: GraphPath): boolean {
  return !!a && a.runtime === b.runtime && a.server === b.server && a.tool === b.tool;
}

interface Placed {
  node: GraphNode;
  x: number;
  y: number;
  w: number;
  h: number;
}

function serverHeight(n: GraphNode): number {
  const tools = Math.min(n.tools?.length ?? 0, MAX_TOOLS);
  const more = (n.tools?.length ?? 0) > MAX_TOOLS ? 1 : 0;
  return 38 + (tools + more) * 16;
}

export function ConnectionTree({ view, graph, onSelect }: {
  view: SessionView; graph: GraphPath | null; onSelect: (p: GraphPath | null) => void;
}): React.JSX.Element {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(900);
  useEffect(() => {
    const measure = () => setWidth(box.current?.clientWidth || 900);
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, []);

  const tree = connectionTree(view.sessions, view.toolCalls);
  const runtimeW = Math.min(240, Math.max(160, width * 0.24));
  const serverX = runtimeW + Math.min(160, width * 0.12) + 16;
  const serverW = Math.max(220, Math.min(460, width - serverX - 16));

  const runtimes: Placed[] = [];
  const servers: Array<Placed & { parent: Placed }> = [];
  let y = 16;
  for (const rt of tree) {
    const start = y;
    const placed: Placed[] = [];
    for (const child of rt.children) {
      const h = serverHeight(child);
      placed.push({ node: child, x: serverX, y, w: serverW, h });
      y += h + 12;
    }
    const end = placed.length ? y - 12 : start + 54;
    const rtNode: Placed = { node: rt, x: 16, y: (start + end) / 2 - 27, w: runtimeW, h: 54 };
    runtimes.push(rtNode);
    for (const p of placed) servers.push({ ...p, parent: rtNode });
    y = Math.max(y, end + 12) + 12;
  }
  const height = Math.max(120, y);
  const toggle = (p: GraphPath) => onSelect(samePath(graph, p) ? null : p);
  const selected = (p: GraphPath) => samePath(graph, p);

  return (
    <div className="panel panel-full">
      <div className="panel-header">
        <div className="panel-title">Connection Graph</div>
        <div className="panel-badge" style={{ background: "var(--cyan-dim)", color: "var(--cyan)" }}>
          {new Set(servers.flatMap((s) => (s.node.kind === "server" ? [s.node.label] : s.node.kind === "idle" ? (s.node.tools ?? []).map((t) => t.name) : []))).size} MCP servers
        </div>
      </div>
      <div className="panel-body tree-scroll" ref={box}>
        {tree.length === 0 ? (
          <div className="empty-state"><div className="icon">🕸️</div>No tool calls in this view.</div>
        ) : (
          <svg className="tree-svg" viewBox={`0 0 ${width} ${height}`} height={height} role="img" aria-label="Runtimes, the servers they called, and their tools">
            {servers.map((s) => {
              const x1 = s.parent.x + s.parent.w, y1 = s.parent.y + s.parent.h / 2, x2 = s.x, y2 = s.y + 19, mx = (x1 + x2) / 2;
              return (
                <g key={`e-${s.node.id}`}>
                  <path className="tree-edge" d={`M ${x1} ${y1} C ${mx} ${y1} ${mx} ${y2} ${x2} ${y2}`} />
                </g>
              );
            })}
            {runtimes.map((r) => (
              <g key={r.node.id} className={`tree-node runtime${selected(r.node.path) ? " selected" : ""}`} onClick={() => toggle(r.node.path)}>
                <title>{r.node.label}</title>
                <rect x={r.x} y={r.y} width={r.w} height={r.h} />
                <text className="tree-title" x={r.x + 12} y={r.y + 22}>{fit(r.node.label, r.w - 24)}</text>
                <text className="tree-meta" x={r.x + 12} y={r.y + 40}>{r.node.calls} calls · {r.node.children.filter((c) => c.kind !== "idle").length} servers</text>
              </g>
            ))}
            {servers.map((s) => {
              const n = s.node;
              const idle = n.kind === "idle";
              const tools = n.tools ?? [];
              return (
                <g key={n.id} className={`tree-node ${n.kind}${selected(n.path) ? " selected" : ""}`} onClick={() => !idle && toggle(n.path)}>
                  <title>{idle ? tools.map((t) => t.name).join(", ") : n.label}</title>
                  <rect x={s.x} y={s.y} width={s.w} height={s.h} />
                  <text className="tree-title" x={s.x + 12} y={s.y + 19}>{fit(n.label, s.w - 110)}</text>
                  {!idle && <text className="tree-meta" x={s.x + s.w - 12} y={s.y + 19} textAnchor="end">{n.calls} calls</text>}
                  {tools.slice(0, MAX_TOOLS).map((t, i) => {
                    const path = { ...n.path, tool: t.name };
                    return (
                      <text
                        key={t.name}
                        className={`tree-tool${selected(path) ? " selected" : ""}`}
                        x={s.x + 20}
                        y={s.y + 38 + i * 16}
                        onClick={(e) => {
                          if (idle) return;
                          e.stopPropagation();
                          toggle(path);
                        }}
                      >
                        {fit(t.name, s.w - 90)}
                        {!idle && <tspan className="tree-meta" dx={8}>{t.calls}</tspan>}
                      </text>
                    );
                  })}
                  {tools.length > MAX_TOOLS && (
                    <text className="tree-meta" x={s.x + 20} y={s.y + 38 + MAX_TOOLS * 16}>and {tools.length - MAX_TOOLS} more</text>
                  )}
                </g>
              );
            })}
          </svg>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Credential ledger, grouped by credential
// ---------------------------------------------------------------------------

function credentialClass(type: string): string {
  if (type === "bearer" || type === "password") return type;
  if (type === "token" || type === "github-pat" || type === "slack-bot") return "token";
  return "api-key";
}

export function CredentialLedger({ view, utc, onSelect }: { view: SessionView; utc: boolean; onSelect: (d: Detail) => void }): React.JSX.Element {
  const groups = groupedLedger(view.toolCalls);
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">Credential Ledger</div>
        <div className="panel-badge" style={{ background: "var(--orange-dim)", color: "var(--orange)" }}>{groups.length} found</div>
      </div>
      <div className="panel-body-scroll">
        {groups.length === 0 ? (
          <div className="empty-state"><div className="icon">🔒</div>No credentials detected in tool parameters.</div>
        ) : (
          <table className="cred-table">
            <thead><tr><th>Type</th><th>Value</th><th>Uses</th><th>Last seen</th></tr></thead>
            <tbody>
              {groups.map((g) => (
                <React.Fragment key={g.key}>
                  <tr className="cred-row" onClick={() => setOpen(open === g.key ? null : g.key)} aria-expanded={open === g.key}>
                    <td><span className={`cred-type ${credentialClass(g.type)}`}>{g.type}</span></td>
                    <td className="cred-value">{g.masked}</td>
                    <td className="cred-tool">{g.uses.length}</td>
                    <td className="cred-server">{formatTime(g.lastSeen, utc)}</td>
                  </tr>
                  {open === g.key && (
                    <tr className="cred-uses">
                      <td colSpan={4}>
                        <ul>
                          {g.uses.map((u) => (
                            <li key={u.toolCallId} onClick={() => onSelect({ kind: "call", id: u.toolCallId })}>
                              {formatWithTz(u.at, utc)} · {u.tool} · {u.server}
                            </li>
                          ))}
                        </ul>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tool calls (sortable) and file events
// ---------------------------------------------------------------------------

const CALL_COLUMNS: Array<{ key: CallSortKey; label: string; num?: boolean }> = [
  { key: "time", label: "Time" }, { key: "tool", label: "Tool" }, { key: "server", label: "Server" },
  { key: "status", label: "Status" }, { key: "duration", label: "Duration", num: true }, { key: "bytes", label: "Response", num: true },
];

export function ToolCallsPanel({ view, utc, detail, onSelect }: {
  view: SessionView; utc: boolean; detail: Detail; onSelect: (d: Detail) => void;
}): React.JSX.Element {
  const [sort, setSort] = useState<{ key: CallSortKey; dir: SortDir }>({ key: "time", dir: "desc" });
  const rows = sortCalls(view.toolCalls, sort.key, sort.dir);
  const selected = detail?.kind === "call" ? detail.id : null;
  const header = (c: (typeof CALL_COLUMNS)[number]) => {
    const active = sort.key === c.key;
    const next: SortDir = active && sort.dir === "desc" ? "asc" : "desc";
    return (
      <th key={c.key} className={c.num ? "num" : undefined} aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}>
        <button onClick={() => setSort({ key: c.key, dir: next })}>{c.label}{active ? (sort.dir === "asc" ? " ▲" : " ▼") : ""}</button>
      </th>
    );
  };
  return (
    <div className="panel panel-full">
      <div className="panel-header">
        <div className="panel-title">Tool Calls</div>
        <div className="panel-badge" style={{ background: "var(--cyan-dim)", color: "var(--cyan)" }}>{rows.length} calls</div>
      </div>
      <div className="panel-body-scroll">
        {rows.length === 0 ? (
          <div className="empty-state"><div className="icon">⏳</div>No tool calls in this view.</div>
        ) : (
          <table className="data-table">
            <thead><tr>{CALL_COLUMNS.map(header)}</tr></thead>
            <tbody>
              {rows.map((tc) => (
                <tr key={tc.tool_call_id} className={`clickable${selected === tc.tool_call_id ? " selected" : ""}`} onClick={() => onSelect({ kind: "call", id: tc.tool_call_id })}>
                  <td>{formatTime(tc.started_at, utc)}</td>
                  <td>{tc.tool_name}</td>
                  <td>{tc.mcp_server}</td>
                  <td><span className={`timeline-status ${tc.status}`}>{tc.status}</span></td>
                  <td className="num">{tc.duration_ms != null ? `${tc.duration_ms} ms` : ""}</td>
                  <td className="num">{tc.response_bytes != null ? `${tc.response_bytes} B` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export function FileEventsPanel({ view, utc }: { view: SessionView; utc: boolean }): React.JSX.Element {
  const rows = [...view.fileEvents].sort((a, b) => b.at.localeCompare(a.at));
  const writes = rows.filter((r) => r.direction === "write").length;
  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">File Events</div>
        <div className="panel-badge" style={{ background: "var(--mint-dim)", color: "var(--mint)" }}>{rows.length - writes} reads · {writes} writes</div>
      </div>
      <div className="panel-body-scroll">
        {rows.length === 0 ? (
          <div className="empty-state"><div className="icon">📄</div>No file events in this view.</div>
        ) : (
          <table className="data-table">
            <thead><tr><th>Time</th><th>Access</th><th>Path</th><th className="num">Bytes</th></tr></thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.event_id}>
                  <td>{formatTime(e.at, utc)}</td>
                  <td><span className={`timeline-status ${e.direction === "write" ? "error" : "success"}`}>{e.direction}</span></td>
                  <td className="path">{e.path}</td>
                  <td className="num">{e.bytes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

function ParamValue({ node }: { node: ParamNode }): React.JSX.Element {
  switch (node.kind) {
    case "scalar":
      return <span className="param-scalar">{node.value}</span>;
    case "text":
      return <pre className="param-text">{node.value}</pre>;
    case "array":
      if (node.items.length === 0) return <span className="param-scalar">[]</span>;
      return (
        <div className="param-nested">
          {node.items.map((item, i) => <ParamEntry key={i} label={`[${i}]`} node={item} />)}
        </div>
      );
    case "object":
      if (node.entries.length === 0) return <span className="param-scalar">{"{}"}</span>;
      return (
        <div className="param-nested">
          {node.entries.map((e) => <ParamEntry key={e.key} label={e.key} node={e.value} />)}
        </div>
      );
  }
}

function ParamEntry({ label, node }: { label: string; node: ParamNode }): React.JSX.Element {
  const block = node.kind === "text" || ((node.kind === "object" || node.kind === "array") && (node.kind === "object" ? node.entries.length : node.items.length) > 0);
  return (
    <div className="param-entry">
      <span className="param-key">{label}</span>
      {block ? <span /> : <ParamValue node={node} />}
      {block && <div style={{ gridColumn: "1 / -1" }}><ParamValue node={node} /></div>}
    </div>
  );
}

/** Parameters as readable fields; text values keep their line breaks. */
export function ParamView({ node, raw }: { node: ParamNode; raw: string }): React.JSX.Element {
  const [showRaw, setShowRaw] = useState(false);
  return (
    <div className="param-tree">
      <div className="param-actions">
        <button className="filter-link" onClick={() => setShowRaw(!showRaw)}>{showRaw ? "Show fields" : "Show raw JSON"}</button>
      </div>
      {showRaw ? (
        <pre className="param-text">{(() => { try { return JSON.stringify(JSON.parse(raw), null, 2); } catch { return raw; } })()}</pre>
      ) : node.kind === "object" ? (
        node.entries.length === 0 ? <span className="param-scalar">(none)</span> : node.entries.map((e) => <ParamEntry key={e.key} label={e.key} node={e.value} />)
      ) : (
        <ParamValue node={node} />
      )}
    </div>
  );
}

export type { SessionRow };
