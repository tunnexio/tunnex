import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Field, Input, Select, RefreshButton } from "./ui";
import { AIUsageDashboard, formatAIUsageCost } from "./AIUsageDashboard";

import AppAccessPagination from "./AppAccessPagination";

type Report = components["schemas"]["AIUsageReport"];
type Inventory = {
  groups: { id: string; name: string }[];
  devices: { id: string; name: string }[];
  teams: { team_id: string }[];
  assignments: { device_id: string }[];
};
type Preset = "today" | "7" | "30" | "custom";
function rangeFor(preset: Exclude<Preset, "custom">) {
  const end = new Date();
  const start = new Date(end);
  start.setUTCHours(0, 0, 0, 0);
  start.setUTCDate(start.getUTCDate() - (preset === "today" ? 0 : Number(preset) - 1));
  return { from: start.toISOString(), to: end.toISOString() };
}

export function AIUsageWorkspace({ orgId, inventory }: { orgId: string; inventory: Inventory }) {
  const [preset, setPreset] = useState<Preset>("7");
  const [range, setRange] = useState(() => rangeFor("7"));
  const [customFrom, setCustomFrom] = useState(range.from.slice(0, 16));
  const [customTo, setCustomTo] = useState(range.to.slice(0, 16));
  const [team, setTeam] = useState("");
  const [device, setDevice] = useState("");
  const [reload, setReload] = useState(0);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [rangeError, setRangeError] = useState("");
  const [busy, setBusy] = useState(true);
  const [knownTeams, setKnownTeams] = useState<{ id: string; name: string }[]>([]);
  const [knownAgents, setKnownAgents] = useState<{ id: string; name: string }[]>([]);
  const serial = useRef(0);
  const invalidate = () => { serial.current++; setReport(null); setError(""); setBusy(true); };
  useEffect(() => {
    const id = ++serial.current;
    const controller = new AbortController();
    setBusy(true); setReport(null); setError("");
    void (async () => {
      try {
        const result = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/usage", {
          params: { path: { orgId }, query: {
            ...range, dashboard: true,
            ...(team ? { team_id: team } : {}), ...(device ? { device_id: device } : {}),
          } }, signal: controller.signal,
        });
        if (id !== serial.current) return;
        if (result.error || !result.data?.dashboard) throw new Error("unavailable");
        setReport(result.data);
        const merge = (old: { id: string; name: string }[], next: { id: string; name: string }[]) =>
          [...new Map([...old, ...next].map((row) => [row.id, { id: row.id, name: row.name }])).values()];
        setKnownTeams((old) => merge(old, result.data!.dashboard!.teams));
        setKnownAgents((old) => merge(old, result.data!.dashboard!.agents));
      } catch {
        if (id === serial.current) setError("Usage could not be loaded. Try again to see your gateway's latest records.");
      } finally {
        if (id === serial.current) setBusy(false);
      }
    })();
    return () => { serial.current++; controller.abort(); };
  }, [orgId, range, team, device, reload]);

  function refresh() {
    invalidate();
    if (preset !== "custom") setRange(rangeFor(preset));
    else setReload((v) => v + 1);
  }
  function applyCustom() {
    const from = new Date(customFrom + "Z"), to = new Date(customTo + "Z");
    const span = to.getTime() - from.getTime();
    if (!Number.isFinite(span) || span <= 0 || span > 31 * 86400000) {
      setRangeError("Choose a positive UTC range of at most 31 days."); return;
    }
    invalidate(); setRangeError(""); setRange({ from: from.toISOString(), to: to.toISOString() });
  }
  const unique = (rows: { id: string; name: string }[]) => [...new Map(rows.map((row) => [row.id, row])).values()];
  const teams = unique([...inventory.teams.map((t) => ({ id: t.team_id, name: inventory.groups.find((g) => g.id === t.team_id)?.name ?? `Retained team (${t.team_id})` })), ...knownTeams]);
  const agents = unique([...inventory.assignments.map((a) => ({ id: a.device_id, name: inventory.devices.find((d) => d.id === a.device_id)?.name ?? `Retained agent (${a.device_id})` })), ...knownAgents]);
  const d = report?.dashboard;
  const ranked = (rows: NonNullable<Report["dashboard"]>["teams"]) => rows.map((r) => ({ ...r, uncostedRequests: r.uncosted_requests }));
  return <div className="ai-usage-workspace"><AIUsageDashboard
    status={busy ? "loading" : error || !d ? "error" : "ready"}
    error={error}
    onRetry={refresh}
    filters={<div className="ai-usage-filter-content">
      <div className="ai-usage-filter-row">
        <Field label="Usage team"><Select value={team} onChange={(e) => { invalidate(); setTeam(e.target.value); }}>
          <option value="">All teams</option>{teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
        </Select></Field>
        <Field label="Usage agent"><Select value={device} onChange={(e) => { invalidate(); setDevice(e.target.value); }}>
          <option value="">All agents</option>{agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </Select></Field>
        <Field label="Time range"><Select value={preset} onChange={(e) => {
          const v = e.target.value as Preset; setPreset(v); setRangeError("");
          if (v !== "custom") { invalidate(); setRange(rangeFor(v)); }
        }}><option value="today">Today (UTC)</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option><option value="custom">Custom range</option></Select></Field>
        <RefreshButton label={busy ? "Refreshing…" : "Refresh"} disabled={busy} onClick={refresh} />
      </div>
      {preset === "custom" && <div className="ai-usage-custom-range">
        <Field label="From (UTC)"><Input type="datetime-local" value={customFrom} onChange={(e) => setCustomFrom(e.target.value)} /></Field>
        <Field label="To (UTC)"><Input type="datetime-local" value={customTo} onChange={(e) => setCustomTo(e.target.value)} /></Field>
        <Button onClick={applyCustom}>Apply range</Button>
      </div>}
      {rangeError && <p role="alert" className="text-sm text-danger">{rangeError}</p>}
      <span className="ai-usage-period">{range.from.slice(0, 10)} to {range.to.slice(0, 10)} · UTC · Gateway records<span className="sr-only">Based on retained gateway records. Older activity may no longer be available.</span></span>
    </div>}
    totals={report && d ? { requests: report.total_requests, tokens: report.total_tokens, inputTokens: report.prompt_tokens, outputTokens: report.completion_tokens, cost: report.total_cost, uncostedRequests: report.uncosted_requests, successfulRequests: d.successful_requests, failedRequests: d.failed_requests, cancelledRequests: d.cancelled_requests } : undefined}
    daily={d?.daily.map((r) => ({ ...r, uncostedRequests: r.uncosted_requests }))}
    models={d?.models}
    userGroups={d?.user_groups ? ranked(d.user_groups) : undefined}
    teams={d ? ranked(d.teams) : undefined}
    agents={d ? ranked(d.agents) : undefined}
    workloads={d && <WorkloadUsage rows={d.workloads} />}
  />

  </div>;
}

function WorkloadUsage({ rows }: { rows: NonNullable<Report["dashboard"]>["workloads"] }) {
  const [page, setPage] = useState(1), [pageSize, setPageSize] = useState(20);
  const sorted = rows ? [...rows].sort((a, b) => b.cost - a.cost || a.name.localeCompare(b.name)) : undefined;
  const currentPage = Math.min(page, Math.max(1, Math.ceil((sorted?.length ?? 0) / pageSize)));
  const visibleRows = sorted?.slice((currentPage - 1) * pageSize, currentPage * pageSize) ?? [];
  const max = sorted?.[0]?.cost ?? 0;
  const count = (value: number) => Number.isFinite(value) && value >= 0 ? value.toLocaleString("en-US") : "Unavailable";
  return <section className="ai-usage-workload-breakdown" aria-label="Workload usage">
    <div className="ai-usage-panel">
      <div className="ai-usage-panel-title"><h3 className="sr-only">Spend by workload</h3><span>{rows ? `${rows.length} workload${rows.length === 1 ? "" : "s"}` : "Unavailable"}</span></div>

      {!sorted?.length ? <p className="ai-usage-muted">{rows ? "No workload usage recorded in this period." : "Workload breakdown is unavailable."}</p>
        : <><div className="ai-usage-table-scroll"><table>
          <caption className="sr-only">Spend by workload</caption>
          <thead><tr><th scope="col">Workload</th><th scope="col">Requests</th><th scope="col">Tokens</th><th scope="col">Estimated cost</th><th scope="col">Without cost</th></tr></thead>
          <tbody>{visibleRows.map((row) => <tr key={row.id}>
            <th scope="row"><span className="ai-usage-rank-name" title={row.id}>{row.name}</span><span className="ai-usage-rank-track" aria-hidden="true"><i style={{ width: `${max > 0 ? Math.max(0, row.cost / max * 100) : 0}%` }} /></span></th>
            <td>{count(row.requests)}</td><td>{count(row.tokens)}</td><td>{row.requests > 0 && row.uncosted_requests === row.requests ? "Unavailable" : formatAIUsageCost(row.cost)}</td><td>{count(row.uncosted_requests)}</td>
          </tr>)}</tbody>
        </table></div><AppAccessPagination page={currentPage} pageSize={pageSize} count={visibleRows.length} hasNext={currentPage * pageSize < sorted.length} maxOffset={null} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} /></>}
    </div>
  </section>;
}
