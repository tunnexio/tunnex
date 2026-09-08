import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Field, Input, Select } from "./ui";
import { AIUsageDashboard } from "./AIUsageDashboard";

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
  return <AIUsageDashboard
    status={busy ? "loading" : error || !d ? "error" : "ready"}
    error={error}
    onRetry={refresh}
    filters={<div className="space-y-3">
      <div className="grid items-end gap-3 sm:grid-cols-2 xl:grid-cols-[1fr_1fr_1fr_auto]">
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
        <Button disabled={busy} onClick={refresh}>{busy ? "Loading usage…" : "Refresh usage"}</Button>
      </div>
      {preset === "custom" && <div className="grid items-end gap-3 sm:grid-cols-[1fr_1fr_auto]">
        <Field label="From (UTC)"><Input type="datetime-local" value={customFrom} onChange={(e) => setCustomFrom(e.target.value)} /></Field>
        <Field label="To (UTC)"><Input type="datetime-local" value={customTo} onChange={(e) => setCustomTo(e.target.value)} /></Field>
        <Button onClick={applyCustom}>Apply range</Button>
      </div>}
      {rangeError && <p role="alert" className="text-sm text-danger">{rangeError}</p>}
      <p className="text-xs text-ink-tertiary">{range.from.slice(0, 10)} {range.from.slice(11, 16)} – {range.to.slice(0, 10)} {range.to.slice(11, 16)} UTC · Based on retained gateway records; older activity may no longer be available.</p>
    </div>}
    totals={report && d ? { requests: report.total_requests, tokens: report.total_tokens, inputTokens: report.prompt_tokens, outputTokens: report.completion_tokens, cost: report.total_cost, uncostedRequests: report.uncosted_requests, successfulRequests: d.successful_requests, failedRequests: d.failed_requests, cancelledRequests: d.cancelled_requests } : undefined}
    daily={d?.daily.map((r) => ({ ...r, uncostedRequests: r.uncosted_requests }))}
    models={d?.models}
    userGroups={d?.user_groups ? ranked(d.user_groups) : undefined}
    teams={d ? ranked(d.teams) : undefined}
    agents={d ? ranked(d.agents) : undefined}
  />;
}
