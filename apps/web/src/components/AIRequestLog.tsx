import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { Button, Input, Select } from "./ui";
import { modelDisplayName } from "./HelpTooltip";
import { formatAIUsageCost } from "./AIUsageDashboard";

// AI-READY-1: the per-request log under Usage & cost. Metadata only: prompts
// and responses are never stored, so there is nothing more to open.
type Entry = components["schemas"]["AIRequestLogEntry"];
type Range = "1" | "7" | "30";
const subjectLabel: Record<Entry["subject_kind"], string> = { user: "User", agent: "Agent", workload: "Workload" };
const ingressLabel: Record<Entry["ingress"], string> = { public: "Public", vpn: "VPN", agent: "Agent", workload: "Workload" };
const refusalLabel: Record<string, string> = {
  ai_daily_threshold_reached: "Daily limit reached", ai_price_unavailable: "Price unknown", ai_policy_denied: "No access",
  ai_gateway_unavailable: "Gateway unavailable", unauthenticated: "Not signed in",
};

function costText(e: Entry): string {
  switch (e.cost_state) {
    case "costed": return formatAIUsageCost(e.cost_usd ?? 0);
    case "pending": return "Pending";
    case "uncosted": return "Uncosted";
    case "unavailable": return "Unavailable";
    default: return "—";
  }
}

export function AIRequestLog({ orgId }: { orgId: string }) {
  const [range, setRange] = useState<Range>("1");
  const [subjectKind, setSubjectKind] = useState<"" | Entry["subject_kind"]>("");
  const [outcome, setOutcome] = useState<"" | Entry["outcome"]>("");
  const [modelInput, setModelInput] = useState(""), [model, setModel] = useState("");
  const [rows, setRows] = useState<Entry[]>([]), [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true), [error, setError] = useState("");
  const [version, setVersion] = useState(0);
  const serial = useRef(0);
  async function load(cursor?: string) {
    const n = ++serial.current;
    setLoading(true); setError("");
    const from = new Date(Date.now() - Number(range) * 24 * 3600 * 1000).toISOString();
    try {
      const r = await api.GET("/api/v1/organizations/{orgId}/ai-gateway/requests", { params: { path: { orgId }, query: { from, limit: 50, ...(subjectKind ? { subject_kind: subjectKind } : {}), ...(outcome ? { outcome } : {}), ...(model ? { model } : {}), ...(cursor ? { cursor } : {}) } } });
      if (n !== serial.current) return;
      if (r.error || !r.data) { setError("Could not load AI requests."); return; }
      const page = r.data;
      setRows((current) => cursor ? [...current, ...page.items] : page.items);
      setNext(page.next_cursor ?? null);
    } catch { if (n === serial.current) setError("Could not reach the API. Retry to load AI requests."); }
    finally { if (n === serial.current) setLoading(false); }
  }
  useEffect(() => { setRows([]); setNext(null); void load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [orgId, range, subjectKind, outcome, model, version]);
  return <section className="ai-request-log" aria-label="AI requests">
    <div className="ai-gateway-filters">
      <Select aria-label="Time range" value={range} onChange={(e) => setRange(e.target.value as Range)}><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option></Select>
      <Select aria-label="Filter by subject" value={subjectKind} onChange={(e) => setSubjectKind(e.target.value as typeof subjectKind)}><option value="">All subjects</option><option value="user">Users</option><option value="agent">Agents</option><option value="workload">Workloads</option></Select>
      <Select aria-label="Filter by status" value={outcome} onChange={(e) => setOutcome(e.target.value as typeof outcome)}><option value="">All statuses</option><option value="ok">Succeeded</option><option value="refused">Refused</option><option value="error">Failed</option></Select>
      <form onSubmit={(e) => { e.preventDefault(); setModel(modelInput.trim()); }}><Input aria-label="Filter by model" placeholder="Exact model, for example openai/gpt-4o-mini" value={modelInput} onChange={(e) => setModelInput(e.target.value)} /></form>
      <Button variant="ghost" size="sm" onClick={() => setVersion((v) => v + 1)}>Refresh</Button>
    </div>
    <p className="text-sm text-ink-tertiary">Time, who, model, status, tokens and cost of each AI call. Prompts and responses are never stored. Tokens and cost appear a few seconds after a call.</p>
    {error && <div className="ai-gateway-error"><p role="alert">{error}</p><Button variant="ghost" size="sm" onClick={() => void load()}>Retry AI requests</Button></div>}
    {!rows.length && loading && <p role="status">Loading AI requests…</p>}
    {!rows.length && !loading && !error && <div className="ai-gateway-empty"><h3>No AI requests</h3><p>No calls match these filters in this time range.</p></div>}
    {rows.length > 0 && <div className="ai-usage-table-scroll"><table className="ai-gateway-table">
      <caption className="sr-only">AI requests, newest first</caption>
      <thead><tr><th>Time</th><th>Subject</th><th>Group</th><th>Model</th><th>Status</th><th>Latency</th><th>Tokens in / out</th><th>Cost</th><th>Path</th></tr></thead>
      <tbody>{rows.map((e) => <tr key={e.id}>
        <td title={e.request_id ? `Request ${e.request_id}` : undefined}>{new Date(e.occurred_at).toLocaleString()}</td>
        <td><span>{e.subject_name || (e.subject_id ? "Removed" : "Unidentified")}</span><small className="block text-ink-tertiary">{subjectLabel[e.subject_kind]}</small></td>
        <td>{e.group_name || "—"}</td>
        <td title={e.model}>{modelDisplayName(e.model)}<small className="block text-ink-tertiary">{e.mode}</small></td>
        <td>{e.outcome === "ok" ? "Succeeded" : e.outcome === "refused" ? "Refused" : "Failed"}<small className="block text-ink-tertiary">{e.refusal_code ? refusalLabel[e.refusal_code] ?? e.refusal_code : `HTTP ${e.status_code}`}</small></td>
        <td>{e.latency_ms.toLocaleString()} ms</td>
        <td>{e.prompt_tokens == null ? "—" : `${e.prompt_tokens.toLocaleString()} / ${(e.completion_tokens ?? 0).toLocaleString()}`}</td>
        <td>{costText(e)}</td>
        <td>{ingressLabel[e.ingress]}</td>
      </tr>)}</tbody>
    </table></div>}
    {next && <Button variant="ghost" disabled={loading} onClick={() => void load(next)}>{loading ? "Loading…" : "Load more"}</Button>}
  </section>;
}
