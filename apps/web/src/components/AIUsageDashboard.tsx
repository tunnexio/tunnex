import { useId, useState, type ReactNode } from "react";
import "./ai-usage-dashboard.css";

export type AIUsageTotals = {
  requests: number; tokens: number; inputTokens: number; outputTokens: number;
  cost: number; uncostedRequests: number; successfulRequests: number; failedRequests: number; cancelledRequests?: number;
};
export type AIUsageDay = { date: string; requests: number; tokens: number; cost: number; uncostedRequests: number };
export type AIUsageRank = { id: string; name: string; requests: number; tokens: number; cost: number; uncostedRequests: number };
export type AIUsageDashboardProps = {
  status: "loading" | "error" | "ready";
  error?: string; onRetry?: () => void; filters?: ReactNode;
  totals?: AIUsageTotals; daily?: AIUsageDay[];
  models?: { name: string; cost: number }[]; teams?: AIUsageRank[]; agents?: AIUsageRank[];
};
const count = (value: number) => value.toLocaleString("en-US");
export function formatAIUsageCost(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "Unavailable";
  if (value > 0 && value < 0.000001) return "<$0.000001";
  return "$" + value.toLocaleString("en-US", {
    minimumFractionDigits: value > 0 && value < 0.01 ? 6 : 2,
    maximumFractionDigits: 6,
  });
}
function validTotals(v: AIUsageTotals) {
  return Object.values(v).every((n) => Number.isFinite(n) && n >= 0);
}
export function AIUsageDashboard(props: AIUsageDashboardProps) {
  const { status, totals, filters, onRetry } = props;
  return <section className="ai-usage-dashboard" aria-label="AI usage dashboard" aria-busy={status === "loading"}>
    <div className="ai-usage-topline"><div><p className="ai-usage-eyebrow">AI GATEWAY / ANALYTICS</p><h2>Usage & cost</h2><p className="ai-usage-muted">Understand where your agents spend.</p></div><span className="ai-usage-source"><i />Native observed estimates</span></div>
    {filters && <div className="ai-usage-filters">{filters}</div>}
    {status === "loading" ? <div className="ai-usage-state" role="status"><span className="ai-usage-loader" />Loading usage from your gateway…</div>
      : status === "error" || !totals || !validTotals(totals) ? <div className="ai-usage-state" role="alert"><h3>Usage is unavailable</h3><p>{props.error || "Could not read usage from your gateway. No zero-spend claim can be made."}</p>{onRetry && <button type="button" onClick={onRetry}>Retry usage</button>}</div>
      : <>
        <div className="ai-usage-overview"><div className="ai-usage-spend"><p className="ai-usage-eyebrow">ESTIMATED SPEND</p><strong>{formatAIUsageCost(totals.cost)}</strong><span>USD · selected period</span><p>Native observed estimates; not provider invoices.</p></div><div className="ai-usage-metrics">
          <Metric label="Requests" value={count(totals.requests)} detail="Observed requests" />
          <Metric label="Tokens" value={count(totals.tokens)} detail="Input + output" />
          <Metric label="Successful" value={count(totals.successfulRequests)} detail="Provider requests" tone={totals.successfulRequests > 0 ? "success" : undefined} />
          <Metric label="Failed" value={count(totals.failedRequests)} detail="Provider requests" tone={totals.failedRequests > 0 ? "failure" : undefined} />
          <Metric label="Avg. cost / request" value={totals.requests > 0 && totals.uncostedRequests === 0 ? formatAIUsageCost(totals.cost / totals.requests) : "Unavailable"} detail={totals.requests === 0 ? "No requests" : totals.uncostedRequests > 0 ? "Incomplete pricing" : "Observed estimated cost"} />
        </div></div>
        {totals.uncostedRequests > 0 && <p className="ai-usage-warning" role="status">Cost is incomplete: {count(totals.uncostedRequests)} observed requests have no recorded cost. The displayed estimate may understate spending.</p>}
        {totals.requests === 0 && <div className="ai-usage-empty" role="status"><h3>No requests in this period</h3><p>Choose another period or send an authorized agent request to begin seeing usage.</p></div>}
        <DailyChart days={props.daily} />
        <div className="ai-usage-rank-grid"><Ranked title="Spend by team" label="Team" rows={props.teams} /><Ranked title="Spend by agent" label="Agent" rows={props.agents} /><Ranked title="Spend by model" label="Model" rows={props.models?.map((m) => ({ ...m, id: m.name }))} /></div>
        <TokenBreakdown totals={totals} />
        <p className="ai-usage-footnote">Provider request outcomes exclude requests refused by Tunnex before reaching the provider.{totals.cancelledRequests !== undefined && ` Cancelled provider requests: ${count(totals.cancelledRequests)}.`} Based on retained gateway records; older activity may no longer be available. Soft thresholds are not strict caps. Concurrent requests may exceed them. </p>
      </>}
  </section>;
}
function Metric({ label, value, detail, tone }: { label: string; value: string; detail: string; tone?: "success" | "failure" }) {
  return <div className={`ai-usage-metric${tone ? ` ai-usage-metric-${tone}` : ""}`}><span>{label}</span><strong>{value}</strong><small title={detail === "Provider requests" ? "Requests refused by Tunnex before reaching the provider are excluded." : undefined}>{detail}</small></div>;
}
function DailyChart({ days }: { days?: AIUsageDay[] }) {
  const id = useId();
  const [active, setActive] = useState<number | null>(null);
  const max = Math.max(...(days ?? []).map((d) => d.cost), 0);
  const selected = active === null ? undefined : days?.[active];
  return <div className="ai-usage-panel ai-usage-chart"><div className="ai-usage-panel-title"><h3>Daily spend</h3><span>Estimated USD · UTC</span></div>
    {!days || days.length === 0 ? <p className="ai-usage-muted">{days ? "No daily usage recorded in this period." : "Daily breakdown is unavailable."}</p> : <>
      <div className="ai-usage-plot"><div className="ai-usage-chart-y"><span>{formatAIUsageCost(max)}</span><span>{formatAIUsageCost(max / 2)}</span><span>$0</span></div><div className="ai-usage-chart-bars" role="group" aria-label="Daily estimated spend">
        {days.map((day, index) => <div className="ai-usage-day" key={day.date}><button type="button" className="ai-usage-bar-target" aria-label={`${day.date}: ${formatAIUsageCost(day.cost)}, ${count(day.requests)} requests, ${count(day.tokens)} tokens`} aria-describedby={active === index ? id : undefined} onFocus={() => setActive(index)} onBlur={() => setActive(null)} onMouseEnter={() => setActive(index)} onMouseLeave={() => setActive(null)} onKeyDown={(e) => { if (e.key === "Escape") setActive(null); }}><svg viewBox="0 0 24 100" preserveAspectRatio="none" aria-hidden="true"><rect x="2" y={100 - (max ? day.cost / max * 94 : 0)} width="20" height={max ? day.cost / max * 94 : 0} rx="2" /></svg></button><span>{day.date.slice(5)}</span></div>)}
      </div></div>
      <div className="ai-usage-chart-detail" id={id} role="status">{selected ? <><strong>{selected.date}</strong><span>{formatAIUsageCost(selected.cost)}</span><span>{count(selected.requests)} requests · {count(selected.tokens)} tokens · {count(selected.uncostedRequests)} without cost</span></> : <span>Hover or focus a day to inspect usage.</span>}</div>
      <details className="ai-usage-table-details"><summary>View daily data table</summary><div className="ai-usage-table-scroll"><table><caption className="sr-only">Daily observed usage in UTC</caption><thead><tr><th scope="col">Date (UTC)</th><th scope="col">Requests</th><th scope="col">Tokens</th><th scope="col">Estimated cost</th><th scope="col">Without cost</th></tr></thead><tbody>{days.map((d) => <tr key={d.date}><th scope="row">{d.date}</th><td>{count(d.requests)}</td><td>{count(d.tokens)}</td><td>{formatAIUsageCost(d.cost)}</td><td>{count(d.uncostedRequests)}</td></tr>)}</tbody></table></div></details>
    </>}
  </div>;
}
function Ranked({ title, label, rows }: { title: string; label: string; rows?: (Pick<AIUsageRank, "id" | "name" | "cost"> & Partial<AIUsageRank>)[] }) {
  const sorted = rows ? [...rows].sort((a, b) => b.cost - a.cost || a.name.localeCompare(b.name)) : undefined;
  const max = sorted?.[0]?.cost ?? 0;
  const hasRequests = label !== "Model";
  return <div className="ai-usage-panel"><div className="ai-usage-panel-title"><h3>{title}</h3><span>{rows ? `${rows.length} ${label.toLowerCase()}${rows.length === 1 ? "" : "s"}` : "Unavailable"}</span></div>
    {!sorted?.length ? <p className="ai-usage-muted">{rows ? "No recorded usage in this period." : "Breakdown is unavailable."}</p> : <div className="ai-usage-table-scroll"><table><caption className="sr-only">{title}</caption><thead><tr><th scope="col">{label}</th>{hasRequests && <th scope="col">Requests</th>}<th scope="col">Cost</th></tr></thead><tbody>{sorted.map((row) => <tr key={row.id}><th scope="row"><span className="ai-usage-rank-name" title={row.name}>{row.name}</span><span className="ai-usage-rank-track" aria-hidden="true"><i style={{ width: `${max ? row.cost / max * 100 : 0}%` }} /></span>{(row.uncostedRequests ?? 0) > 0 && <small className="ai-usage-rank-missing">{count(row.uncostedRequests!)} without cost</small>}</th>{hasRequests && <td>{row.requests === undefined ? "Unavailable" : count(row.requests)}</td>}<td>{formatAIUsageCost(row.cost)}</td></tr>)}</tbody></table></div>}
  </div>;
}
function TokenBreakdown({ totals }: { totals: AIUsageTotals }) {
  const sum = totals.inputTokens + totals.outputTokens;
  return <div className="ai-usage-panel ai-usage-tokens"><div><h3>Token breakdown</h3><p className="ai-usage-muted">Input and output tokens recorded by the gateway.</p></div><div className="ai-usage-token-visual"><div className="ai-usage-token-track" aria-hidden="true"><i style={{ width: `${sum ? totals.inputTokens / sum * 100 : 0}%` }} /><b style={{ width: `${sum ? totals.outputTokens / sum * 100 : 0}%` }} /></div><div className="ai-usage-token-labels"><span><i />Input <strong>{count(totals.inputTokens)}</strong></span><span><b />Output <strong>{count(totals.outputTokens)}</strong></span></div></div></div>;
}

export default AIUsageDashboard;
