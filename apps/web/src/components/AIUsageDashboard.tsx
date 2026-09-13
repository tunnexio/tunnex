import { useId, useState, type ReactNode } from "react";
import "./ai-usage-dashboard.css";
import { HelpTooltip } from "./HelpTooltip";

export type AIUsageTotals = {
  requests: number; tokens: number; inputTokens: number; outputTokens: number;
  cost: number; uncostedRequests: number; successfulRequests: number; failedRequests: number; cancelledRequests?: number;
};
export type AIUsageDay = { date: string; requests: number; tokens: number; cost: number; uncostedRequests: number };
export type AIUsageRank = { id: string; name: string; requests: number; tokens: number; cost: number; uncostedRequests: number };
export type AIUsageDashboardProps = {
  workloads?: ReactNode;
  status: "loading" | "error" | "ready";
  error?: string; onRetry?: () => void; filters?: ReactNode;
  totals?: AIUsageTotals; daily?: AIUsageDay[];
  models?: { name: string; cost: number }[]; teams?: AIUsageRank[]; agents?: AIUsageRank[]; userGroups?: AIUsageRank[];
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
export function compactUsageValue(value: number, currency = false): string {
  if (!Number.isFinite(value) || value < 0) return "Unavailable";
  if (value < 10000) return currency ? formatAIUsageCost(value) : count(value);
  return (currency ? "$" : "") + new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}
function validTotals(v: AIUsageTotals) {
  return Object.values(v).every((n) => Number.isFinite(n) && n >= 0);
}
export function AIUsageDashboard(props: AIUsageDashboardProps) {
  const { status, totals, filters, onRetry } = props;
  const pricedRequests = Math.max(0, (totals?.requests ?? 0) - (totals?.uncostedRequests ?? 0));
  const [breakdown, setBreakdown] = useState("User groups");
  return <section className="ai-usage-dashboard" aria-label="AI usage dashboard" aria-busy={status === "loading"}>
    <div className="ai-usage-topline"><h2>Usage & cost</h2><HelpTooltip label="About usage estimates">Gateway observations, not provider invoices. Outcomes exclude requests refused before reaching the provider. Older records may no longer be retained. Soft thresholds are not strict caps.</HelpTooltip></div>
    {filters && <div className="ai-usage-filters">{filters}</div>}
    {status === "loading" ? <div className="ai-usage-state" role="status"><span className="ai-usage-loader" />Loading usage from your gateway…</div>
      : status === "error" || !totals || !validTotals(totals) ? <div className="ai-usage-state" role="alert"><h3>Usage is unavailable</h3><p>{props.error || "Could not read usage from your gateway. No zero-spend claim can be made."}</p>{onRetry && <button type="button" onClick={onRetry}>Retry usage</button>}</div>
      : <>
        <div className="ai-usage-overview"><div className="ai-usage-spend"><p className="ai-usage-eyebrow">Estimated spend <HelpTooltip>Recorded costs in USD for the selected period. Missing pricing can understate spending.</HelpTooltip></p><strong title={totals.uncostedRequests === totals.requests && totals.requests > 0 ? "No recorded prices" : formatAIUsageCost(totals.cost)}>{totals.requests > 0 && totals.uncostedRequests === totals.requests ? "Unavailable" : compactUsageValue(totals.cost, true)}</strong><span>{totals.uncostedRequests > 0 ? "Incomplete pricing" : "USD · estimated"}</span></div><div className="ai-usage-metrics">
          <Metric label="Requests" value={compactUsageValue(totals.requests)} exact={count(totals.requests)} detail="Observed requests" />
          <Metric label="Tokens" value={compactUsageValue(totals.tokens)} exact={count(totals.tokens)} detail="Input + output" />
          <Metric label="Successful" value={compactUsageValue(totals.successfulRequests)} exact={count(totals.successfulRequests)} detail="Provider requests" tone={totals.successfulRequests > 0 ? "success" : undefined} />
          <Metric label="Failed" value={compactUsageValue(totals.failedRequests)} exact={count(totals.failedRequests)} detail="Provider requests" tone={totals.failedRequests > 0 ? "failure" : undefined} />
          <Metric label="Avg. cost / priced request" value={pricedRequests > 0 ? compactUsageValue(totals.cost / pricedRequests, true) : "Unavailable"} exact={pricedRequests > 0 ? formatAIUsageCost(totals.cost / pricedRequests) : "Unavailable"} detail={`Average over ${count(pricedRequests)} priced requests. ${count(totals.uncostedRequests)} requests without cost excluded.`} />
        </div></div>
        {totals.uncostedRequests > 0 && <p className="ai-usage-warning" role="status">{count(totals.uncostedRequests)} requests missing cost <HelpTooltip>The estimate excludes requests with no recorded price and may understate spending. Missing cost is not zero cost.</HelpTooltip></p>}
        {totals.requests === 0 && <div className="ai-usage-empty" role="status"><h3>No requests in this period</h3><p>Choose another period or send an authorized agent request to begin seeing usage.</p></div>}
        <div className="ai-usage-analysis-grid"><DailyChart days={props.daily} />
        <div className="ai-usage-breakdowns"><div className="ai-usage-tabs" role="tablist" aria-label="Usage breakdown">{["User groups", "Teams", "Agents", "Models", ...(props.workloads ? ["Workloads"] : [])].map(name => <button key={name} type="button" role="tab" aria-selected={breakdown === name} onClick={() => setBreakdown(name)}>{name}</button>)}</div>
        <div role="tabpanel" aria-label={breakdown}>
        {breakdown === "User groups" && <Ranked title="Spend by user group" label="User group" rows={props.userGroups} />}
        {breakdown === "Teams" && <Ranked title="Spend by team" label="Team" rows={props.teams} />}
        {breakdown === "Agents" && <Ranked title="Spend by agent" label="Agent" rows={props.agents} />}
        {breakdown === "Models" && <Ranked emptyMessage="No priced model usage." title="Spend by model" label="Model" rows={props.models?.map(m => ({ ...m, id: m.name }))} />}
        {breakdown === "Workloads" && props.workloads}
        </div></div></div>
      </>}
  </section>;
}
function Metric({ label, value, exact, detail, tone }: { label: string; value: string; exact?: string; detail: string; tone?: "success" | "failure" }) {
  return <div className={`ai-usage-metric${tone ? ` ai-usage-metric-${tone}` : ""}`}><span>{label}<HelpTooltip>{detail === "Provider requests" ? "Requests refused before reaching the provider are excluded." : detail}</HelpTooltip></span><strong title={exact ?? value} aria-label={exact ?? value}>{value}</strong></div>;
}
function DailyChart({ days }: { days?: AIUsageDay[] }) {
  const id = useId();
  const [active, setActive] = useState<number | null>(null);
  const [metric, setMetric] = useState<"requests" | "cost">("requests");
  const max = Math.max(...(days ?? []).map(d => d[metric]), 0);
  const axis = (value: number) => metric === "cost" ? formatAIUsageCost(value) : count(Math.ceil(value));
  const selected = active === null ? undefined : days?.[active];
  return <div className="ai-usage-panel ai-usage-chart"><div className="ai-usage-panel-title"><h3>Daily activity</h3><div className="ai-usage-chart-switch"><button type="button" aria-pressed={metric === "requests"} onClick={() => setMetric("requests")}>Requests</button><button type="button" aria-pressed={metric === "cost"} onClick={() => setMetric("cost")}>Spend</button><HelpTooltip>Daily totals in UTC. Focus or hover over a day for details. Spend includes recorded prices only.</HelpTooltip></div></div>
    {!days || days.length === 0 ? <p className="ai-usage-muted">{days ? "No daily usage recorded in this period." : "Daily breakdown is unavailable."}</p> : <>
      <div className="ai-usage-plot"><div className="ai-usage-chart-y"><span>{axis(max)}</span><span>{axis(max / 2)}</span><span>{metric === "cost" ? "$0" : "0"}</span></div><div className="ai-usage-chart-bars" role="group" aria-label={metric === "cost" ? "Daily estimated spend" : "Daily requests"}>
        {days.map((day, index) => <div className="ai-usage-day" key={day.date}><button type="button" className="ai-usage-bar-target" aria-label={`${day.date}: ${formatAIUsageCost(day.cost)}, ${count(day.requests)} requests, ${count(day.tokens)} tokens`} aria-describedby={active === index ? id : undefined} onFocus={() => setActive(index)} onBlur={() => setActive(null)} onMouseEnter={() => setActive(index)} onMouseLeave={() => setActive(null)} onKeyDown={(e) => { if (e.key === "Escape") setActive(null); }}><svg viewBox="0 0 24 100" preserveAspectRatio="none" aria-hidden="true"><rect x="2" y={100 - (max ? day[metric] / max * 94 : 0)} width="20" height={max ? day[metric] / max * 94 : 0} rx="2" /></svg></button><span>{day.date.slice(5)}</span></div>)}
      </div></div>
      <div className="ai-usage-chart-detail" id={id} role="status">{selected ? <><strong>{selected.date}</strong><span>{formatAIUsageCost(selected.cost)}</span><span>{count(selected.requests)} requests · {count(selected.tokens)} tokens · {count(selected.uncostedRequests)} without cost</span></> : <span>UTC · {metric === "cost" ? "Recorded spend" : "Requests"}</span>}</div>
      <details className="ai-usage-table-details"><summary>View daily data table</summary><div className="ai-usage-table-scroll"><table><caption className="sr-only">Daily observed usage in UTC</caption><thead><tr><th scope="col">Date (UTC)</th><th scope="col">Requests</th><th scope="col">Tokens</th><th scope="col">Estimated cost</th><th scope="col">Without cost</th></tr></thead><tbody>{days.map((d) => <tr key={d.date}><th scope="row">{d.date}</th><td>{count(d.requests)}</td><td>{count(d.tokens)}</td><td>{formatAIUsageCost(d.cost)}</td><td>{count(d.uncostedRequests)}</td></tr>)}</tbody></table></div></details>
    </>}
  </div>;
}
function Ranked({ title, label, rows, emptyMessage }: { emptyMessage?: string; title: string; label: string; rows?: (Pick<AIUsageRank, "id" | "name" | "cost"> & Partial<AIUsageRank>)[] }) {
  const sorted = rows ? [...rows].sort((a, b) => b.cost - a.cost || a.name.localeCompare(b.name)) : undefined;
  const max = sorted?.[0]?.cost ?? 0;
  const hasRequests = label !== "Model";
  return <div className="ai-usage-panel"><div className="ai-usage-panel-title"><h3>{title}</h3><span>{rows ? `${rows.length} ${label.toLowerCase()}${rows.length === 1 ? "" : "s"}` : "Unavailable"}</span></div>
    {!sorted?.length ? <p className="ai-usage-muted">{rows ? emptyMessage ?? "No recorded usage in this period." : "Breakdown is unavailable."}</p> : <div className="ai-usage-table-scroll"><table><caption className="sr-only">{title}</caption><thead><tr><th scope="col">{label}</th>{hasRequests && <th scope="col">Requests</th>}<th scope="col">Cost</th></tr></thead><tbody>{sorted.map((row) => <tr key={row.id}><th scope="row"><span className="ai-usage-rank-name" title={row.name}>{row.name}</span><span className="ai-usage-rank-track" hidden={!max} aria-hidden="true"><i style={{ width: `${max ? row.cost / max * 100 : 0}%` }} /></span>{(row.uncostedRequests ?? 0) > 0 && <small className="ai-usage-rank-missing">{count(row.uncostedRequests!)} without cost</small>}</th>{hasRequests && <td>{row.requests === undefined ? "Unavailable" : count(row.requests)}</td>}<td>{row.requests && row.uncostedRequests === row.requests ? "Unavailable" : formatAIUsageCost(row.cost)}</td></tr>)}</tbody></table></div>}
  </div>;
}

export default AIUsageDashboard;
