import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, Button, Card, DataTable, EmptyState, ErrorText, Loading, PageHeader } from "../components/ui";
import { api, apiErrorMessage, type AlertOccurrence, type AlertOccurrenceState } from "../lib/api";
import { relativeAge } from "../lib/format";
import { useOrg } from "../lib/useOrg";

type View = "active" | "history";

function productLabel(row: AlertOccurrence): string {
  if (row.resource_type === "kubernetes_cluster" || row.resource_type === "kubernetes_service") return "Kubernetes";
  return row.resource_type.charAt(0).toUpperCase() + row.resource_type.slice(1);
}

function resourceHref(row: AlertOccurrence): string | null {
  switch (row.resource_type) {
    case "gateway": return `/gateways/${encodeURIComponent(row.resource_id)}`;
    case "site": return `/sites?site=${encodeURIComponent(row.resource_id)}`;
    case "device": return "/devices";
    case "agent": return `/agents/${encodeURIComponent(row.resource_id)}`;
    case "kubernetes_cluster":
    case "kubernetes_service": return "/kubernetes";
    default: return null;
  }
}

function severityTone(severity: AlertOccurrence["severity"]): "danger" | "warn" | "neutral" {
  return severity === "critical" ? "danger" : severity === "warning" ? "warn" : "neutral";
}

export default function Alerts() {
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const [view, setView] = useState<View>("active");
  const [rows, setRows] = useState<AlertOccurrence[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!org) return;
    setRows(null);
    setError(null);
    const state: AlertOccurrenceState = view === "active" ? "firing" : "resolved";
    const { data, error } = await api.GET("/api/v1/organizations/{orgId}/alert-occurrences", {
      params: { path: { orgId: org.id }, query: { state } },
    });
    if (error) {
      setError(apiErrorMessage(error, "Could not load alerts."));
      return;
    }
    setRows(data ?? []);
  }, [org, view]);

  useEffect(() => { void load(); }, [load]);

  const counts = useMemo(() => ({
    critical: rows?.filter((row) => row.severity === "critical").length ?? 0,
    warning: rows?.filter((row) => row.severity === "warning").length ?? 0,
  }), [rows]);

  if (orgLoading) return <Loading label="Loading alerts…" size="page" />;
  if (orgFailed || !org) return <ErrorText>Could not load the organization for alerts.</ErrorText>;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Alerts"
        subtitle="Persistent product conditions across your network and workloads."
        actions={<div className="flex gap-2"><Button variant="ghost" onClick={() => void load()}>Refresh</Button><Link className="inline-flex min-h-9 items-center rounded-md border border-white/10 px-3 text-cell font-medium text-ink-primary hover:bg-white/5" to="/settings?section=features">Notifications</Link></div>}
      />

      <div className="flex items-center gap-5 border-b border-white/10" role="tablist" aria-label="Alert views">
        {(["active", "history"] as const).map((item) => (
          <button key={item} type="button" role="tab" aria-selected={view === item} onClick={() => setView(item)} className={`border-b-2 px-1 pb-2 text-cell font-medium capitalize ${view === item ? "border-white text-ink-heading" : "border-transparent text-ink-tertiary hover:text-ink-primary"}`}>{item}</button>
        ))}
      </div>

      {view === "active" && rows && rows.length > 0 && (
        <div className="grid grid-cols-3 divide-x divide-white/10 rounded-lg border border-white/10 bg-ink-panel px-1 py-3" aria-label="Active alert summary">
          <div className="px-4"><div className="font-mono text-stat text-ink-heading">{rows.length}</div><div className="text-badge uppercase tracking-wider text-ink-tertiary">Active</div></div>
          <div className="px-4"><div className="font-mono text-stat text-danger">{counts.critical}</div><div className="text-badge uppercase tracking-wider text-ink-tertiary">Critical</div></div>
          <div className="px-4"><div className="font-mono text-stat text-warn">{counts.warning}</div><div className="text-badge uppercase tracking-wider text-ink-tertiary">Warning</div></div>
        </div>
      )}

      {error ? <Card><ErrorText>{error}</ErrorText><Button className="mt-3" variant="ghost" onClick={() => void load()}>Retry</Button></Card> : rows === null ? <Loading label={`Loading ${view} alerts…`} /> : (
        <Card>
          <DataTable
            caption={view === "active" ? "Active alerts" : "Resolved alert history"}
            rows={rows}
            rowKey={(row) => row.id}
            failed={false}
            pageSize={25}
            empty={<EmptyState>{view === "active" ? "No active conditions have been recorded." : "No resolved alerts recorded yet."}</EmptyState>}
            columns={[
              { key: "severity", header: "Severity", cell: (row) => <Badge tone={severityTone(row.severity)}>{row.severity}</Badge>, sortValue: (row) => row.severity },
              { key: "condition", header: "Condition", cell: (row) => <div><div className="font-medium text-ink-heading">{row.subject}</div><div className="mt-0.5 text-badge text-ink-tertiary">{row.event_key}</div></div>, sortValue: (row) => row.subject },
              { key: "resource", header: "Resource", cell: (row) => { const href = resourceHref(row); const label = row.resource_name || row.resource_id; return <div><div className="text-badge text-ink-tertiary">{productLabel(row)}</div>{href ? <Link className="font-medium text-ink-primary hover:underline" to={href}>{label}</Link> : <span>{label}</span>}</div>; }, sortValue: (row) => row.resource_name || row.resource_id },
              { key: "observed", header: view === "active" ? "Last observed" : "Resolved", cell: (row) => relativeAge(view === "active" ? row.last_observed_at : row.resolved_at ?? row.last_observed_at), sortValue: (row) => row.last_observed_at },
            ]}
          />
        </Card>
      )}
    </div>
  );
}
