import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AlertManagement } from "../components/AlertManagement";
import { Badge, Button, Card, DataTable, EmptyState, ErrorText, Loading, Modal, PageHeader } from "../components/ui";
import { api, apiErrorMessage, type AlertOccurrence, type AlertOccurrenceState, type Role } from "../lib/api";
import { useAuth } from "../lib/auth";
import { relativeAge } from "../lib/format";
import { can } from "../lib/rbac";
import { useOrg } from "../lib/useOrg";

import "../network-workspaces.css";
import "../alerts-workspace.css";

type View = "active" | "history" | "management";

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
  const { state: authState } = useAuth();
  const [severity, setSeverity] = useState("all");
  const [inspected, setInspected] = useState<AlertOccurrence | null>(null);
  const [view, setView] = useState<View>("active");
  const [rows, setRows] = useState<AlertOccurrence[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);

  const load = useCallback(async () => {
    if (!org || view === "management") return;
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
  useEffect(() => {
    if (!org || authState.status !== "authed") return;
    let cancelled = false;
    void api.GET("/api/v1/organizations/{orgId}/members", {
      params: { path: { orgId: org.id } },
    }).then((response) => {
      if (!cancelled) setMyRole(response.data?.find((member) => member.user_id === authState.user.id)?.role);
    });
    return () => { cancelled = true; };
  }, [authState, org]);

  const canManage = can(myRole, "alerting:manage");
  const emailVerified = authState.status === "authed" && authState.user.email_verified;

  const counts = useMemo(() => ({
    critical: rows?.filter((row) => row.severity === "critical").length ?? 0,
    warning: rows?.filter((row) => row.severity === "warning").length ?? 0,
  }), [rows]);

  if (orgLoading) return <Loading label="Loading alerts…" size="page" />;
  if (orgFailed || !org) return <ErrorText>Could not load the organization for alerts.</ErrorText>;

  return (
    <div className="network-management alerts-workspace">
      <PageHeader
        title="Alerts"
        subtitle={org.name}
        actions={view !== "management" ? <Button variant="ghost" onClick={() => void load()}>Refresh</Button> : undefined}
      />

      <div className="flex items-center gap-5 border-b border-white/10" role="tablist" aria-label="Alert views">
        {(["active", "history", ...(canManage ? ["management" as const] : [])] as View[]).map((item) => (
          <button key={item} type="button" role="tab" aria-selected={view === item} onClick={() => { setView(item); setSeverity("all"); }} className={`border-b-2 px-1 pb-2 text-cell font-medium capitalize ${view === item ? "border-white text-ink-heading" : "border-transparent text-ink-tertiary hover:text-ink-primary"}`}>{item}</button>
        ))}
      </div>

      {view === "management" && canManage ? (
        <AlertManagement orgId={org.id} canEdit={emailVerified} canAllowPrivate={myRole === "owner"} />
      ) : <>
      {rows && !error && (
        <section className="tnx-card-surface alerts-summary" aria-label={view === "active" ? "Active alert summary" : "Resolved alert summary"}>
          <div><span>{view === "active" ? "Active conditions" : "Resolved conditions"}</span><strong>{rows.length}</strong></div>
          <div><span>Critical</span><strong className="text-danger">{counts.critical}</strong></div>
          <div><span>Warning</span><strong className="text-warn">{counts.warning}</strong></div>
        </section>
      )}

      {error ? <Card><ErrorText>{error}</ErrorText><Button className="mt-3" variant="ghost" onClick={() => void load()}>Retry</Button></Card> : rows === null ? <Loading label={`Loading ${view} alerts…`} /> : (
        <Card className="alerts-inventory">
          <div className="alerts-inventory-heading">
            <h2>{view === "active" ? "Needs attention" : "Resolved history"}</h2>
            <div className="alerts-filters" aria-label="Filter severity">
              {["all", "critical", "warning", "info"].map(value => <button type="button" key={value} aria-pressed={severity === value} onClick={() => setSeverity(value)}>{value === "all" ? "All severities" : value}</button>)}
            </div>
          </div>
          <DataTable
            caption={view === "active" ? "Active alerts" : "Resolved alert history"}
            rows={rows.filter(row => severity === "all" || row.severity === severity)}
            rowKey={(row) => row.id}
            failed={false}
            pageSize={25}
            empty={<EmptyState>{severity !== "all" ? "No alerts match this severity." : view === "active" ? "No active conditions have been recorded." : "No resolved alerts recorded yet."}</EmptyState>}
            columns={[
              { key: "severity", header: "Severity", cell: (row) => <Badge tone={severityTone(row.severity)}>{row.severity}</Badge>, sortValue: (row) => row.severity },
              { key: "condition", header: "Condition", cell: (row) => <div><button type="button" className="alert-open" onClick={() => setInspected(row)}>{row.subject}<span aria-hidden="true">↗</span></button></div>, sortValue: (row) => row.subject },
              { key: "resource", header: "Resource", cell: (row) => { const href = resourceHref(row); const label = row.resource_name || row.resource_id; return <div><div className="text-badge text-ink-tertiary">{productLabel(row)}</div>{href ? <Link className="alert-resource-link" to={href}>{label}</Link> : <span>{label}</span>}</div>; }, sortValue: (row) => row.resource_name || row.resource_id },
              { key: "observed", header: view === "active" ? "Last observed" : "Resolved", cell: (row) => relativeAge(view === "active" ? row.last_observed_at : row.resolved_at ?? row.last_observed_at), sortValue: (row) => view === "active" ? row.last_observed_at : row.resolved_at ?? row.last_observed_at },
            ]}
          />
        </Card>
      )}
      </>}
      {inspected && <Modal title={inspected.subject} size="wide" onDismiss={() => setInspected(null)} actions={<Button variant="ghost" onClick={() => setInspected(null)}>Close</Button>}>
        <div className="alert-detail-state"><Badge tone={severityTone(inspected.severity)}>{inspected.severity}</Badge><span>{inspected.state === "firing" ? "Active condition" : "Resolved"}</span></div>
        <dl className="alert-detail-facts">
          <div><dt>Resource</dt><dd>{inspected.resource_name || inspected.resource_id}</dd></div>
          <div><dt>Product</dt><dd>{productLabel(inspected)}</dd></div>
          <div><dt>First observed</dt><dd>{new Date(inspected.first_observed_at).toLocaleString()}</dd></div>
          <div><dt>Last observed</dt><dd>{new Date(inspected.last_observed_at).toLocaleString()}</dd></div>
          <div><dt>Occurrences</dt><dd>{inspected.occurrence_count}</dd></div>
          <div><dt>Signal</dt><dd>{inspected.event_key}</dd></div>
          {inspected.resolved_at && <div><dt>Resolved</dt><dd>{new Date(inspected.resolved_at).toLocaleString()}</dd></div>}
        </dl>
        {resourceHref(inspected) && <Link className="alert-detail-link" to={resourceHref(inspected)!}>Open {productLabel(inspected).toLowerCase()} →</Link>}
      </Modal>}
    </div>
  );
}
