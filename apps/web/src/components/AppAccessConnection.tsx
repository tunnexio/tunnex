import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { Badge, Button, Card, ErrorText, Loading } from "./ui";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";

type Check = components["schemas"]["AppAccessCheck"];
type Runtime = components["schemas"]["AppAccessGatewayRuntime"];
const gatewayLabels: Record<Runtime["status"], string> = {
  unknown: "Applications capability has not been reported.",
  unsupported: "This gateway does not support the required Applications connector version.",
  unavailable: "The gateway's Applications report is no longer current.",
  supported: "The gateway supports Applications connection checks.",
};
const failures: Record<Check["error_code"], string> = {
  "": "",
  dns_failed: "The gateway could not resolve the origin.",
  target_refused: "The destination is outside the saved origin policy.",
  connect_failed: "The gateway could not connect to the origin.",
  tls_failed: "Origin TLS verification failed. Check the hostname and trusted CA.",
  http_failed: "The origin did not complete a bounded HTTP response.",
  deadline_exceeded: "The connection check timed out.",
  assignment_changed: "The saved application changed during this check.",
  feature_withdrawn: "Applications was turned off or became unavailable during this check.",
  connector_failed: "The connector could not complete this check.",
};

export default function AppAccessConnection({ orgId, appId, gatewayId, version, revision = version, canCheck, dirty, onCheck }: {
  orgId: string; appId: string; gatewayId: string; version: number; revision?: number; canCheck: boolean; dirty: boolean; onCheck?: (check: Check | null) => void;
}) {
  const [runtime, setRuntime] = useState<Runtime | null>(null);
  const [check, setCheck] = useState<Check | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  useEffect(() => {
    let cancelled = false; setRuntime(null); setError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/gateways/{gatewayId}/status", { params: { path: { orgId, gatewayId } } })).then(result => {
      if (cancelled) return;
      if (result.ok) setRuntime(result.data); else setError(result.error);
    });
    return () => { cancelled = true; };
  }, [orgId, gatewayId, refresh]);
  useEffect(() => { setCheck(null); }, [orgId, appId, gatewayId, version]);
  useEffect(() => { onCheck?.(check); }, [check, onCheck]);
  useEffect(() => {
    if (!check || (check.status !== "queued" && check.status !== "running")) return;
    let cancelled = false;
    const timeout = window.setTimeout(() => {
      void loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/checks/{checkId}", { params: { path: { orgId, appId, checkId: check.id } } })).then(result => {
        if (cancelled) return;
        if (result.ok) { setCheck(result.data); setError(""); }
        else setError(result.error);
      });
    }, 1000);
    return () => { cancelled = true; window.clearTimeout(timeout); };
  }, [orgId, appId, check]);
  const request = async () => {
    if (!canCheck || dirty || busy || runtime?.status !== "supported") return;
    setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/app-access/applications/{appId}/checks", { params: { path: { orgId, appId } }, body: { expected_version: version } });
      if (result.error || !result.data) {
        setError(apiErrorCode(result.error) === "version_conflict" || apiErrorCode(result.error) === "stale_version" ? "The saved application changed. Reopen it before checking the connection." : apiErrorMessage(result.error, "Could not request a connection check."));
      } else setCheck(result.data);
    } catch { setError("Could not reach the API. Retry to check the saved application."); }
    finally { setBusy(false); }
  };
  const pending = check?.status === "queued" || check?.status === "running";
  const outdated = check !== null && (check.revision !== revision || dirty);
  return <Card className="space-y-4"><div className="app-access-panel-header"><div><h3 className="font-semibold">Connection check</h3><p className="text-sm text-ink-secondary">Verify the saved origin through its gateway.</p></div>{runtime && <Badge tone={runtime.status === "supported" ? "neutral" : runtime.status === "unsupported" ? "warn" : "unknown"}>{runtime.status === "supported" ? "Supported" : runtime.status === "unsupported" ? "Unsupported" : runtime.status === "unavailable" ? "Unavailable" : "Not reported"}</Badge>}</div>
    {runtime ? <p role="status" className="text-sm">{gatewayLabels[runtime.status]}</p> : !error && <Loading size="inline" label="Loading gateway capability…" />}
    {runtime?.reported_at && <p className="text-sm text-ink-secondary">Gateway report: {new Date(runtime.reported_at).toLocaleString()}</p>}
    <div className="app-access-toolbar"><Button variant="ghost" onClick={() => setRefresh(n => n + 1)}>Refresh gateway status</Button>
      {canCheck && <Button disabled={busy || pending || dirty || runtime?.status !== "supported"} onClick={() => void request()}>{busy ? "Requesting check…" : pending ? "Checking connection…" : "Check saved connection"}</Button>}</div>
    {dirty && <p className="text-sm">Save your changes before checking the connection.</p>}
    <ErrorText>{error}</ErrorText>
    {check && <div className="space-y-3 border-t border-line pt-4"><p role="status" className="font-medium">{check.status === "succeeded" ? "Origin connection succeeded." : check.status === "failed" ? "Origin connection failed." : check.status === "expired" ? "Connection check expired." : check.status === "withdrawn" ? "Connection check was withdrawn." : "Connection check is pending."}</p>
      <p className="text-sm">Saved revision {check.revision} · Requested {new Date(check.created_at).toLocaleString()}</p>
      {outdated && <p className="text-sm">This result does not cover your current unsaved changes.</p>}
      <ul className="app-access-data-list text-sm" aria-label="Origin check results">{[["DNS", check.dns_status], ["Connection", check.connect_status], ["TLS", check.tls_status]].map(([label, status]) => <li key={label} className="app-access-data-row"><span>{label}: {status}</span><Badge tone={status === "passed" ? "neutral" : status === "failed" ? "danger" : "neutral"}>{status}</Badge></li>)}</ul>
      {failures[check.error_code] && <p>{failures[check.error_code]}</p>}
      {error && pending && <Button variant="ghost" onClick={() => setCheck(current => current ? { ...current } : null)}>Retry check status</Button>}
    </div>}
    <p className="text-sm text-ink-secondary">Checks cover the saved origin connection. Connection checks do not change the active publication.</p>
  </Card>;
}
