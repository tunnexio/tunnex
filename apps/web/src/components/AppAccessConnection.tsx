import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { Badge, Button, ErrorText, Loading, RefreshButton } from "./ui";
import { ResourceSummary } from "./ResourceSummary";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { suggestedOriginRange } from "../lib/appaccessorigin";
import { FirewallHelp, gatewayAddress } from "./FirewallHelp";

type Check = components["schemas"]["AppAccessCheck"];
type Runtime = components["schemas"]["AppAccessGatewayRuntime"];
const gatewayLabels: Record<Runtime["status"], string> = {
  unknown: "Applications capability has not been reported.",
  unsupported: "This gateway does not support the required Applications connector version.",
  unavailable: "The gateway's Applications report is no longer current.",
  supported: "The gateway supports Applications connection checks.",
};
export const failures: Record<Check["error_code"], string> = {
  "": "",
  dns_failed: "The gateway could not resolve the origin.",
  target_refused: "The gateway refused this destination: the saved origin policy does not allow it. Private origins need their address range listed under Advanced connection settings → Allowed private destination ranges. Add the origin's range there, save, and check again.",
  connect_failed: "The gateway could not connect to the origin.",
  tls_failed: "Origin TLS verification failed. Check the hostname and trusted CA.",
  http_failed: "The origin did not complete a bounded HTTP response.",
  deadline_exceeded: "The connection check timed out.",
  assignment_changed: "The saved application changed during this check.",
  feature_withdrawn: "Applications was turned off or became unavailable during this check.",
  connector_failed: "The connector could not complete this check.",
};

/** Origin host and port for reachability guidance (AA-2). */
export function originTarget(originUrl: string): { host: string; port: number } | null {
  try { const url = new URL(originUrl); return { host: url.hostname.replace(/^\[|\]$/g, ""), port: url.port ? Number(url.port) : url.protocol === "http:" ? 80 : 443 }; } catch { return null; }
}

export default function AppAccessConnection({ orgId, appId, gatewayId, version, revision = version, canCheck, dirty, onCheck, embedded = false, originUrl = "", allowedCidrs = [], onAllowDestination, gateway }: {
  orgId: string; appId: string; gatewayId: string; version: number; revision?: number; canCheck: boolean; dirty: boolean; onCheck?: (check: Check | null) => void; embedded?: boolean;
  /** The SAVED origin URL and allowed ranges the check ran against, for target_refused guidance. */
  originUrl?: string; allowedCidrs?: string[];
  /** Fills a suggested range into the draft (the admin still saves and re-checks). Omitted when the viewer cannot edit. */
  onAllowDestination?: (cidr: string) => void;
  /** The connector gateway, for firewall examples when the origin cannot be reached. */
  gateway?: { name: string; endpoint?: string | null };
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
  // Only report checks this view actually ran: mounting with no result must not erase a
  // passing check the review step still relies on (the parent drops checks on save).
  useEffect(() => { if (check) onCheck?.(check); }, [check, onCheck]);
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
  const capability = runtime && <Badge tone={runtime.status === "supported" ? "neutral" : runtime.status === "unsupported" ? "warn" : "unknown"}>{runtime.status === "supported" ? "Supported" : runtime.status === "unsupported" ? "Unsupported" : runtime.status === "unavailable" ? "Unavailable" : "Not reported"}</Badge>;
  const content = <div className="space-y-4">
    {runtime ? <p role="status" className="text-sm">{gatewayLabels[runtime.status]}</p> : !error && <Loading size="inline" label="Loading gateway capability…" />}
    {runtime?.reported_at && <p className="text-sm text-ink-secondary">Gateway report: {new Date(runtime.reported_at).toLocaleString()}</p>}
    <div className="app-access-toolbar"><RefreshButton label="Refresh gateway status" onClick={() => setRefresh(n => n + 1)} />
      {canCheck && <Button disabled={busy || pending || dirty || runtime?.status !== "supported"} onClick={() => void request()}>{busy ? "Requesting check…" : pending ? "Checking connection…" : "Check saved connection"}</Button>}</div>
    {dirty && <p className="text-sm">Save your changes before checking the connection.</p>}
    <ErrorText>{error}</ErrorText>
    {check && <div className="aa-connection-result space-y-4"><p role="status" className="font-medium">{check.status === "succeeded" ? "Origin connection succeeded." : check.status === "failed" ? "Origin connection failed." : check.status === "expired" ? "Connection check expired." : check.status === "withdrawn" ? "Connection check was withdrawn." : "Connection check is pending."}</p>
      <dl className="tnx-resource-facts" aria-label="Connection check details"><div><dt>Saved revision</dt><dd>{check.revision}</dd></div><div><dt>Requested</dt><dd>{new Date(check.created_at).toLocaleString()}</dd></div></dl>
      {outdated && <p className="text-sm">This result does not cover your current unsaved changes.</p>}
      <dl className="tnx-resource-facts aa-connection-results" aria-label="Origin check results">{[["DNS", check.dns_status], ["Connection", check.connect_status], ["TLS", check.tls_status]].map(([label, status]) => <div key={label}><dt>{label}</dt><dd><Badge tone={status === "passed" ? "neutral" : status === "failed" ? "danger" : "neutral"}>{status}</Badge></dd></div>)}</dl>
      {check.error_code === "target_refused" ? <TargetRefused originUrl={originUrl} allowedCidrs={allowedCidrs} onAllow={onAllowDestination} /> : failures[check.error_code] && <p>{failures[check.error_code]}</p>}
      {(check.error_code === "connect_failed" || check.error_code === "deadline_exceeded") && originTarget(originUrl) && <FirewallHelp summary="Can't reach the origin?" gatewayName={gateway?.name ?? "for this application"} gatewayIp={gatewayAddress(gateway?.endpoint)} host={originTarget(originUrl)!.host} port={originTarget(originUrl)!.port} />}
      {error && pending && <Button variant="ghost" onClick={() => setCheck(current => current ? { ...current } : null)}>Retry check status</Button>}
    </div>}
    <p className="text-sm text-ink-secondary">Checks cover the saved origin connection. Connection checks do not change the active publication.</p>
  </div>;
  return embedded ? <section className="aa-connection-embedded" aria-label="Connection check"><div className="aa-connection-heading"><div><h3>Connection check</h3><p>Verify the saved origin through its gateway.</p></div>{capability}</div>{content}</section> : <ResourceSummary title="Connection check" className="aa-connection-summary" description="Verify the saved origin through its gateway." actions={capability}>{content}</ResourceSummary>;
}

function TargetRefused({ originUrl, allowedCidrs, onAllow }: { originUrl: string; allowedCidrs: string[]; onAllow?: (cidr: string) => void }) {
  const [added, setAdded] = useState("");
  const suggestion = suggestedOriginRange(originUrl, allowedCidrs);
  if (!suggestion || suggestion.covered) return <p>{failures.target_refused}</p>;
  return <div className="space-y-2">
    <p>The gateway refused this destination: {suggestion.address} is a private address, and private origins need their range allowed. Add {suggestion.range} under Advanced connection settings → Allowed private destination ranges, save, and check again.</p>
    {onAllow && (added ? <p role="status" className="text-sm">Added {added} to Allowed private destination ranges. Save the draft, then check the connection again.</p>
      : <Button variant="ghost" type="button" onClick={() => { onAllow(suggestion.range); setAdded(suggestion.range); }}>Allow {suggestion.range}</Button>)}
  </div>;
}
