import "../network-workspaces.css";
import { Button as ActionButton } from "../components/ui/button";
import { WireGuardDemo } from "../components/WireGuardDemo";
import { IPsecWorkspace } from "../components/IPsecWorkspace";
import { SiteToSiteNavigation } from "../components/SiteToSiteNavigation";
import { useEffect, useState, type ReactNode } from "react";
import { api, loadOne, type Site, type Member } from "../lib/api";
import { SitePairReview, SitePairDetails } from "../components/SitePairReview";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { siteGate } from "../lib/sitesview";
import { Link } from "react-router-dom";
import { ConnectionChooser } from "../components/ConnectionChooser";
import { Button, Card, PageHeader } from "../components/ui";

export type SiteToSiteState = {
  kind: "loading" | "error" | "ready";
  sites: Site[];
  canManage: boolean;
  role?: string;
  error?: string;
  permissionError?: boolean;
  reloadPage?: boolean;
};
const initial: SiteToSiteState = { kind: "loading", sites: [], canManage: false };

export default function SiteToSite() {
  const { org, loading, failed } = useOrg();
  const { state: auth } = useAuth();
  const userId = auth.status === "authed" ? auth.user.id : "";
  const verified = auth.status === "authed" && auth.user.email_verified;
  const [attempt, retry] = useState(0);
  const [result, setResult] = useState<{ key: string; value: SiteToSiteState }>({ key: "", value: initial });
  const key = `${org?.id ?? ""}:${userId}:${verified}:${attempt}`;
  useEffect(() => {
    let cancelled = false;
    setResult({ key, value: initial });
    if (loading) return;
    if (!org) {
      setResult({ key, value: { ...initial, kind: "error", reloadPage: failed, error: failed ? "Could not load your organizations." : "Select an organization to view its networks." } });
      return;
    }
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path: { orgId: org.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId: org.id } } })),
    ]).then(([sites, members]) => {
      if (cancelled) return;
      const role = members.ok ? (members.data as Member[]).find(member => member.user_id === userId)?.role : undefined;
      setResult({ key, value: sites.ok
        ? { kind: "ready", sites: sites.data as Site[], canManage: siteGate({ role, emailVerified: verified }).canManage, permissionError: !members.ok, role }
        : { ...initial, kind: "error", error: sites.error } });
    });
    return () => { cancelled = true; };
  }, [key, org?.id, loading, failed, userId, verified]);
  return <SiteToSiteView orgId={org?.id} renderIPsecWorkspace={(createRequest, onRequestCreate, onCreateHandled) => !loading && org && result.key === key && result.value.kind === "ready" ? <IPsecWorkspace onCreateHandled={onCreateHandled} createRequest={createRequest} onRequestCreate={onRequestCreate} orgId={org.id} userId={userId} emailVerified={verified} role={result.value.role} sites={result.value.sites} /> : undefined} key={key} renderDetails={(first, second) => org ? <SitePairDetails orgId={org.id} first={first} second={second} /> : null} state={result.key === key && !loading ? result.value : initial} onRetry={() => retry(value => value + 1)} />;
}

export function SiteToSiteView({ orgId, state, onRetry, renderDetails, ipsecWorkspace, renderIPsecWorkspace }: { orgId?: string; ipsecWorkspace?: ReactNode; renderIPsecWorkspace?: (request: number, onCreate: () => void, onHandled: () => void) => ReactNode; state: SiteToSiteState; onRetry: () => void; renderDetails?: (first: Site, second: Site) => ReactNode }) {
  const [method, setMethod] = useState<"wireguard" | "ipsec">("wireguard");
  const [demo, setDemo] = useState(false);
  const [choosing, setChoosing] = useState(false);
  const [createRequest, setCreateRequest] = useState(0);
  return <div className="network-management space-y-5">
    <PageHeader title="Site-to-site" subtitle="Connect entire networks through gateways." actions={state.canManage && !demo ? <ActionButton onClick={() => setChoosing(true)}>Create connection</ActionButton> : undefined} />
    <SiteToSiteNavigation active="connectivity" />
    <div className="network-filter-tabs" role="group" aria-label="Connection method">
      <ActionButton variant="ghost" className={method === "wireguard" ? "network-filter-active" : ""} aria-pressed={method === "wireguard"} onClick={() => setMethod("wireguard")} aria-label="WireGuard">Tunnex to Tunnex · WireGuard</ActionButton>
      <ActionButton variant="ghost" className={method === "ipsec" ? "network-filter-active" : ""} aria-pressed={method === "ipsec"} onClick={() => { setDemo(false); setMethod("ipsec"); }} aria-label="IPsec">Cloud VPN / Firewall · IPsec</ActionButton>
    </div>
    {method === "ipsec" ? (renderIPsecWorkspace ? renderIPsecWorkspace(createRequest, () => setChoosing(true), () => setCreateRequest(0)) : ipsecWorkspace) ?? <Card><p>Load your networks to view IPsec.</p><Button onClick={onRetry}>Retry</Button></Card> : demo ? <WireGuardDemo embedded onExit={() => setDemo(false)} /> : <>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 className="text-section font-semibold text-ink-heading">Tunnex to Tunnex</h2><p className="mt-1 text-cell text-ink-tertiary">Automatically managed links.</p></div>
      <div className="flex gap-2"><ActionButton variant="ghost" onClick={() => setDemo(true)}>View demo</ActionButton><ActionButton variant="outline" onClick={onRetry}>Refresh</ActionButton></div>
    </div>
    <Card>
      {state.kind === "loading" && <p role="status">Loading networks…</p>}
      {state.kind === "error" && <div role="alert"><p>{state.error}</p><Button onClick={state.reloadPage ? () => window.location.reload() : onRetry}>{state.reloadPage ? "Reload page" : "Retry networks"}</Button></div>}
      {state.kind === "ready" && <>
        {state.sites.length < 2 ? <div className="flex flex-wrap items-center justify-between gap-4">
          <div><h3 className="font-semibold text-ink-heading">No WireGuard links</h3><p className="mt-1 text-sm text-ink-secondary">{state.sites.length === 0 ? "No networks configured yet." : "A second network is required."}</p></div>
          {state.sites.length === 1 && state.canManage && <ActionButton asChild variant="outline"><Link to="/sites">Go to Networks</Link></ActionButton>}
        </div> : renderDetails ? <SitePairReview sites={state.sites} renderDetails={renderDetails} /> : <p className="text-sm text-ink-secondary">Link details unavailable.</p>}
        {state.permissionError && <div role="alert" className="mt-4"><p>Could not check your setup permissions.</p><Button onClick={onRetry}>Retry permissions</Button></div>}
        {!state.canManage && !state.permissionError && <p className="mt-4 text-sm text-ink-secondary">Setup requires a verified site manager. Contact your administrator for access.</p>}
      </>}
    </Card>
    <details className="text-cell text-ink-tertiary">
      <summary className="cursor-pointer">Setup requirements</summary>
      <p className="mt-2">A gateway and approved ranges at each location, one reachable public WireGuard hub, access policies and return routes. Links are configured automatically.</p>
    </details>
    </>}
    {state.canManage && choosing && <ConnectionChooser orgId={orgId} sites={state.sites} onClose={() => setChoosing(false)} onAWS={() => { setChoosing(false); setMethod("ipsec"); setCreateRequest(value => value + 1); }} />}
  </div>;
}
