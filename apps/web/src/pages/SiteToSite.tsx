import "../network-workspaces.css";
import "../app-access-workspace.css";
import "../site-to-site-workspace.css";
import { Button as ActionButton } from "../components/ui/button";
import { IPsecWorkspace } from "../components/IPsecWorkspace";
import { SiteToSiteNavigation } from "../components/SiteToSiteNavigation";
import { useEffect, useState, type ReactNode } from "react";
import { api, loadOne, type Site, type Member } from "../lib/api";
import { SitePairReview, SitePairDetails } from "../components/SitePairReview";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { siteGate } from "../lib/sitesview";
import { Link, useSearchParams } from "react-router-dom";
import { ConnectionChooser } from "../components/ConnectionChooser";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import { Button, Loading, PageHeader } from "../components/ui";

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
  const [params, setParams] = useSearchParams();
  const method = params.get("method") === "ipsec" ? "ipsec" : "wireguard";
  const setMethod = (value: "wireguard" | "ipsec") => setParams(previous => { const next = new URLSearchParams(previous); next.set("method", value); return next; });
  const [choosing, setChoosing] = useState(false);
  const [createRequest, setCreateRequest] = useState(0);
  return <div className="site-to-site-workspace s2s-connections-workspace network-management">
    <PageHeader navigationTitle title="Site-to-site" />
    <div className="s2s-workspace-toolbar">
      <SiteToSiteNavigation active="connectivity" />
      <div className="s2s-toolbar-actions">
        {method === "wireguard" && <ActionButton size="sm" variant="ghost" disabled={state.kind === "loading"} onClick={onRetry}>Refresh</ActionButton>}
        {state.canManage && <ActionButton size="sm" onClick={() => setChoosing(true)}>Create connection</ActionButton>}
      </div>
    </div>
    <fieldset className="connection-purpose">
      <legend className="sr-only">What would you like to connect?</legend>
      <label className={`connection-purpose-option ${method === "wireguard" ? "is-selected" : ""}`}>
        <input type="radio" name="connection-purpose" value="wireguard" checked={method === "wireguard"} onChange={() => setMethod("wireguard")} />
        <span><strong>Between your networks</strong><small>WireGuard</small></span>
      </label>
      <label className={`connection-purpose-option ${method === "ipsec" ? "is-selected" : ""}`}>
        <input type="radio" name="connection-purpose" value="ipsec" checked={method === "ipsec"} onChange={() => setMethod("ipsec")} />
        <span><strong>To a cloud VPN</strong><small>IPsec · AWS</small></span>
      </label>
    </fieldset>
    {method === "ipsec" ? (renderIPsecWorkspace ? renderIPsecWorkspace(createRequest, () => setChoosing(true), () => setCreateRequest(0)) : ipsecWorkspace) ?? <section className="s2s-connection-state"><p>Load your networks to view IPsec.</p><Button onClick={onRetry}>Retry</Button></section> : <>
    <section className="s2s-connection-content">
      {state.kind === "loading" && <Loading label="Loading networks…" />}
      {state.kind === "error" && <div role="alert"><p>{state.error}</p><Button onClick={state.reloadPage ? () => window.location.reload() : onRetry}>{state.reloadPage ? "Reload page" : "Retry networks"}</Button></div>}
      {state.kind === "ready" && <>
        {state.sites.length < 2 ? <AppAccessEmptyState icon={null} title="No WireGuard links" description={state.sites.length === 0 ? "No networks configured yet." : "A second network is required."} action={state.sites.length === 1 && state.canManage ? <ActionButton asChild size="sm" variant="outline"><Link to="/sites">Go to Networks</Link></ActionButton> : undefined} /> : renderDetails ? <SitePairReview sites={state.sites} renderDetails={renderDetails} /> : <p className="text-sm text-ink-secondary">Link details unavailable.</p>}
        {state.permissionError && <div role="alert" className="mt-4"><p>Could not check your setup permissions.</p><Button onClick={onRetry}>Retry permissions</Button></div>}
        {!state.canManage && !state.permissionError && <p className="mt-4 text-sm text-ink-secondary">Setup requires a verified site manager. Contact your administrator for access.</p>}
      </>}
    </section>
    <details className="s2s-disclosure s2s-setup-requirements">
      <summary className="cursor-pointer">Setup requirements</summary>
      <p className="mt-2">A gateway and approved ranges at each location, one reachable public WireGuard hub, access policies and return routes. Links are configured automatically.</p>
    </details>
    </>}
    {state.canManage && choosing && <ConnectionChooser orgId={orgId} sites={state.sites} onClose={() => setChoosing(false)} onAWS={() => { setChoosing(false); setMethod("ipsec"); setCreateRequest(value => value + 1); }} />}
  </div>;
}
