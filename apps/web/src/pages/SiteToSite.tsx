import { Button as ActionButton } from "../components/ui/button";
import { IPsecWorkspace } from "../components/IPsecWorkspace";
import { SiteToSiteNavigation } from "../components/SiteToSiteNavigation";
import { useEffect, useState, type ReactNode } from "react";
import { api, loadOne, type Site, type Member } from "../lib/api";
import { SitePairReview, SitePairDetails } from "../components/SitePairReview";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { siteGate } from "../lib/sitesview";
import { Link } from "react-router-dom";
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
  return <SiteToSiteView ipsecWorkspace={!loading && org && result.key === key && result.value.kind === "ready" ? <IPsecWorkspace orgId={org.id} userId={userId} emailVerified={verified} role={result.value.role} sites={result.value.sites} /> : undefined} key={key} renderDetails={(first, second) => org ? <SitePairDetails orgId={org.id} first={first} second={second} /> : null} state={result.key === key && !loading ? result.value : initial} onRetry={() => retry(value => value + 1)} />;
}

export function SiteToSiteView({ state, onRetry, renderDetails, ipsecWorkspace }: { ipsecWorkspace?: ReactNode; state: SiteToSiteState; onRetry: () => void; renderDetails?: (first: Site, second: Site) => ReactNode }) {
  const [method, setMethod] = useState<"wireguard" | "ipsec">("wireguard");
  return <div className="space-y-6">
    <PageHeader title="Site-to-site" subtitle="Review network connectivity." actions={method === "wireguard" && state.canManage ?
      <ActionButton asChild><Link to="/network/setup">Add a network</Link></ActionButton> : undefined} />
    <SiteToSiteNavigation active="connectivity" />
    <div className="flex gap-2" role="group" aria-label="Connection method">
      <ActionButton variant={method === "wireguard" ? "default" : "outline"} aria-pressed={method === "wireguard"} onClick={() => setMethod("wireguard")}>WireGuard</ActionButton>
      <ActionButton variant={method === "ipsec" ? "default" : "outline"} aria-pressed={method === "ipsec"} onClick={() => setMethod("ipsec")}>IPsec</ActionButton>
    </div>
    {method === "ipsec" ? ipsecWorkspace ?? <Card><p>Load your networks to view IPsec.</p><Button onClick={onRetry}>Retry</Button></Card> : <>
    <Card>
      {state.kind === "loading" && <p role="status">Loading networks…</p>}
      {state.kind === "error" && <div role="alert"><p>{state.error}</p><Button onClick={state.reloadPage ? () => window.location.reload() : onRetry}>{state.reloadPage ? "Reload page" : "Retry networks"}</Button></div>}
      {state.kind === "ready" && <>
        {state.sites.length === 0 ? <p>No networks configured yet.</p> : renderDetails ? <SitePairReview sites={state.sites} renderDetails={renderDetails} /> : null}
        {state.permissionError && <div role="alert" className="mt-4"><p>Could not check your setup permissions.</p><Button onClick={onRetry}>Retry permissions</Button></div>}
        {!state.canManage && !state.permissionError && <p className="mt-4 text-sm text-ink-secondary">Setup requires a verified site manager. Contact your administrator for access.</p>}
      </>}
    </Card>
    <div className="flex flex-wrap gap-3">
      <ActionButton asChild variant="outline"><Link to="/access">Review access policies</Link></ActionButton>
      <ActionButton asChild variant="outline"><Link to="/routed-ranges">Review routed ranges</Link></ActionButton>
    </div>
    <details className="text-sm text-ink-secondary">
      <summary className="cursor-pointer font-medium text-ink-primary">Setup guide</summary>
      <ol className="mt-3 list-decimal space-y-2 pl-5">
        <li>Add a gateway and network ranges at each location.</li>
        <li>Approve ranges and allow the required traffic.</li>
        <li>Configure return routes and test between devices.</li>
      </ol>
    </details>
    </>}
  </div>;
}
