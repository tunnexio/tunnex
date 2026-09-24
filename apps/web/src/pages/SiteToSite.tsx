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
        ? { kind: "ready", sites: sites.data as Site[], canManage: siteGate({ role, emailVerified: verified }).canManage, permissionError: !members.ok }
        : { ...initial, kind: "error", error: sites.error } });
    });
    return () => { cancelled = true; };
  }, [key, org?.id, loading, failed, userId, verified]);
  return <SiteToSiteView key={key} renderDetails={(first, second) => org ? <SitePairDetails orgId={org.id} first={first} second={second} /> : null} state={result.key === key && !loading ? result.value : initial} onRetry={() => retry(value => value + 1)} />;
}

export function SiteToSiteView({ state, onRetry, renderDetails }: { state: SiteToSiteState; onRetry: () => void; renderDetails?: (first: Site, second: Site) => ReactNode }) {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Site-to-site"
        subtitle="Connect office and cloud networks so their devices can reach each other."
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <section aria-labelledby="wireguard-heading" className="space-y-4">
            <p className="text-sm text-ink-secondary">WireGuard</p>
            <h2 id="wireguard-heading" className="text-xl font-semibold">
              Connect using Tunnex
            </h2>
            <p>
              Use a Tunnex gateway at each location. Devices behind the gateways
              do not need the Tunnex client installed.
            </p>
            <ol className="list-decimal space-y-2 pl-5 text-ink-secondary">
              <li>Add each network using an existing or newly enrolled gateway.</li>
              <li>Review the site routes and allow the traffic you need.</li>
              <li>Configure return routes and test access between devices.</li>
            </ol>
            <div className="flex flex-wrap gap-4">
              {state.canManage && <Link className="underline underline-offset-4" to="/network/setup">
                Add a network
              </Link>}
              <Link className="underline underline-offset-4" to="/sites">
                Manage existing sites
              </Link>
            </div>
          </section>
        </Card>
        <Card>
          <section aria-labelledby="ipsec-heading" className="space-y-4">
            <p className="text-sm text-ink-secondary">IPsec · Not available yet</p>
            <h2 id="ipsec-heading" className="text-xl font-semibold">
              Connect an existing VPN
            </h2>
            <p>
              Planned support for connecting a local Tunnex gateway to a
              compatible cloud-managed VPN or firewall.
            </p>
            <p className="text-ink-secondary">
              This method will not require a Tunnex gateway at the remote VPN
              endpoint. IPsec connections cannot be configured in this release.
            </p>
          </section>
        </Card>
      </div>
      <Card>
        <section aria-labelledby="networks-heading" className="space-y-3">
          <h2 id="networks-heading" className="text-lg font-semibold">Your existing networks</h2>
          {state.kind === "loading" && <p role="status">Loading networks…</p>}
          {state.kind === "error" && <div role="alert"><p>{state.error}</p><Button onClick={state.reloadPage ? () => window.location.reload() : onRetry}>{state.reloadPage ? "Reload page" : "Retry networks"}</Button></div>}
          {state.kind === "ready" && <>
            <p className="text-ink-secondary">These are configured sites, not verified connections. Open a site to review gateways, routes and access.</p>
            {state.sites.length === 0 ? <p>No networks configured yet.</p> :
              <ul className="space-y-2">{state.sites.map(site => <li key={site.id} className="break-words"><Link className="underline underline-offset-4" to={`/sites?site=${encodeURIComponent(site.id)}`}>{site.name}</Link></li>)}</ul>}
            {state.permissionError && <div role="alert"><p>Could not check your setup permissions.</p><Button onClick={onRetry}>Retry permissions</Button></div>}
            {!state.canManage && !state.permissionError && <p className="text-ink-secondary">Network setup requires a verified account with site management permission. Contact your administrator if you need access.</p>}
          </>}
        </section>
      </Card>
      {state.kind === "ready" && renderDetails && <Card><SitePairReview sites={state.sites} renderDetails={renderDetails} /></Card>}
      <Card>
        <section aria-labelledby="access-heading" className="space-y-3">
          <h2 id="access-heading" className="text-lg font-semibold">
            Choose what can communicate
          </h2>
          <p className="text-ink-secondary">
            Review your access policies and routes before connecting networks. A gateway handshake confirms the tunnel;
            test a destination device to verify the full network path.
          </p>
          <div className="flex flex-wrap gap-4">
            <Link className="underline underline-offset-4" to="/access">
              Review access policies
            </Link>
            <Link className="underline underline-offset-4" to="/routed-ranges">
              Review routed ranges
            </Link>
          </div>
        </section>
      </Card>
    </div>
  );
}
