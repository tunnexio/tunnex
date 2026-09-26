import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, loadOne, type Loaded, type Node, type Site, type SiteSubnet, type HubSet } from "../lib/api";
import { policyHealthBadge, siteLinkNote } from "../lib/healthview";
import "../site-pair.css";
import { NetworkDetailList } from "./NetworkDetailList";
import { Icon } from "./Icon";
import { Badge, Button, Card, Field, Select } from "./ui";

export function SitePairReview({ sites, renderDetails }: {
  sites: Site[];
  renderDetails: (first: Site, second: Site) => ReactNode;
}) {
  const [firstId, setFirstId] = useState("");
  const [secondId, setSecondId] = useState("");
  const first = sites.find(site => site.id === firstId);
  const second = sites.find(site => site.id === secondId);
  return <section aria-labelledby="pair-heading" className="site-pair-review space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div><h2 id="pair-heading" className="text-lg font-semibold">Inspect two networks</h2><p className="mt-1 text-xs text-ink-secondary">See their gateways, IP ranges and reported status. Selecting networks makes no changes.</p></div>
      <div className="flex gap-2">
        {first && second && <button className="pair-text-action" onClick={() => { setFirstId(secondId); setSecondId(firstId); }}><Icon name="arrow-right-left" size={14} />Swap networks</button>}
        {(first || second) && <button className="pair-text-action" onClick={() => { setFirstId(""); setSecondId(""); }}>Reset</button>}
      </div>
    </div>
    {sites.length < 2 ? <p>WireGuard needs a Tunnex gateway at each location. Add a second network to review the pair.</p> : <>
      <div className="pair-selectors">
        <Field label="First network"><Select value={first?.id ?? ""} onChange={event => {
          setFirstId(event.target.value);
          if (event.target.value === secondId) setSecondId("");
        }}><option value="">Choose a network</option>{sites.map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</Select></Field>
        <span className="pair-selector-link" aria-hidden="true"><Icon name="arrow-right-left" size={18} /></span>
        <Field label="Second network"><Select value={second?.id ?? ""} onChange={event => setSecondId(event.target.value)}>
          <option value="">Choose another network</option>{sites.filter(site => site.id !== firstId).map(site => <option key={site.id} value={site.id}>{site.name}</option>)}
        </Select></Field>
      </div>
      {first && second && first.id !== second.id ? renderDetails(first, second) : <p role="status" className="pair-selection-hint">{!first ? "Choose your first network, then the network you want to reach." : `Now choose the network you want to review alongside ${first.name}.`}</p>}
    </>}
  </section>;
}

export type SitePairConfiguration = {
  nodes: Loaded<Node[]>;
  firstRanges: Loaded<SiteSubnet[]>;
  secondRanges: Loaded<SiteSubnet[]>;
  hubSet: Loaded<HubSet>;
};

export function SitePairDetails({ orgId, first, second }: { orgId: string; first: Site; second: Site }) {
  const [attempt, retry] = useState(0);
  const key = `${orgId}:${first.id}:${second.id}:${attempt}`;
  const [result, setResult] = useState<{ key: string; data: SitePairConfiguration } | null>(null);
  useEffect(() => {
    let cancelled = false;
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", { params: { path: { orgId, siteId: first.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites/{siteId}/subnets", { params: { path: { orgId, siteId: second.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/hub-set", { params: { path: { orgId } } })),
    ]).then(([nodes, firstRanges, secondRanges, hubSet]) => {
      if (!cancelled) setResult({ key, data: { nodes, firstRanges, secondRanges, hubSet } });
    });
    return () => { cancelled = true; };
  }, [key, orgId, first.id, second.id]);
  if (result?.key !== key) return <p role="status">Loading network configuration…</p>;
  return <SitePairConfigurationView first={first} second={second} data={result.data} onRetry={() => retry(value => value + 1)} />;
}

export function SitePairConfigurationView({ first, second, data, onRetry }: {
  first: Site; second: Site; data: SitePairConfiguration; onRetry: () => void;
}) {
  const incomplete = !data.nodes.ok || !data.firstRanges.ok || !data.secondRanges.ok || !data.hubSet.ok;
  return <div className="site-pair-configuration space-y-4">
    <div className="pair-context"><span className="pair-protocol"><Icon name="network" size={14} />WireGuard</span><span>Traffic not verified</span></div>
    <div className="pair-endpoints">
      <SiteConfiguration key={first.id} site={first} nodes={data.nodes} ranges={data.firstRanges} />
      <SiteConfiguration key={second.id} site={second} nodes={data.nodes} ranges={data.secondRanges} />
    </div>
    <details className="pair-diagnostics" open={!data.hubSet.ok}><summary>Transit hubs &amp; routing</summary>
    <section aria-labelledby="transit-hubs-heading" className="space-y-3 break-words">
      <h3 id="transit-hubs-heading" className="font-semibold">Reported transit hubs</h3>
      <p className="text-ink-secondary">Organization-wide roles, not a traffic-path check.</p>
      {!data.hubSet.ok ? <p role="alert">Could not load transit hubs. {data.hubSet.error}</p> : data.hubSet.data.members.length === 0 ? <p>No transit hub set reported.</p> : <ul className="space-y-2">{data.hubSet.data.members.map(member => {
        const gateway = data.nodes.ok ? data.nodes.data.find(node => node.id === member.node_id) : undefined;
        return <li key={member.node_id}>
          <span>{member.role === "primary" ? "Primary" : "Standby"}</span>{" · "}
          {gateway ? <>
            {gateway.site_id ? <Link className="underline underline-offset-4" to={`/sites?site=${encodeURIComponent(gateway.site_id)}&gateway=${encodeURIComponent(gateway.id)}`}>{gateway.name}</Link> : <span>{gateway.name}</span>}
            {gateway.status === "revoked" && <span> · Revoked</span>}
          </> : <><span>{member.node_id}</span><p className="text-sm text-ink-secondary">Gateway details unavailable</p></>}
        </li>;
      })}</ul>}
    </section>
    </details>
    {incomplete && <Button onClick={onRetry}>Retry configuration</Button>}
    <div className="pair-footer">
      <p className="text-xs text-ink-secondary">Traffic between these networks has not been verified. This review makes no connection changes.</p>
      <div className="flex flex-wrap gap-4">
        <Link className="pair-text-action" to="/sites?section=topology">View network topology</Link>
        <Link className="pair-text-action" to="/access">Review access policies</Link>
      </div>
    </div>
  </div>;
}

function SiteConfiguration({ site, nodes, ranges }: { site: Site; nodes: Loaded<Node[]>; ranges: Loaded<SiteSubnet[]> }) {
  const gateways = nodes.ok ? nodes.data.filter(node => node.site_id === site.id) : [];
  return <Card className="pair-endpoint"><section aria-label={`${site.name} configuration`} className="space-y-3 break-words">
    <div className="pair-endpoint-heading"><span className="pair-network-icon" aria-hidden="true"><Icon name="network" size={20} /></span><h3 className="font-semibold">{site.name}</h3><Link aria-label={`Settings for ${site.name}`} className="pair-settings" to={`/sites?site=${encodeURIComponent(site.id)}`}><Icon name="settings" size={16} /></Link></div>
    <h4 className="pair-section-label">Gateways</h4>
    {!nodes.ok ? <p role="alert">Could not load gateways. {nodes.error}</p> : gateways.length === 0 ? <p>No gateway assigned.</p> : <NetworkDetailList label={`${site.name} gateways`} items={gateways} searchText={node => node.name} renderItem={node => {
      const health = policyHealthBadge(node);
      const note = node.status === "revoked" ? null : siteLinkNote(node);
      return <li key={node.id} className="pair-gateway-row">
      <div className="pair-gateway-main">
      <Link className="underline underline-offset-4" to={`/sites?site=${encodeURIComponent(site.id)}&gateway=${encodeURIComponent(node.id)}`}>{node.name}</Link>
      {node.status === "revoked" ? <Badge tone="danger">Revoked</Badge> : health ? <Badge tone={health.tone}>{health.label}</Badge> : <Badge tone="neutral">Registered</Badge>}
      </div>
      <details className="pair-gateway-evidence"><summary>Report details</summary>
        {node.status !== "revoked" && health && <span className="text-xs text-ink-secondary">Registered</span>}
        <p className="text-xs text-ink-secondary">Last report: {node.last_seen_at && Number.isFinite(Date.parse(node.last_seen_at)) ? new Date(node.last_seen_at).toLocaleString() : "Not reported"}</p>
        {note && <p className="text-xs text-ink-secondary"><span>Reported peer note: </span><span>site link down: {note.peer}{note.demoted && " (demoted)"}</span></p>}
      </details>
    </li>;
    }} />}
    <h4 className="pair-section-label">Network ranges</h4>
    {!ranges.ok ? <p role="alert">Could not load ranges. {ranges.error}</p> : ranges.data.length === 0 ? <p>No network ranges advertised.</p> : <div className="pair-ranges"><NetworkDetailList label={`${site.name} ranges`} items={ranges.data} searchText={range => `${range.cidr} ${range.status}`} renderItem={range => <li key={range.id}><span className="font-mono">{range.cidr}</span><span className={range.status === "approved" ? "text-ink-secondary" : "text-warn"}>{range.status === "approved" ? "Approved" : "Pending approval"}</span></li>} /></div>}
  </section></Card>;
}
