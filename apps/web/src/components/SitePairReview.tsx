import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, loadOne, type Loaded, type Node, type Site, type SiteSubnet } from "../lib/api";
import { Button, Card, Field, Select } from "./ui";

export function SitePairReview({ sites, renderDetails }: {
  sites: Site[];
  renderDetails: (first: Site, second: Site) => ReactNode;
}) {
  const [firstId, setFirstId] = useState("");
  const [secondId, setSecondId] = useState("");
  const first = sites.find(site => site.id === firstId);
  const second = sites.find(site => site.id === secondId);
  return <section aria-labelledby="pair-heading" className="space-y-4">
    <h2 id="pair-heading" className="text-lg font-semibold">Review two networks</h2>
    <p className="text-ink-secondary">Choose existing sites to check their gateways and network ranges before reviewing access. This does not create or change a connection.</p>
    {sites.length < 2 ? <p>Add at least two sites to review a site-to-site path.</p> : <>
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="First network"><Select value={first?.id ?? ""} onChange={event => {
          setFirstId(event.target.value);
          if (event.target.value === secondId) setSecondId("");
        }}><option value="">Choose a network</option>{sites.map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</Select></Field>
        <Field label="Second network"><Select value={second?.id ?? ""} onChange={event => setSecondId(event.target.value)}>
          <option value="">Choose another network</option>{sites.filter(site => site.id !== firstId).map(site => <option key={site.id} value={site.id}>{site.name}</option>)}
        </Select></Field>
      </div>
      {first && second && first.id !== second.id ? renderDetails(first, second) : <p className="text-ink-secondary">Select two different networks to see their configuration.</p>}
    </>}
  </section>;
}

export type SitePairConfiguration = {
  nodes: Loaded<Node[]>;
  firstRanges: Loaded<SiteSubnet[]>;
  secondRanges: Loaded<SiteSubnet[]>;
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
    ]).then(([nodes, firstRanges, secondRanges]) => {
      if (!cancelled) setResult({ key, data: { nodes, firstRanges, secondRanges } });
    });
    return () => { cancelled = true; };
  }, [key, orgId, first.id, second.id]);
  if (result?.key !== key) return <p role="status">Loading network configuration…</p>;
  return <SitePairConfigurationView first={first} second={second} data={result.data} onRetry={() => retry(value => value + 1)} />;
}

export function SitePairConfigurationView({ first, second, data, onRetry }: {
  first: Site; second: Site; data: SitePairConfiguration; onRetry: () => void;
}) {
  const incomplete = !data.nodes.ok || !data.firstRanges.ok || !data.secondRanges.ok;
  return <div className="space-y-4">
    <div className="grid gap-4 lg:grid-cols-2">
      <SiteConfiguration site={first} nodes={data.nodes} ranges={data.firstRanges} />
      <SiteConfiguration site={second} nodes={data.nodes} ranges={data.secondRanges} />
    </div>
    {incomplete && <Button onClick={onRetry}>Retry configuration</Button>}
    <div className="space-y-2">
      <h3 className="font-semibold">Next: review the full path</h3>
      <ol className="list-decimal space-y-2 pl-5 text-ink-secondary">
        <li>Confirm each site has a usable gateway and the required approved ranges.</li>
        <li>Review the existing topology and access policy for traffic in each direction.</li>
        <li>Configure local return routes, then test an application between devices at the two sites.</li>
      </ol>
      <p className="text-ink-secondary">Traffic between these networks has not been verified here. Tunnex may route through a hub; selecting a pair does not establish a direct tunnel.</p>
      <div className="flex flex-wrap gap-4">
        <Link className="underline underline-offset-4" to="/sites">View network topology</Link>
        <Link className="underline underline-offset-4" to="/access">Review access policies</Link>
      </div>
    </div>
  </div>;
}

function SiteConfiguration({ site, nodes, ranges }: { site: Site; nodes: Loaded<Node[]>; ranges: Loaded<SiteSubnet[]> }) {
  const gateways = nodes.ok ? nodes.data.filter(node => node.site_id === site.id) : [];
  return <Card><section aria-label={`${site.name} configuration`} className="space-y-3 break-words">
    <h3 className="font-semibold">{site.name}</h3>
    <p className="text-sm text-ink-secondary">WireGuard · configured site</p>
    <h4 className="font-semibold">Gateways</h4>
    {!nodes.ok ? <p role="alert">Could not load gateways. {nodes.error}</p> : gateways.length === 0 ? <p>No gateway assigned.</p> : <ul className="space-y-2">{gateways.map(node => <li key={node.id}>
      <Link className="underline underline-offset-4" to={`/sites?site=${encodeURIComponent(site.id)}&gateway=${encodeURIComponent(node.id)}`}>{node.name}</Link>
      <span> · {node.status === "revoked" ? "Revoked" : "Registered"}</span>
      <p className="text-sm text-ink-secondary">Last report: {node.last_seen_at && Number.isFinite(Date.parse(node.last_seen_at)) ? new Date(node.last_seen_at).toLocaleString() : "Not reported"}</p>
    </li>)}</ul>}
    <h4 className="font-semibold">Network ranges</h4>
    {!ranges.ok ? <p role="alert">Could not load ranges. {ranges.error}</p> : ranges.data.length === 0 ? <p>No network ranges advertised.</p> : <ul className="space-y-2">{ranges.data.map(range => <li key={range.id}><span className="font-mono">{range.cidr}</span> · {range.status === "approved" ? "Approved" : "Pending approval"}</li>)}</ul>}
    <Link className="inline-block underline underline-offset-4" to={`/sites?site=${encodeURIComponent(site.id)}`}>View site settings</Link>
  </section></Card>;
}
