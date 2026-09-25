import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, loadOne, type Loaded, type Node, type Site, type SiteSubnet, type HubSet } from "../lib/api";
import { policyHealthBadge, siteLinkNote } from "../lib/healthview";
import { Badge, Button, Card, Field, Select } from "./ui";

export function SitePairReview({ sites, renderDetails }: {
  sites: Site[];
  renderDetails: (first: Site, second: Site) => ReactNode;
}) {
  const [firstId, setFirstId] = useState("");
  const [secondId, setSecondId] = useState("");
  const first = sites.find(site => site.id === firstId);
  const second = sites.find(site => site.id === secondId);
  return <section aria-labelledby="pair-heading" className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 id="pair-heading" className="text-lg font-semibold">Review existing network pair</h2>
      <div className="flex gap-2">
        {first && second && <Button variant="ghost" size="sm" onClick={() => { setFirstId(secondId); setSecondId(firstId); }}>Swap networks</Button>}
        {(first || second) && <Button variant="ghost" size="sm" onClick={() => { setFirstId(""); setSecondId(""); }}>Reset</Button>}
      </div>
    </div>
    {sites.length < 2 ? <p>WireGuard needs a Tunnex gateway at each location. Add a second network to review the pair.</p> : <>
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="First network"><Select value={first?.id ?? ""} onChange={event => {
          setFirstId(event.target.value);
          if (event.target.value === secondId) setSecondId("");
        }}><option value="">Choose a network</option>{sites.map(site => <option key={site.id} value={site.id}>{site.name}</option>)}</Select></Field>
        <Field label="Second network"><Select value={second?.id ?? ""} onChange={event => setSecondId(event.target.value)}>
          <option value="">Choose another network</option>{sites.filter(site => site.id !== firstId).map(site => <option key={site.id} value={site.id}>{site.name}</option>)}
        </Select></Field>
      </div>
      {first && second && first.id !== second.id ? renderDetails(first, second) : <p className="text-ink-secondary">Select both networks to see their gateways and ranges.</p>}
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
  return <div className="space-y-4">
    <div className="grid gap-4 lg:grid-cols-2">
      <SiteConfiguration site={first} nodes={data.nodes} ranges={data.firstRanges} />
      <SiteConfiguration site={second} nodes={data.nodes} ranges={data.secondRanges} />
    </div>
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
    {incomplete && <Button onClick={onRetry}>Retry configuration</Button>}
    <div className="space-y-2">
      <p className="text-sm text-ink-secondary">Traffic between these networks has not been verified. This review makes no connection changes.</p>
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
    {!nodes.ok ? <p role="alert">Could not load gateways. {nodes.error}</p> : gateways.length === 0 ? <p>No gateway assigned.</p> : <ul className="space-y-2">{gateways.map(node => {
      const health = policyHealthBadge(node);
      const note = node.status === "revoked" ? null : siteLinkNote(node);
      return <li key={node.id}>
      <Link className="underline underline-offset-4" to={`/sites?site=${encodeURIComponent(site.id)}&gateway=${encodeURIComponent(node.id)}`}>{node.name}</Link>
      <span> · {node.status === "revoked" ? "Revoked" : "Registered"}</span>
      <p className="text-sm text-ink-secondary">Last report: {node.last_seen_at && Number.isFinite(Date.parse(node.last_seen_at)) ? new Date(node.last_seen_at).toLocaleString() : "Not reported"}</p>
      {health && <p className="text-sm [&>.tnx-badge]:max-w-full [&>.tnx-badge]:!whitespace-normal"><span>Reported status: </span><Badge tone={health.tone}>{health.label}</Badge></p>}
      {note && <p className="text-sm text-ink-secondary"><span>Reported peer note: </span><span>site link down: {note.peer}{note.demoted && " (demoted)"}</span></p>}
    </li>;
    })}</ul>}
    <h4 className="font-semibold">Network ranges</h4>
    {!ranges.ok ? <p role="alert">Could not load ranges. {ranges.error}</p> : ranges.data.length === 0 ? <p>No network ranges advertised.</p> : <ul className="space-y-2">{ranges.data.map(range => <li key={range.id}><span className="font-mono">{range.cidr}</span> · {range.status === "approved" ? "Approved" : "Pending approval"}</li>)}</ul>}
    <Link className="inline-block underline underline-offset-4" to={`/sites?site=${encodeURIComponent(site.id)}`}>View site settings</Link>
  </section></Card>;
}
