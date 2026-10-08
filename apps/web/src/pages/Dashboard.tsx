import { SetupChoices } from "./Setup";
import "../overview-scan.css";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { hubSetView } from "../lib/hubsetview";
import { assembleTopology, meshFrom } from "../lib/sitesview";
import { NodeLink } from "../components/viz";
import { assembleClusters } from "../lib/k8sview";
import { UpgradeCenter } from "../components/UpgradeCenter";
import {
  api, listItems, apiErrorMessage, loadOne,
  type Device, type Loaded, type Node, type OrgOverview, type Site,
  type HubSet, type PolicyRule, type ZeroTrustMode, type K8sCluster, type K8sService,
} from "../lib/api";
import { Button, EmptyState, ErrorText, Loading, Section } from "../components/ui";
import { attributionBadge, gatewayHealthRow, policyHealthBadge } from "../lib/healthview";
import { agentSummary, type AgentRow } from "../lib/agentview";
import { isFreshOrg, peerSlices, postureSplit, statFrom, statText, type StatState } from "../lib/overviewview";

type Slice = { label: string; value: number; tone: "ok" | "warn" | "danger" | "neutral" };

export default function Dashboard() {
  const { org, loading, failed } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed"
    ? `${state.user.id}:${state.user.email_verified}:${state.user.must_change_password}`
    : state.status;
  // Remount at the scope boundary: a new organization or actor never inherits saved counts.
  return <div className="overview-scan">
    <h1 className="sr-only">Overview</h1>
    {loading || state.status === "loading" ? <Loading label="Loading your overview…" />
      : !org ? <ErrorText>{failed ? "Could not load your organizations." : "You are not a member of any organization yet."}</ErrorText>
      : state.status !== "authed" ? <ErrorText>Sign in to view your overview.</ErrorText>
      : <OverviewContent key={`${org.id}:${actor}`} orgId={org.id} orgName={org.name} />}
  </div>;
}

function OverviewContent({ orgId, orgName }: { orgId: string; orgName: string }) {
  const [data, setData] = useState<OrgOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reading, setReading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  const [sitesRes, setSitesRes] = useState<Loaded<Site[]> | null>(null);
  const [pendingRes, setPendingRes] = useState<Loaded<Device[]> | null>(null);
  const [nodesRes, setNodesRes] = useState<Loaded<Node[]> | null>(null);
  const [agentsRes, setAgentsRes] = useState<Loaded<AgentRow[]> | null>(null);
  const [agentsPartial, setAgentsPartial] = useState(false);
  const [rulesRes, setRulesRes] = useState<Loaded<PolicyRule[]> | null>(null);
  const [devicesRes, setDevicesRes] = useState<Loaded<Device[]> | null>(null);
  const [hubSetRes, setHubSetRes] = useState<Loaded<HubSet> | null>(null);
  const [k8sClustersRes, setK8sClustersRes] = useState<Loaded<K8sCluster[]> | null>(null);
  const [k8sServicesRes, setK8sServicesRes] = useState<Loaded<K8sService[]> | null>(null);
  const [ztRes, setZtRes] = useState<Loaded<ZeroTrustMode> | null>(null);

  useEffect(() => {
    let cancelled = false;
    setReading(true); setData(null); setError(null);
    setSitesRes(null); setPendingRes(null); setNodesRes(null); setAgentsRes(null);
    setAgentsPartial(false); setRulesRes(null); setDevicesRes(null); setHubSetRes(null);
    setK8sClustersRes(null); setK8sServicesRes(null); setZtRes(null);
    const path = { orgId };
    // Each read owns its state. Failure is unavailable, never an invented zero or healthy verdict.
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/devices/pending", { params: { path } }))
      .then(r => !cancelled && setPendingRes(inventoryResult<Device>(r)));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/policies", { params: { path } }))
      .then(r => !cancelled && setRulesRes(inventoryResult<PolicyRule>(r)));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", { params: { path } }))
      .then(r => !cancelled && setZtRes(r as Loaded<ZeroTrustMode>));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/sites", { params: { path } }))
      .then(r => !cancelled && setSitesRes(inventoryResult<Site>(r)));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path } }))
      .then(r => !cancelled && setNodesRes(inventoryResult<Node>(r)));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/agents", { params: { path, query: { limit: 100 } } }))
      .then(r => {
        if (cancelled || !r.ok || (!Array.isArray(r.data) && !Array.isArray(r.data?.items)) || !listItems(r.ok ? r.data : undefined).every(row => !!row && typeof row.device_id === "string")) return;
        const partial = !Array.isArray(r.data) && !!r.data.next_cursor;
        setAgentsPartial(partial);
        setAgentsRes({ ok: true, data: listItems(r.data) as AgentRow[] });
      });
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/devices", { params: { path } }))
      .then(r => !cancelled && setDevicesRes(inventoryResult<Device>(r)));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/hub-set", { params: { path } }))
      .then(r => !cancelled && setHubSetRes(r.ok && (!r.data || !Array.isArray(r.data.members) || !r.data.members.every(member => member && typeof member.node_id === "string" && ["primary", "standby"].includes(member.role)) || !Number.isSafeInteger(r.data.generation)) ? { ok: false, error: "Could not load the hub set." } : r as Loaded<HubSet>));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/clusters", { params: { path } }))
      .then(r => !cancelled && setK8sClustersRes(inventoryResult<K8sCluster>(r)));
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/k8s/services", { params: { path } }))
      .then(r => !cancelled && setK8sServicesRes(inventoryResult<K8sService>(r)));
    void api.GET("/api/v1/organizations/{orgId}/overview", { params: { path } })
      .then(({ data: overview, error: loadError }) => {
        if (cancelled) return;
        const valid = overview && [overview.members, overview.devices, overview.nodes].every(value => Number.isSafeInteger(value) && value >= 0);
        if (loadError || !valid) setError(apiErrorMessage(loadError, "Could not load the overview."));
        else setData(overview);
        setReading(false);
      }).catch(() => {
        if (!cancelled) { setError("Could not reach the API."); setReading(false); }
      });
    return () => { cancelled = true; };
  }, [orgId, attempt]);

  const members = statFrom(data ? { ok: true, data } : null, d => d.members);
  const devices = statFrom(data ? { ok: true, data } : null, d => d.devices);
  const gateways = statFrom(data ? { ok: true, data } : null, d => d.nodes);
  const sites = statFrom(sitesRes, r => r.length);
  const pending = statFrom(pendingRes, r => r.length);
  const fresh = !!data && (isFreshOrg(gateways, devices, members) || (
    devices.state === "ok" && devices.value === 0 && sitesRes?.ok === true && sitesRes.data.length === 0
  ));
  const zeroTrust = ztRes?.ok && ztRes.data?.mode === "enforcing" ? "enforcing"
    : ztRes?.ok && ztRes.data?.mode === "off" ? "not enforced" : null;
  const degraded = nodesRes?.ok ? nodesRes.data.filter(n => policyHealthBadge(n) !== null).length : null;

  return <>
    <div className="scan-toolbar">
      <div className="scan-org">{orgName}<span>Network at a glance</span></div>
      <div className="scan-toolbar-actions">
        <Link to="/setup" className="scan-text-link">Setup guide</Link>
        <Button aria-label="Refresh overview" variant="ghost" disabled={reading} onClick={() => setAttempt(value => value + 1)}>{reading ? "Refreshing…" : "Refresh"}</Button>
      </div>
    </div>
    <UpgradeCenter />
    <ErrorText>{error}</ErrorText>
    {reading && <div className="scan-loading"><Loading label="Loading your overview…" /></div>}
    {data && <>
      <section aria-label="Fleet summary" className="scan-fleet">
        <div aria-label="Fleet summary metrics" className="scan-metrics">
          <Stat label="Devices" to="/devices" value={devices} />
          <Stat label="Gateways" to="/gateways" value={gateways} sub={degraded ? `${degraded} degraded` : null} subTone="danger" />
          <Stat label="Sites" to="/sites" value={sites} />
          <Stat label="Members" to="/users" value={members} />
          {agentsRes?.ok && <Stat label="AI Agents" to="/agents" value={statFrom(agentsRes, r => r.length)} partial={agentsPartial} sub={agentsPartial ? "Loaded agents" : agentSummary(agentsRes.data).note} subTone="warn" />}
          {rulesRes?.ok && <Stat label="Access Rules" to="/access" value={statFrom(rulesRes, r => r.length)} sub={zeroTrust} subTone={zeroTrust === "not enforced" ? "warn" : "neutral"} />}
          {pendingRes?.ok && <Stat label="Approvals" to="/devices/approvals" value={pending} sub={pending.state === "ok" && pending.value > 0 ? "needs review" : null} subTone="warn" />}
        </div>
      </section>
      {fresh && <Section title="Get started" className="scan-onboarding"><SetupChoices /></Section>}
      <div className="scan-health">
        <Section title="Gateway Health" className="scan-gateways" actions={<Link to="/gateways" className="scan-text-link">View gateways</Link>}>
          <GatewayHealth result={nodesRes} />
        </Section>
        <Section title="Device Health" className="scan-devices" actions={<Link to="/devices" className="scan-text-link">View devices</Link>}>
          <DeviceHealth result={devicesRes} />
        </Section>
      </div>
      <Section title="Your network" className="scan-network" actions={<Link to="/sites" className="scan-text-link">Open infrastructure</Link>}>
        <div className="scan-network-layout">
          <div className="scan-topology">
            {sitesRes === null || nodesRes === null ? <Loading />
              : !sitesRes.ok || !nodesRes.ok ? <ErrorText>The topology is unavailable.</ErrorText>
              : <NodeLink label="Site topology" source={{ endpoint: "/api/v1/organizations/{orgId}/sites" }} failed={false}
                {...(() => {
                  const mesh = meshFrom(assembleTopology(sitesRes.data, {}, nodesRes.data), nodesRes.data, hubSetRes?.ok ? hubSetRes.data : undefined, false);
                  return { nodes: mesh.nodes, links: mesh.links };
                })()}
                maxHeight={245} empty="No sites configured yet. Bind a gateway to a site to build the mesh." />}
          </div>
          <div className="scan-infrastructure">
            <HubSummary result={hubSetRes} nodes={nodesRes} />
            <KubernetesSummary clusters={k8sClustersRes} services={k8sServicesRes} />
          </div>
        </div>
      </Section>
    </>}
  </>;
}

function GatewayHealth({ result }: { result: Loaded<Node[]> | null }) {
  if (result === null) return <Loading />;
  if (!result.ok) return <ErrorText>Gateway health is unavailable.</ErrorText>;
  if (!result.data.length) return <EmptyState>No gateway enrolled yet.</EmptyState>;
  const health = result.data.map(gatewayHealthRow);
  const issues = health.filter(verdict => verdict.tone !== "ok");
  const revoked = issues.filter(verdict => verdict.label === "revoked");
  const unhealthy = issues.filter(verdict => verdict.label !== "revoked");
  const unattributed = result.data.filter(node => attributionBadge(node) !== null).length;
  const groups = Array.from(issues.reduce((map, verdict) => map.set(verdict.label, (map.get(verdict.label) ?? 0) + 1), new Map<string, number>()))
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b));
  return <div className="scan-gateway-body">
    <StateDistribution label="Gateway health summary" unit="total" note="Includes revoked" prominent slices={[
      { label: "Healthy", value: health.length - issues.length, tone: "ok" },
      { label: "Unhealthy", value: unhealthy.length, tone: "danger" },
      { label: "Revoked", value: revoked.length, tone: "neutral" },
    ]} />
    {issues.length || unattributed ? <div className="scan-conditions">
      <div className="scan-section-caption">Needs attention</div>
      <div role="group" aria-label="Gateway health conditions" className="scan-condition-list">
        {unattributed > 0 && <div className="scan-condition" data-tone="warn"><span>no recorded owner</span><span>{unattributed}</span></div>}
        {groups.map(([label, count]) => <div className="scan-condition" data-tone={label === "revoked" ? "neutral" : "danger"} key={label}><span>{label}</span><span>{count}</span></div>)}
      </div>
      <Link to="/gateways" className="scan-review-link">{issues.length ? `Review ${issues.length} affected gateway${issues.length === 1 ? "" : "s"}` : "Review gateway ownership"}<span aria-hidden="true">→</span></Link>
    </div> : <p className="scan-clear">No gateway health issues reported.</p>}
  </div>;
}

function DeviceHealth({ result }: { result: Loaded<Device[]> | null }) {
  if (result === null) return <Loading />;
  if (!result.ok) return <ErrorText>Device health is unavailable.</ErrorText>;
  if (!result.data.length) return <EmptyState>No devices enrolled yet.</EmptyState>;
  const posture = postureSplit(result.data);
  return <div className="scan-device-body">
    <StateDistribution label="Peer connection status" title="Connection" unit="devices" slices={peerSlices(result.data).filter(slice => slice.value > 0 || ["Recent handshake", "No recent handshake", "Posture-blocked"].includes(slice.label))} />
    <StateDistribution label="Device posture" title="Posture" unit="devices" slices={[
      { label: "Compliant", value: posture.compliant, tone: "ok" },
      { label: "Noncompliant", value: posture.noncompliant, tone: "warn" },
      { label: "Blocked", value: posture.blocked, tone: "danger" },
      { label: "Unknown", value: posture.unknown, tone: "neutral" },
    ]} />
  </div>;
}

function StateDistribution({ label, title, unit, note, slices, prominent = false }: { label: string; title?: string; unit: string; note?: string; slices: Slice[]; prominent?: boolean }) {
  const total = slices.reduce((sum, slice) => sum + slice.value, 0);
  return <figure aria-label={label} className={`scan-distribution ${prominent ? "scan-distribution-prominent" : ""}`}>
    <div className="scan-distribution-heading">
      {title && <h3>{title}</h3>}
      <div className="scan-distribution-total"><strong>{total}</strong><span>{unit}</span></div>
      {note && <span className="scan-total-note">{note}</span>}
    </div>
    <div className="scan-status-track" aria-hidden="true">
      {slices.filter(slice => slice.value > 0).map(slice => <span key={slice.label} data-tone={slice.tone} style={{ width: `${slice.value / total * 100}%` }} />)}
    </div>
    <ul className="scan-distribution-list">
      {slices.map(slice => <li key={slice.label}><span className="scan-dot" data-tone={slice.tone} aria-hidden="true" /><span>{slice.label}</span><span className="scan-distribution-value">{slice.value}</span>{prominent && <small>{total ? Math.round(slice.value / total * 100) : 0}%</small>}</li>)}
    </ul>
  </figure>;
}

function HubSummary({ result, nodes }: { result: Loaded<HubSet> | null; nodes: Loaded<Node[]> | null }) {
  const hub = result?.ok && result.data?.members ? hubSetView(result.data, Date.now()) : null;
  return <div className="scan-hub">
    <div className="scan-infra-heading"><h3>HA Hub Set</h3>{hub && <span>Gen {hub.generation}</span>}</div>
    {result === null ? <Loading /> : !result.ok ? <ErrorText>The hub set is unavailable.</ErrorText>
      : !hub ? <EmptyState>No HA hub set. Pin two or more gateways to create one.</EmptyState>
      : <ul aria-label="Hub set" className="scan-hub-members">{hub.members.map(member => {
        const name = nodes?.ok ? nodes.data.find(node => node.id === member.nodeId)?.name ?? member.nodeId.slice(0, 8) : member.nodeId.slice(0, 8);
        const role = member.demoted ? "demoted" : member.role;
        const status = member.reporting ? `hs ${member.handshakeAge}` : "not reporting";
        return <li key={member.nodeId} aria-label={`${name} (${role}): ${status}`}>
          <div><span>{name}</span><small>{role}</small></div>
          <span className="scan-hub-status" data-tone={member.warm ? "ok" : member.reporting ? "warn" : "danger"}>{status}</span>
        </li>;
      })}</ul>}
  </div>;
}

function KubernetesSummary({ clusters, services }: { clusters: Loaded<K8sCluster[]> | null; services: Loaded<K8sService[]> | null }) {
  return <div className="scan-kubernetes">
    <div className="scan-infra-heading"><h3>Kubernetes</h3><Link to="/kubernetes" className="scan-text-link">Open Kubernetes</Link></div>
    {clusters === null || services === null ? <Loading />
      : !clusters.ok ? <ErrorText>Kubernetes infrastructure is unavailable.</ErrorText>
      : !clusters.data.length ? <EmptyState>No clusters registered. Register one to expose Services privately.</EmptyState>
      : !services.ok ? <ErrorText>Service inventory is unavailable.</ErrorText>
      : (() => {
        const rows = assembleClusters(clusters.data, services.data);
        const total = rows.reduce((sum, row) => sum + row.services.length, 0);
        return <div role="group" aria-label="Kubernetes summary">
          <div className="scan-service-total"><span>Exposed services</span><strong>{total}</strong></div>
          <ul className="scan-clusters">{rows.slice(0, 3).map(cluster => <li key={cluster.id}><span>{cluster.name}</span><span aria-label={`${cluster.services.length} exposed services`}>{cluster.services.length}</span></li>)}</ul>
          {rows.length > 3 && <p className="scan-more">{rows.length - 3} more cluster{rows.length - 3 === 1 ? "" : "s"}</p>}
        </div>;
      })()}
  </div>;
}

function Stat({ label, to, value, sub, subTone = "neutral", partial = false }: {
  label: string; to: string; value: StatState; sub?: ReactNode;
  subTone?: "neutral" | "warn" | "danger"; partial?: boolean;
}) {
  const text = statText(value);
  return <div role="group" aria-label={label} className="scan-metric">
    <Link to={to}>
      <span className="scan-metric-label">{label}</span>
      <span className="scan-metric-value font-bold" title={value.state === "failed" ? "Could not load this count." : undefined}>{text === null ? value.state === "failed" ? "n/a" : "…" : `${text}${partial ? "+" : ""}`}</span>
      <span className="scan-metric-note" data-tone={value.state === "failed" ? "danger" : subTone}>{value.state === "failed" ? "could not load" : sub}</span>
    </Link>
  </div>;
}

function inventoryResult<T>(result: Loaded<unknown>): Loaded<T[]> {
  return result.ok ? Array.isArray(result.data) && result.data.every(inventoryRow) ? { ok: true, data: result.data as T[] } : { ok: false, error: "Could not read the inventory." } : result;
}

function inventoryRow(row: unknown): boolean {
  return !!row && typeof row === "object" && !Array.isArray(row) && typeof (row as { id?:unknown }).id === "string";
}
