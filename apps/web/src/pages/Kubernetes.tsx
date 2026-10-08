import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { Link, useSearchParams } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import {
  api,
  apiErrorCode,
  apiErrorMessage,
  loadOne,
  type Loaded,
  type Member,
  type Role,
  type Site,
  type K8sCluster,
  type K8sConnectorPoolConfiguration,
  type K8sService,
} from "../lib/api";
import { useAuth } from "../lib/auth";
import { ResourceSummary } from "../components/ResourceSummary";
import {
  Badge,
  Button,
  DataTable,
  ErrorText,
  Field,
  Input,
  Loading,
  Modal,
  Select,
  SettingGroup,
  SettingRow,
  SettingValue,
} from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { roleFromMembers } from "../lib/policyview";
import { can } from "../lib/rbac";
import {
  assembleClusters,
  clusterConnectorState,
  k8sGate,
  managedEditWarning,
  objectControls,
  type ClusterCard,
  type ServiceRow,
} from "../lib/k8sview";
// ⛔ EXPLICIT IMPORT, and it is load-bearing: without it `Node` resolves to the DOM's global `Node`, so
// `site_id` and `policy_degraded_kind` "do not exist" with no hint that a different type was found.
import type { Node } from "../lib/api";
import {
  ProviderFirstEnrollmentModal,
  ProviderMetadataCorrectionModal,
} from "../components/K8sEnrollment";
import { K8sServiceInventoryStatus } from "../components/K8sServiceInventoryStatus";
import { K8sHAActivationPanel } from "../components/K8sHAActivationPanel";
import { K8sConnectorPoolPanel } from "../components/K8sConnectorPoolPanel";
import { providerPlatformEntry } from "../lib/k8senrollment";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";

import "../network-workspaces.css";
import "../kubernetes-workspace.css";

// Kubernetes (S10.3): the in-cluster connectivity surface — register a cluster (a synthetic VIP range fronted
// by a site gateway) and expose its Services to the fabric. CONNECTIVITY is CORE (all editions): this whole
// page is k8s:manage-gated but never edition-gated; the GRANT that reaches an exposed Service (Access page)
// is the enterprise governance gate. Every rendered field is wire-truth; the FQDN is READ from the server
// (never constructed in the client — "copy, don't construct").

interface Raw {
  clusters: K8sCluster[];
  services: K8sService[];
  sites: Site[] | null; // null means the inventory read failed; [] is a verified empty result
  sitesError: string | null;
  // D9: gateways, for the reachability qualification. A cluster's Services must not read as reachable when a
  // gateway fronting its site has no endpoint view.
  nodes: Node[] | null;
  nodesError: string | null;
  // NULL = the read failed. Distinct from 0, which means "we looked and there are none".
  machineCreds: number | null;
  connectorPools: Record<string, ConnectorPoolLookup>;
}

// A pool conversion deliberately clears the legacy connector_node_id. This is
// an explicit read result, so an unavailable pool read never becomes a false
// “connector required” claim in the dashboard.
type ConnectorPoolLookup =
  | { kind: "configured"; configuration: K8sConnectorPoolConfiguration }
  | { kind: "unconfigured" }
  | { kind: "unavailable" };

type ConnectorBinding =
  | { kind: "direct"; nodeId: string }
  | { kind: "pool"; nodeId: string }
  | { kind: "missing"; nodeId: null }
  | { kind: "unavailable"; nodeId: null };

const clusterSteps = ["overview", "connection", "services", "network"] as const;
type ClusterStep = typeof clusterSteps[number];

export default function Kubernetes() {
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const loadScope = `${currentOrg?.id ?? ""}:${myId}:${emailVerified ? "verified" : "unverified"}`;
  const loadScopeRef = useRef(loadScope);
  loadScopeRef.current = loadScope;
  const requestSequence = useRef(0);
  const [loadedScope, setLoadedScope] = useState("");
  const scopeCurrent = loadedScope === loadScope;
  const [orgId, setOrgId] = useState<string | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  const [raw, setRaw] = useState<Raw | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const [params, setParams] = useSearchParams();
  const requestedSection = params.get("section");
  const section = requestedSection === "services" || requestedSection === "operations" ? requestedSection : "clusters";
  const query = params.get("q") ?? "";
  const selectedId = params.get("cluster");
  const requestedDetail = params.get("detail");
  const detail: ClusterStep = clusterSteps.includes(requestedDetail as ClusterStep) ? requestedDetail as ClusterStep : "overview";
  const pageSize = appAccessPageSize(params.get("page_size"));
  const pageValue = Number(params.get("page"));
  const requestedPage = Number.isSafeInteger(pageValue) && pageValue > 0 ? pageValue : 1;

  useEffect(() => {
    if (requestedSection !== null && requestedSection !== section) {
      const next = new URLSearchParams(params);
      next.set("section", section);
      setParams(next, { replace: true });
    }
  }, [params, requestedSection, section, setParams]);

  const reload = useCallback(async () => {
    const sequence = ++requestSequence.current;
    const requestScope = loadScope;
    const isCurrent = () => sequence === requestSequence.current && loadScopeRef.current === requestScope;
    setLoadedScope("");
    setMyRole(undefined);
    setOrgId(null);
    setLoadError(null);
    setRaw(null);
    setRegistering(false);
    setExposeFor(null);
    setConnectorFor(null);
    setProviderMetadataFor(null);
    setDeregisterFor(null);
    setUnexposeFor(null);
    setInspectedService(null);
    setTrafficPathOpen(false);
    setCommandsOpen(false);
    // ⛔ THE ORG COMES FROM THE SEAM, NOT FROM INDEX ZERO (S12.5). This used to fetch the org list here and
    // take `[0]`, which meant a user in two organizations could reach only one of them and the switcher in
    // the header would have had nothing to switch.
    // ⛔ LOADING IS NOT ABSENCE (S12.5). See the note in Dashboard.tsx — three states, not two: still
    // loading (say nothing), the read failed (say THAT), genuinely no membership (say that).
    if (orgLoading) return;
    const first = currentOrg;
    if (!first) {
      setLoadedScope(requestScope);
      return setLoadError(
        orgFailed
          ? "Could not load your organizations."
          : "You are not a member of any organization yet.",
      );
    }
    setOrgId(first.id);
    const memRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Member[]>;
    if (!isCurrent()) return;
    const role = roleFromMembers(memRes, myId).role;
    setMyRole(role);
    const cRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/k8s/clusters", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<K8sCluster[]>;
    if (!isCurrent()) return;
    if (!cRes.ok) { setLoadedScope(requestScope); return setLoadError(cRes.error); }
    const svcRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/k8s/services", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<K8sService[]>;
    if (!isCurrent()) return;
    if (!svcRes.ok) { setLoadedScope(requestScope); return setLoadError(svcRes.error); }
    const sRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/sites", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Site[]>;
    if (!isCurrent()) return;
    // ⛔ TWO SECOND-CLASS READS. Both enrich a screen that is already correct, so a failure degrades a cell
    // rather than blanking the page — and `null` is carried through rather than collapsed to 0/[].
    const nRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/nodes", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Node[]>;
    if (!isCurrent()) return;
    const mcRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/machine-credentials", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<unknown[]>;
    if (!isCurrent()) return;
    const connectorPools: Record<string, ConnectorPoolLookup> = {};
    // A direct owner is already present in the cluster payload. Only clusters
    // without it need the pool read, which keeps the common path single-read.
    if (can(role, "k8s_ha:view")) {
      await Promise.all(cRes.data.filter((cluster) => cluster.connector_node_id == null).map(async (cluster) => {
        try {
          const { data, error } = await api.GET("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector-pool", {
            params: { path: { orgId: first.id, clusterId: cluster.id } },
          });
          connectorPools[cluster.id] = error
            ? apiErrorCode(error) === "connector_pool_not_found" ? { kind: "unconfigured" } : { kind: "unavailable" }
            : data ? { kind: "configured", configuration: data } : { kind: "unavailable" };
        } catch { connectorPools[cluster.id] = { kind: "unavailable" }; }
      }));
    } else {
      for (const cluster of cRes.data) if (cluster.connector_node_id == null) connectorPools[cluster.id] = { kind: "unavailable" };
    }
    if (!isCurrent()) return;
    setLoadedScope(requestScope);
    setRaw({
      clusters: cRes.data,
      services: svcRes.data,
      sites: sRes.ok ? sRes.data : null,
      sitesError: sRes.ok ? null : sRes.error,
      nodes: nRes.ok ? nRes.data : null,
      nodesError: nRes.ok ? null : nRes.error,
      // NULL, not 0 — "we could not look" is a different fact from "there are none", and the tile says which.
      machineCreds: mcRes.ok ? mcRes.data.length : null,
      connectorPools,
    });
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, myId, orgLoading, orgFailed, loadScope]);
  useEffect(() => {
    void reload();
    return () => { requestSequence.current += 1; };
  }, [reload]);

  const gate = k8sGate({ role: scopeCurrent ? myRole : undefined, emailVerified });
  const cards: ClusterCard[] = useMemo(
    () => (raw && scopeCurrent ? assembleClusters(raw.clusters, raw.services) : []),
    [raw, scopeCurrent],
  );
  const siteName = useMemo(
    () => new Map((raw?.sites ?? []).map((x) => [x.id, x.name])),
    [raw],
  );
  const nodeName = useMemo(
    () => new Map((raw?.nodes ?? []).map((x) => [x.id, x.name])),
    [raw],
  );
  // The selected connector, not merely any gateway in the site, owns the endpoint watch and DNAT.
  const gateways = useMemo(
    () =>
      (raw?.nodes ?? []).map((n: Node) => ({
        id: n.id,
        revoked: n.status === "revoked",
        endpointsUnavailable:
          // ⛔ S14.21: a REVOKED gateway is not reporting anything — its last known kind is a stale
          // reading of a machine that is no longer meant to work.
          n.status !== "revoked" &&
          n.policy_degraded_kind === "k8s_endpoints_unavailable",
      })),
    [raw],
  );
  function connectorBinding(cluster: ClusterCard): ConnectorBinding {
    if (cluster.connectorNodeId !== null) return { kind: "direct", nodeId: cluster.connectorNodeId };
    const pool = raw?.connectorPools[cluster.id];
    if (pool?.kind === "configured") return { kind: "pool", nodeId: pool.configuration.active_node_id };
    if (pool?.kind === "unconfigured") return { kind: "missing", nodeId: null };
    return { kind: "unavailable", nodeId: null };
  }

  // ⛔ ONE MODAL OWNER AT PAGE LEVEL. The per-cluster card used to hold its own modal state; the wireframe's
  // layout is a TABLE, and a table row cannot own a modal without one instance per row. Hoisting it here is
  // what makes the table possible, and it keeps every mutation path (expose / unexpose / deregister) intact.
  const [exposeFor, setExposeFor] = useState<ClusterCard | null>(null);
  const [connectorFor, setConnectorFor] = useState<ClusterCard | null>(null);
  const [providerMetadataFor, setProviderMetadataFor] = useState<ClusterCard | null>(null);
  const [deregisterFor, setDeregisterFor] = useState<ClusterCard | null>(null);
  const [unexposeFor, setUnexposeFor] = useState<ServiceRow | null>(null);
  const [trafficPathOpen, setTrafficPathOpen] = useState(false);
  const [commandsOpen, setCommandsOpen] = useState(false);
  const [commandKind, setCommandKind] = useState<"gateway" | "operator">("gateway");
  const [commandStep, setCommandStep] = useState(0);

  // Every exposed Service, flattened WITH its cluster, so the table is one scannable list rather than a list
  // per card. §6.2: the SERVICE list is the scaling surface, so it gets the table; the cluster list does not.
  const serviceRows = useMemo(
    () =>
      cards.flatMap((c) =>
        c.services.map((sv) => ({
          ...sv,
          clusterId: c.id,
          clusterName: c.name,
          configured: clusterConnectorState({ connectorNodeId: connectorBinding(c).nodeId, gateways })
            .configured,
        })),
      ),
    [cards, gateways],
  );
  const visibleCards = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return needle === "" ? cards : cards.filter((card) => card.name.toLowerCase().includes(needle));
  }, [cards, query]);
  const selected = cards.find((card) => card.id === selectedId) ?? null;
  useEffect(() => {
    if (selectedId && raw && !selected) updateQuery({ cluster: null });
  }, [raw, selected, selectedId]);
  function updateQuery(changes: Record<string, string | null>) {
    setParams(current => {
      const next = new URLSearchParams(current);
      if (["q", "cluster", "section", "detail", "page_size"].some(key => key in changes)) next.delete("page");
      for (const [key, value] of Object.entries(changes)) {
        if (value === null || value === "") next.delete(key);
        else next.set(key, value);
      }
      return next;
    });
  }

  function openCluster(card: ClusterCard, step: ClusterStep = "overview") {
    updateQuery({ section: "clusters", cluster: card.id, detail: step === "overview" ? null : step, q: null });
  }
  function editable(card: ClusterCard) { return gate.canManage && !objectControls(card.managedByOperator).withheld; }
  function connectorControls(card: ClusterCard) {
    const binding = connectorBinding(card);
    return editable(card) && raw?.nodes !== null && binding.kind !== "pool" && binding.kind !== "unavailable";
  }
  function clusterMenu(card: ClusterCard, includeNavigation = true) {
    return <AppAccessRowMenu label={`Cluster actions for ${card.name}`} actions={[
      ...(includeNavigation ? [
        { key: "view", label: "View cluster", onSelect: () => openCluster(card) },
        { key: "services", label: "View services", onSelect: () => updateQuery({ section: "services", cluster: card.id, detail: null, q: null }) },
      ] : []),
      ...(connectorControls(card) ? [{ key: "connector", label: connectorBinding(card).kind === "missing" ? "Select connector" : "Change connector", onSelect: () => setConnectorFor(card) }] : []),
      ...(editable(card) ? [
        { key: "provider", label: "Correct provider metadata", onSelect: () => setProviderMetadataFor(card) },
        { key: "remove", label: "Deregister", danger: true, onSelect: () => setDeregisterFor(card) },
      ] : []),
    ]} />;
  }
  function connectorCell(card: ClusterCard) {
    const binding = connectorBinding(card);
    const connector = clusterConnectorState({ connectorNodeId: binding.nodeId, gateways });
    return <div className="kubernetes-cell-stack">
      <span>{binding.kind === "pool" ? `Pool: ${nodeName.get(binding.nodeId) ?? "active connector unavailable"}` : binding.kind === "direct" ? nodeName.get(binding.nodeId) ?? "Connector unavailable" : binding.kind === "missing" ? "Connector required" : "Connector pool state unavailable"}</span>
      {binding.kind === "missing" && <span className="sr-only">connector: not selected</span>}
      {binding.kind === "unavailable" && <span className="sr-only">connector pool state could not be read; no connector state is inferred</span>}
      {raw?.nodes === null ? <span className="kubernetes-muted">Gateway inventory unavailable</span> : binding.kind !== "unavailable" && !connector.configured && connector.why !== null && <><Badge tone="warn">Needs setup</Badge><span className="sr-only">{connector.why}</span></>}
    </div>;
  }
  const clusterColumns = [
    { key: "cluster", header: "Cluster", cell: (card: ClusterCard) => {
      const provider = providerPlatformEntry(card.provider, card.platform);
      return <div className="kubernetes-cell-stack"><button type="button" className="kubernetes-name-link" onClick={() => openCluster(card)}>{card.name}</button><span className="kubernetes-muted" aria-label={card.managedByOperator ? managedEditWarning("cluster") : undefined}>{[provider?.platformLabel, card.managedByOperator ? "GitOps" : "Dashboard"].filter(Boolean).join(" · ")}</span></div>;
    } },
    { key: "site", header: "Network", cell: (card: ClusterCard) => siteName.get(card.siteId) ?? "Site unavailable" },
    { key: "connector", header: "Connector", cell: connectorCell },
    { key: "services", header: "Services", cell: (card: ClusterCard) => card.services.length },
    { key: "actions", header: "Actions", cell: (card: ClusterCard) => clusterMenu(card) },
  ];

  type SvcRow = (typeof serviceRows)[number];
  const [inspectedService, setInspectedService] = useState<SvcRow | null>(null);
  const serviceColumns = [
    { key: "service", header: "Service", cell: (row: SvcRow) => <div className="kubernetes-cell-stack"><button type="button" className="kubernetes-name-link" aria-label={row.fqdn} title={row.fqdn} onClick={() => setInspectedService(row)}>{row.name}</button><span className="kubernetes-muted">{row.namespace}</span></div> },
    { key: "cluster", header: "Cluster", cell: (row: SvcRow) => <button type="button" className="kubernetes-text-link" onClick={() => { const card = cards.find(card => card.id === row.clusterId); if (card) openCluster(card); }}>{row.clusterName}</button> },
    { key: "vip", header: "VIP · port", cell: (row: SvcRow) => <div className="kubernetes-cell-stack"><span>{row.vip}</span><span className="kubernetes-muted">{row.protocol.toUpperCase()} {row.ports}</span></div> },
    { key: "owner", header: "Managed by", cell: (row: SvcRow) => <span aria-label={row.managedByOperator ? managedEditWarning("Service") : undefined}>{row.managedByOperator ? "GitOps" : "Dashboard"}</span> },
    { key: "actions", header: "Actions", cell: (row: SvcRow) => <AppAccessRowMenu label={`Service actions for ${row.fqdn}`} actions={[
      { key: "view", label: "View service", onSelect: () => setInspectedService(row) },
      ...(gate.canManage && !objectControls(row.managedByOperator).withheld ? [{ key: "remove", label: "Unexpose", danger: true, onSelect: () => setUnexposeFor(row) }] : []),
    ]} /> },
  ];
  const filteredServices = serviceRows.filter(row => (!selectedId || row.clusterId === selectedId) && `${row.fqdn} ${row.namespace} ${row.name} ${row.clusterName}`.toLowerCase().includes(query.trim().toLowerCase()));
  const showingServices = section === "services" || (section === "clusters" && selected && detail === "services");
  const count = showingServices ? filteredServices.length : visibleCards.length;
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(count / pageSize)));
  const first = (page - 1) * pageSize;
  const pagedCards = visibleCards.slice(first, first + pageSize);
  const pagedServices = filteredServices.slice(first, first + pageSize);
  useEffect(() => { if (raw && scopeCurrent && requestedPage !== page) updateQuery({ page: page === 1 ? null : String(page) }); }, [raw, scopeCurrent, requestedPage, page]);
  const pagination = <AppAccessPagination maxOffset={null} page={page} pageSize={pageSize} count={showingServices ? pagedServices.length : pagedCards.length} hasNext={page * pageSize < count} onPageChange={next => updateQuery({ page: String(next) })} onPageSizeChange={size => updateQuery({ page_size: String(size) })} previousLabel={showingServices ? "Previous services" : "Previous clusters"} nextLabel={showingServices ? "Next services" : "Next clusters"} />;
  const selectedProviderContext = selected ? providerPlatformEntry(selected.provider, selected.platform) : null;
  const selectedBinding = selected ? connectorBinding(selected) : null;
  const resetSearch = () => updateQuery({ q: null });
  const servicesList = <section className="kubernetes-services" aria-label="Exposed services">
    <div className="kubernetes-list-toolbar">
      <Input aria-label="Search services" placeholder="Search services, namespaces or clusters…" value={query} onChange={event => updateQuery({ q: event.target.value })} />
      {section === "services" && <Select aria-label="Filter services by cluster" value={selectedId ?? ""} onChange={event => updateQuery({ cluster: event.target.value || null })} width="auto"><option value="">All clusters</option>{cards.map(card => <option key={card.id} value={card.id}>{card.name}</option>)}</Select>}
      <span className="kubernetes-list-count">{filteredServices.length} service{filteredServices.length === 1 ? "" : "s"}</span>
      {selected && editable(selected) && <Button size="sm" onClick={() => setExposeFor(selected)}>Expose service</Button>}
    </div>
    {pagedServices.length ? <div className="kubernetes-flat-table kubernetes-service-table" data-scoped={section === "clusters" ? "true" : undefined}><DataTable caption="Exposed Kubernetes Services" columns={section === "clusters" ? serviceColumns.filter(column => column.key !== "cluster") : serviceColumns} rows={pagedServices} rowKey={row => row.id} empty={null} failed={false} filterable={false} pageSize={0} variant="flat" /></div> : <div className="kubernetes-empty-state" role="status"><h3>{query ? "No matching services" : "No exposed services"}</h3><p>{query ? "Try another service or namespace." : selected ? "Choose a service from this cluster’s connector inventory." : "Select a cluster to expose its first service."}</p>{query && <Button size="sm" variant="ghost" onClick={resetSearch}>Clear search</Button>}</div>}
    {pagination}
  </section>;
  const operatorCommands = [
    `CLI_VERSION="$(tunnex version)"
CHART_VERSION="\${CLI_VERSION#v}"
TUNNEX_CONTROL_PLANE_URL="${window.location.origin}"
TUNNEX_ORGANIZATION_ID="${orgId ?? "replace-with-organization-uuid"}"

case "$CHART_VERSION" in dev|unknown|"")
  echo "Use a released CLI or set CHART_VERSION explicitly." >&2
  exit 1
esac`,
    `helm upgrade --install tunnex-operator-crds \\
  oci://ghcr.io/tunnexio/charts/tunnex-operator-crds \\
  --version "$CHART_VERSION" \\
  --namespace tunnex-system --create-namespace \\
  --take-ownership --wait

kubectl wait --for=condition=Established --timeout=120s \\
  crd/tunnexclusters.tunnex.io \\
  crd/tunnexexposedservices.tunnex.io \\
  crd/tunnexgrants.tunnex.io`,
    `helm upgrade --install tunnex-operator \\
  oci://ghcr.io/tunnexio/charts/tunnex-operator \\
  --version "$CHART_VERSION" \\
  --namespace tunnex-system --create-namespace \\
  --set-string controlPlane.url="$TUNNEX_CONTROL_PLANE_URL" \\
  --set-string controlPlane.organizationID="$TUNNEX_ORGANIZATION_ID" \\
  --set-string machineToken.existingSecret=tunnex-operator-credential \\
  --atomic --wait`
  ];
  const currentRaw = scopeCurrent ? raw : null;

  return (
    <div className="network-management kubernetes-workspace">
      <h1 className="sr-only">Kubernetes</h1>
      <div className="kubernetes-workspace-toolbar">
        <nav aria-label="Kubernetes workspace" className="kubernetes-tabs">
          {([["clusters", "Clusters"], ["services", "Exposed services"], ["operations", "Operations"]] as const).map(([id, label]) => <button type="button" key={id} aria-current={section === id ? "page" : undefined} onClick={() => updateQuery({ section: id, cluster: null, detail: null, q: null })}>{label}</button>)}
        </nav>
        <div className="kubernetes-toolbar-actions"><Button variant="ghost" size="sm" aria-label="Refresh Kubernetes" onClick={() => void reload()}>Refresh</Button>{currentRaw && gate.canManage && (currentRaw.sites?.length ?? 0) > 0 && <Button size="sm" onClick={() => setRegistering(true)}>Register cluster</Button>}</div>
      </div>
      {scopeCurrent && loadError && <LoadRetry error={loadError} onRetry={reload} />}
      {(!scopeCurrent || (!loadError && currentRaw === null)) && <Loading size="inline" label="Loading Kubernetes services…" />}
      {currentRaw && !loadError && <>
        {(currentRaw.sitesError || currentRaw.nodesError) && <div role="alert" className="kubernetes-read-warning"><span>{[currentRaw.sitesError && "Network inventory unavailable. Registration is disabled.", currentRaw.nodesError && "Gateway inventory unavailable. Connector selection and configuration details cannot be verified."].filter(Boolean).join(" ")}</span><Button variant="ghost" size="sm" onClick={() => void reload()}>Retry inventory reads</Button></div>}
        {cards.length === 0 && section !== "operations" ? <div className="kubernetes-empty-state" role="status"><h2>Connect your first cluster</h2><p>{currentRaw.sites === null ? "Network inventory is unavailable. Retry before registering a cluster." : currentRaw.sites.length === 0 ? "Add a network with a gateway before connecting a cluster." : "Register a cluster, then choose the services to expose."}</p>{currentRaw.sites?.length === 0 && <Link className="kubernetes-text-link" to="/network/setup">Set up a network</Link>}</div> : <>
          {section === "clusters" && !selected && <section aria-label="Clusters" className="kubernetes-clusters">
            <div className="kubernetes-list-toolbar"><Input aria-label="Search clusters" value={query} onChange={event => updateQuery({ q: event.target.value })} placeholder="Search clusters" /><span className="kubernetes-list-count">{visibleCards.length} cluster{visibleCards.length === 1 ? "" : "s"} · {serviceRows.length} exposed service{serviceRows.length === 1 ? "" : "s"}</span></div>
            {pagedCards.length ? <div className="kubernetes-flat-table kubernetes-cluster-table"><DataTable caption="Registered Kubernetes clusters" columns={clusterColumns} rows={pagedCards} rowKey={card => card.id} empty={null} failed={false} filterable={false} pageSize={0} variant="flat" /></div> : <div className="kubernetes-empty-state" role="status"><h3>No matching clusters</h3><p>Try another cluster name.</p><Button size="sm" variant="ghost" onClick={resetSearch}>Clear search</Button></div>}
            {pagination}
          </section>}
          {section === "services" && servicesList}
          {section === "clusters" && selected && <section className="kubernetes-cluster-detail" aria-label={`${selected.name} cluster`}>
            <nav className="kubernetes-breadcrumb" aria-label="Cluster breadcrumb"><button type="button" onClick={() => updateQuery({ cluster: null, detail: null, q: null })}>Clusters</button><span aria-hidden="true">/</span><span aria-current="page">{selected.name}</span></nav>
            <header className="kubernetes-entity-header"><div><h2>{selected.name}</h2><p>{selectedProviderContext ? `${selectedProviderContext.providerLabel} · ${selectedProviderContext.platformLabel}` : "Provider not recorded"}{selected.managedByOperator ? " · GitOps" : ""}</p></div>{clusterMenu(selected, false)}</header>
            <div className="kubernetes-detail-layout">
              <nav className="kubernetes-detail-rail" aria-label="Cluster detail sections">{clusterSteps.map(step => <button type="button" key={step} aria-current={detail === step ? "step" : undefined} onClick={() => updateQuery({ detail: step === "overview" ? null : step, q: null })}>{step[0].toUpperCase() + step.slice(1)}</button>)}</nav>
              <section className="kubernetes-detail-stage" aria-labelledby="kubernetes-stage-heading">{detail === "services" && <header className="kubernetes-stage-header"><h3 id="kubernetes-stage-heading">Services</h3></header>}
                {detail === "overview" && <ResourceSummary title="Overview" headingId="kubernetes-stage-heading" actions={<span className="kubernetes-stage-count">{selected.services.length} exposed service{selected.services.length === 1 ? "" : "s"}</span>} footer={<div className="kubernetes-summary-actions"><Button variant="ghost" onClick={() => updateQuery({ detail: "connection", q: null })}>View connection</Button><Button variant="ghost" onClick={() => updateQuery({ section: "services", cluster: selected.id, detail: null, q: null })}>View services</Button></div>}>
                  <dl className="kubernetes-facts tnx-resource-facts"><div><dt>Network</dt><dd>{siteName.has(selected.siteId) ? <Link to={`/sites?section=overview&site=${selected.siteId}`}>{siteName.get(selected.siteId)}</Link> : "Site record unavailable"}</dd></div><div><dt>Connector</dt><dd>{connectorCell(selected)}</dd></div><div><dt>Managed by</dt><dd aria-label={selected.managedByOperator ? managedEditWarning("cluster") : undefined}>{selected.managedByOperator ? "GitOps operator" : "Dashboard"}</dd></div></dl>
                  {selected.managedByOperator && <p className="kubernetes-context">Edit the cluster CR to change its configuration.</p>}
                </ResourceSummary>}
                {detail === "connection" && <>
                  <ResourceSummary title="Connection" headingId="kubernetes-stage-heading" actions={<span className="kubernetes-stage-count">{selected.services.length} exposed service{selected.services.length === 1 ? "" : "s"}</span>}>
                  <dl className="kubernetes-facts tnx-resource-facts"><div><dt>Network</dt><dd>{siteName.get(selected.siteId) ?? "Site record unavailable"}</dd></div><div><dt>Connector</dt><dd>{selectedBinding?.kind === "pool" ? `Pool active: ${nodeName.get(selectedBinding.nodeId) ?? "Unavailable"}` : selectedBinding?.kind === "direct" ? nodeName.get(selectedBinding.nodeId) ?? "Unavailable" : selectedBinding?.kind === "missing" ? "Not selected" : "Pool state unavailable"}</dd></div></dl>
                  {raw?.nodes !== null && selectedBinding?.kind !== "unavailable" && <p className="kubernetes-context">{clusterConnectorState({ connectorNodeId: selectedBinding?.nodeId ?? null, gateways }).why ?? "Connector configuration is available. Service readiness is reported separately."}</p>}
                  {connectorControls(selected) && <Button variant="ghost" size="sm" onClick={() => setConnectorFor(selected)}>{selectedBinding?.kind === "missing" ? "Select connector" : "Change connector"}</Button>}
                  </ResourceSummary>
                  {orgId && <K8sConnectorPoolPanel orgId={orgId} cluster={selected} nodes={currentRaw.nodes} role={myRole} emailVerified={emailVerified} onChanged={reload} />}
                </>}
                {detail === "services" && servicesList}
                {detail === "network" && <ResourceSummary title="Network" headingId="kubernetes-stage-heading" actions={<span className="kubernetes-stage-count">{selected.services.length} exposed service{selected.services.length === 1 ? "" : "s"}</span>}><dl className="kubernetes-facts tnx-resource-facts">{[["VIP range", selected.vipRange], ["Service CIDR", selected.serviceCidr], ["DNS zone", selected.dnsZone || "Not configured"], ["DNS VIP", selected.dnsVip ?? "Not allocated"]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl></ResourceSummary>}
              </section>
            </div>
          </section>}
          {section === "operations" && <div className="kubernetes-operations">
            <SettingGroup title="Kubernetes configuration">
              <SettingRow label="Traffic path" description="Service name → VIP → connector → ready pod"><Button size="sm" variant="ghost" onClick={() => setTrafficPathOpen(true)}>View path</Button></SettingRow>
              {orgId && <K8sHAActivationPanel orgId={orgId} role={myRole} emailVerified={emailVerified} />}
              <SettingRow label="Operator and connector setup" description="Install a connector or the optional GitOps operator."><Button size="sm" variant="ghost" onClick={() => { setCommandKind("gateway"); setCommandStep(0); setCommandsOpen(true); }}>View commands</Button></SettingRow>
              <SettingRow label="Machine credentials"><SettingValue>{currentRaw.machineCreds === null ? "Credentials unavailable" : `${currentRaw.machineCreds} machine ${currentRaw.machineCreds === 1 ? "credential" : "credentials"}`}</SettingValue></SettingRow>
            </SettingGroup>
          </div>}
        </>}
      </>}
      {scopeCurrent && inspectedService && <Modal placement="right" showClose title={inspectedService.name} onDismiss={() => setInspectedService(null)} actions={<><Button variant="ghost" onClick={() => { const card = cards.find(card => card.id === inspectedService.clusterId); if (card) openCluster(card); setInspectedService(null); }}>View cluster</Button>{gate.canManage && !inspectedService.managedByOperator && <Button variant="danger" onClick={() => { setUnexposeFor(inspectedService); setInspectedService(null); }}>Unexpose</Button>}</>}>
        <ResourceSummary title="Service details" description={inspectedService.fqdn} className="kubernetes-service-inspection"><dl className="kubernetes-facts tnx-resource-facts tnx-resource-facts-single">{[["Cluster", inspectedService.clusterName], ["Namespace", inspectedService.namespace], ["VIP", inspectedService.vip], ["Protocol", inspectedService.protocol.toUpperCase()], ["Port", inspectedService.ports], ["Managed by", inspectedService.managedByOperator ? "GitOps operator" : "Dashboard"]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>{inspectedService.managedByOperator && <p className="kubernetes-context" aria-label={managedEditWarning("Service")}>Edit the Service CR to change exposure.</p>}</ResourceSummary>
      </Modal>}
      {scopeCurrent && trafficPathOpen && (
        <Modal placement="right" showClose title="Kubernetes traffic path" onDismiss={() => setTrafficPathOpen(false)} actions={<Button variant="ghost" onClick={() => setTrafficPathOpen(false)}>Close</Button>}>
          <p className="font-sans text-cell text-ink-heading">device → service name → VIP → ready pod</p>
          <p className="mt-3 text-cell text-ink-tertiary">Endpoint inventory failures withdraw delivery. Policy remains keyed to the pre-DNAT VIP.</p>
        </Modal>
      )}
      {scopeCurrent && commandsOpen && <Modal placement="right" showClose title="Operator and connector setup" onDismiss={() => setCommandsOpen(false)} actions={<Button variant="ghost" onClick={() => setCommandsOpen(false)}>Close</Button>}>
        <div className="kubernetes-command-guide">
          <nav aria-label="Setup method" className="kubernetes-command-methods"><button type="button" aria-current={commandKind === "gateway" ? "page" : undefined} onClick={() => setCommandKind("gateway")}>Gateway</button><button type="button" aria-current={commandKind === "operator" ? "page" : undefined} onClick={() => { setCommandKind("operator"); setCommandStep(0); }}>GitOps operator</button></nav>
          {commandKind === "gateway" ? <><h3>Install the connector</h3><p>Use the logged-in, version-matched CLI. Review the plan before installing.</p><pre>{`tunnex k8s plan --org ${orgId ?? "<organization-id>"} --node-name <gateway-name>
tunnex k8s install --org ${orgId ?? "<organization-id>"} --node-name <gateway-name> --yes`}</pre><details><summary>Credential handling</summary><p>The CLI streams the single-use token on stdin and removes the consumed bootstrap Secret after readiness.</p></details></> : <>
            <nav className="kubernetes-command-steps" aria-label="Operator setup steps">{["Prepare", "Install CRDs", "Install operator"].map((label, index) => <button type="button" key={label} aria-current={commandStep === index ? "step" : undefined} onClick={() => setCommandStep(index)}><span>{index + 1}</span>{label}</button>)}</nav>
            <h3>{["Prepare the environment", "Upgrade the CRDs", "Install the operator"][commandStep]}</h3>
            <p>{commandStep === 0 ? "Create the machine credential as Kubernetes Secret tunnex-operator-credential in tunnex-system. Set these variables, then run all steps in the same shell." : commandStep === 1 ? "Upgrade retained CRDs before the operator. Adoption accepts only an exact approved legacy Tunnex schema; unknown ownerless schemas fail before apply." : "The chart reads the existing Secret. This upgrade waits for readiness and rolls back on failure."}</p>
            <pre>{operatorCommands[commandStep]}</pre>
            <div className="kubernetes-command-footer"><Button variant="ghost" disabled={commandStep === 0} onClick={() => setCommandStep(step => step - 1)}>Back</Button>{commandStep < 2 && <Button onClick={() => setCommandStep(step => step + 1)}>Continue</Button>}</div>
          </>}
        </div>
      </Modal>}

      {scopeCurrent && gate.canManage && registering && orgId && raw && (
        <ProviderFirstEnrollmentModal
          sites={raw.sites}
          nodes={raw.nodes}
          sitesError={raw.sitesError}
          nodesError={raw.nodesError}
          onDismiss={() => setRegistering(false)}
          onSubmit={async (draft) => {
            if (!draft.provider || !draft.platform || !providerPlatformEntry(draft.provider, draft.platform)) {
              return { ok: false as const, error: "Choose one supported provider and Kubernetes service pair." };
            }
            // The request is still constructed explicitly: UI-only draft state
            // cannot leak onto the wire, and provider metadata remains context,
            // never a cloud-discovery or authority claim.
            const { error } = await api.POST(
              "/api/v1/organizations/{orgId}/k8s/clusters",
              {
                params: { path: { orgId } },
                body: {
                  site_id: draft.siteId,
                  connector_node_id: draft.connectorNodeId,
                  provider: draft.provider,
                  platform: draft.platform,
                  name: draft.name,
                  vip_range: draft.vipRange,
                  service_cidr: draft.serviceCidr,
                  dns_zone: draft.dnsZone,
                },
              },
            );
            return error
              ? { ok: false as const, error: apiErrorMessage(error, "Could not register the cluster.") }
              : { ok: true as const };
          }}
          onDone={() => {
            setRegistering(false);
            void reload();
          }}
        />
      )}
      {scopeCurrent && gate.canManage && exposeFor && orgId && (
        <ExposeServiceModal
          orgId={orgId}
          clusterId={exposeFor.id}
          onClose={() => setExposeFor(null)}
          onDone={reload}
        />
      )}
      {scopeCurrent && gate.canManage && connectorFor && orgId && raw && raw.nodes !== null && (
        <SetConnectorModal
          orgId={orgId}
          cluster={connectorFor}
          nodes={raw.nodes ?? []}
          onClose={() => setConnectorFor(null)}
          onDone={reload}
        />
      )}
      {scopeCurrent && gate.canManage && providerMetadataFor && orgId && (
        <ProviderMetadataCorrectionModal
          clusterName={providerMetadataFor.name}
          initialProvider={providerMetadataFor.provider}
          initialPlatform={providerMetadataFor.platform}
          onDismiss={() => setProviderMetadataFor(null)}
          onSubmit={async (provider, platform) => {
            const { error } = await api.PUT(
              "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/provider-metadata",
              {
                params: { path: { orgId, clusterId: providerMetadataFor.id } },
                body: { provider, platform },
              },
            );
            return error
              ? { ok: false as const, error: apiErrorMessage(error, "Could not save provider metadata.") }
              : { ok: true as const };
          }}
          onDone={() => {
            setProviderMetadataFor(null);
            void reload();
          }}
        />
      )}
      {scopeCurrent && gate.canManage && deregisterFor && orgId && (
        <DeregisterClusterModal
          orgId={orgId}
          card={deregisterFor}
          onClose={() => setDeregisterFor(null)}
          onDone={reload}
        />
      )}
      {scopeCurrent && gate.canManage && unexposeFor && orgId && (
        <UnexposeServiceModal
          orgId={orgId}
          service={unexposeFor}
          onClose={() => setUnexposeFor(null)}
          onDone={reload}
        />
      )}
    </div>
  );
}

function SetConnectorModal({
  orgId,
  cluster,
  nodes,
  onClose,
  onDone,
}: {
  orgId: string;
  cluster: ClusterCard;
  nodes: Node[];
  onClose: () => void;
  onDone: () => void;
}) {
  const connectors = nodes.filter(
    (node) =>
      node.status === "active" && node.site_id === cluster.siteId && node.endpoint?.trim(),
  );
  const [connectorNodeId, setConnectorNodeId] = useState(
    cluster.connectorNodeId ?? connectors[0]?.id ?? "",
  );
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (busy || !connectors.some(node => node.id === connectorNodeId)) return;
    setBusy(true);
    setErr(null);
    try {
      const { error } = await api.PUT("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector", {
        params: { path: { orgId, clusterId: cluster.id } }, body: { node_id: connectorNodeId },
      });
      if (error) return setErr(apiErrorMessage(error, "Could not set the in-cluster connector."));
      onClose(); onDone();
    } catch { setErr("Could not reach the API. Refresh before retrying the connector change."); }
    finally { setBusy(false); }
  }

  return (
    <Modal
      placement="right" showClose
      title={`Set connector for ${cluster.name}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !connectorNodeId}>
            {busy ? "Saving connector…" : "Save connector"}
          </Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
      <p className="mb-3 text-cell text-ink-tertiary">
        Choose the in-cluster gateway that receives service traffic.
      </p>
      <p className="mb-3 text-micro text-warn">Changing the connector can interrupt service delivery until the replacement reports fresh inventory.</p>
      <Field label="In-cluster connector node">
        <Select disabled={busy} value={connectorNodeId} onChange={(e) => setConnectorNodeId(e.target.value)}>
          {connectors.length === 0 ? (
            <option value="">No active endpoint-bearing connector is bound to this site</option>
          ) : (
            connectors.map((node) => (
              <option key={node.id} value={node.id}>
                {node.name}
              </option>
            ))
          )}
        </Select>
      </Field>
      <ErrorText>{err}</ErrorText>
      </div>
    </Modal>
  );
}

type InventoryService = components["schemas"]["K8sInventoryService"];
type InventoryPage = components["schemas"]["K8sInventoryPage"];

export function ExposeServiceModal({
  orgId,
  clusterId,
  onClose,
  onDone,
  fixtureInventory,
  onFixtureExpose,
}: {
  orgId: string;
  clusterId: string;
  onClose: () => void;
  onDone: () => void;
  fixtureInventory?: InventoryPage;
  onFixtureExpose?: (inventoryRef: string, portRefs: string[]) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState("");
  // WF-K5 M8/M9: an exposure needs a SINGLE specific port + a protocol — the gateway DNATs VIP:port ->
  // podIP:targetPort, so all-ports/ranges are refused server-side. The form must offer the port the refusal
  // teaches the user to supply (offering the refusal without the field would make the dashboard structurally
  // unable to produce a valid exposure). Protocol is tcp/udp (no "any" — a ported DNAT needs an L4 proto).
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [manualOpen, setManualOpen] = useState(false);
  const [inventory, setInventory] = useState<InventoryService[] | null>(null);
  const [inventoryCursor, setInventoryCursor] = useState<string | null>(null);
  const [inventoryState, setInventoryState] = useState<"unavailable" | "loading" | "ready" | "empty" | "stale" | "error">("loading");
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const [inventoryObservedAt, setInventoryObservedAt] = useState<string | null>(null);
  const [inventoryFreshUntil, setInventoryFreshUntil] = useState<string | null>(null);
  const [inventoryBusy, setInventoryBusy] = useState(false);
  const [selectedNamespace, setSelectedNamespace] = useState("");
  const [selectedInventoryRef, setSelectedInventoryRef] = useState("");
  const [selectedPortRefs, setSelectedPortRefs] = useState<string[]>([]);
  const inventoryEpoch = useRef(0);
  const inventoryItemsRef = useRef<InventoryService[]>([]);

  // Client-side UX validation ONLY — the server's ExposeService is the authoritative validator (one-validator):
  // its typed refusals (service_port_required / service_port_range_unsupported) render verbatim via apiErrorMessage.
  const portNum = Number(port);
  const portValid =
    Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535;

  const namespaces = useMemo(
    () => [...new Set((inventory ?? []).map((item) => item.namespace))].sort(),
    [inventory],
  );
  const namespaceServices = useMemo(
    () => (inventory ?? []).filter((item) => item.namespace === selectedNamespace),
    [inventory, selectedNamespace],
  );
  const selectedInventory = namespaceServices.find((item) => item.inventory_ref === selectedInventoryRef) ?? null;

  const loadInventory = useCallback(async (cursor?: string, append = false) => {
    const epoch = ++inventoryEpoch.current;
    if (!append) {
      setInventory(null);
      inventoryItemsRef.current = [];
      setInventoryObservedAt(null);
      setInventoryFreshUntil(null);
      setInventoryState("loading");
      setSelectedNamespace("");
      setSelectedInventoryRef("");
      setSelectedPortRefs([]);
    }
    setInventoryError(null);
    const result = await loadOne(() => api.GET(
      "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/inventory",
      { params: { path: { orgId, clusterId }, query: { cursor, limit: 100 } } },
    ));
    if (epoch !== inventoryEpoch.current) return;
    if (!result.ok) {
      const message = result.error || "Could not read authenticated connected-agent inventory.";
      setInventoryError(message);
      setInventoryState(message.toLowerCase().includes("stale") ? "stale" : "error");
      return;
    }
    if (!result.data || !Array.isArray(result.data.items)) {
      setInventoryState("unavailable");
      setInventoryCursor(null);
      return;
    }
    const items = append ? [...inventoryItemsRef.current, ...result.data.items] : result.data.items;
    inventoryItemsRef.current = items;
    setInventory(items);
    setInventoryCursor(result.data.next_cursor ?? null);
    setInventoryObservedAt(result.data.observed_at);
    setInventoryFreshUntil(result.data.fresh_until);
    setInventoryState(items.length === 0 ? "empty" : "ready");
  }, [clusterId, orgId]);

  useEffect(() => {
    if (fixtureInventory) {
      inventoryItemsRef.current = fixtureInventory.items;
      setInventory(fixtureInventory.items);
      setInventoryCursor(fixtureInventory.next_cursor ?? null);
      setInventoryObservedAt(fixtureInventory.observed_at);
      setInventoryFreshUntil(fixtureInventory.fresh_until);
      setInventoryState(fixtureInventory.items.length === 0 ? "empty" : "ready");
    } else void loadInventory();
    return () => { inventoryEpoch.current += 1; };
  }, [clusterId, fixtureInventory, orgId]);

  async function submit() {
    if (busy || inventoryBusy) return;
    setBusy(true);
    setErr(null);
    try {
      const { error } = await api.POST(
        "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/services",
        {
          params: { path: { orgId, clusterId } },
          // Single specific port: port_low == port_high (ranges are refused). Server stays authoritative.
          body: {
            name,
            namespace,
            protocol,
            port_low: portNum,
            port_high: portNum,
          },
        },
      );
      if (error) return setErr(apiErrorMessage(error, "Could not expose the Service."));
      onClose();
      onDone();
    } finally {
      setBusy(false);
    }
  }

  async function exposeInventory() {
    if (manualOpen || inventoryState !== "ready" || !selectedInventory || selectedPortRefs.length === 0 || busy || inventoryBusy) return;
    setInventoryBusy(true);
    setInventoryError(null);
    try {
      if (onFixtureExpose) {
        await onFixtureExpose(selectedInventory.inventory_ref, selectedPortRefs);
        return;
      }
      const response = await api.POST(
        "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/inventory/{inventoryRef}/expose",
        {
          params: { path: { orgId, clusterId, inventoryRef: selectedInventory.inventory_ref } },
          body: { port_refs: selectedPortRefs },
        },
      );
      if (response.error) {
        const code = apiErrorCode(response.error) ?? "";
        setInventoryError(apiErrorMessage(response.error, "Could not atomically expose the selected Service ports."));
        if (code.includes("stale") || code.includes("inventory")) setInventoryState("stale");
        return;
      }
      onClose();
      onDone();
    } finally {
      setInventoryBusy(false);
    }
  }

  return (
    <Modal
      placement="right" showClose
      title="Expose a Service"
      size="wide"
      onDismiss={busy || inventoryBusy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy || inventoryBusy}>
            Cancel
          </Button>
          {manualOpen && <Button
            onClick={submit}
            disabled={
              busy ||
              inventoryBusy ||
              !manualOpen ||
              name.trim() === "" ||
              namespace.trim() === "" ||
              !portValid
            }
          >
            {busy ? "Exposing service…" : "Expose service"}
          </Button>}
        </>
      }
    >
      <div className="kubernetes-exposure-form">
      {!manualOpen && <>
      <K8sServiceInventoryStatus variant="flat" state={
        inventoryState === "unavailable" ? { kind: "unavailable" } :
          inventoryState === "loading" ? { kind: "loading" } :
          inventoryState === "empty" ? { kind: "empty" } :
            inventoryState === "stale" ? { kind: "stale" } :
              inventoryState === "error" ? { kind: "error", message: inventoryError ?? undefined } :
                { kind: "ready", content: (
                  <div className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-2">
                      <Field label="Namespace">
                        <Select value={selectedNamespace} onChange={(event) => { setSelectedNamespace(event.target.value); setSelectedInventoryRef(""); setSelectedPortRefs([]); }}>
                          <option value="">Choose a verified namespace…</option>
                          {namespaces.map((value) => <option key={value} value={value}>{value}</option>)}
                        </Select>
                      </Field>
                      <Field label="Service">
                        <Select disabled={!selectedNamespace} value={selectedInventoryRef} onChange={(event) => { setSelectedInventoryRef(event.target.value); setSelectedPortRefs([]); }}>
                          <option value="">{selectedNamespace ? "Choose a verified Service…" : "Choose a namespace first"}</option>
                          {namespaceServices.map((item) => <option key={item.inventory_ref} value={item.inventory_ref}>{item.service}</option>)}
                        </Select>
                      </Field>
                    </div>
                    {selectedInventory && <fieldset className="space-y-2"><legend className="text-xs font-semibold text-ink-body">Exact ports to expose</legend>{selectedInventory.ports.map((item) => { const checked = selectedPortRefs.includes(item.port_ref); return <label key={item.port_ref} className="flex cursor-pointer items-center gap-3 rounded-md border border-line px-3 py-2 text-sm text-ink-body"><input type="checkbox" className="h-4 w-4 accent-current" checked={checked} onChange={() => setSelectedPortRefs((current) => checked ? current.filter((ref) => ref !== item.port_ref) : [...current, item.port_ref])} /><span>{item.name ? `${item.name} · ` : ""}{item.protocol.toUpperCase()} {item.service_port}</span></label>; })}</fieldset>}
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      {inventoryCursor ? <Button variant="ghost" size="sm" disabled={inventoryBusy} onClick={() => void loadInventory(inventoryCursor, true)}>Load more inventory</Button> : <span className="text-micro text-ink-faint">Verified current inventory{inventoryObservedAt && inventoryFreshUntil ? ` · observed ${new Date(inventoryObservedAt).toLocaleString()} · fresh through ${new Date(inventoryFreshUntil).toLocaleString()}` : ""}</span>}
                      <Button disabled={!selectedInventory || selectedPortRefs.length === 0 || inventoryBusy || busy} onClick={() => void exposeInventory()}>{inventoryBusy ? "Exposing selected ports…" : `Expose selected ports (${selectedPortRefs.length})`}</Button>
                    </div>
                    {inventoryError && <ErrorText>{inventoryError}</ErrorText>}
                  </div>
                ) }
      } />

      {(inventoryState === "stale" || inventoryState === "error") && <div className="mt-2"><Button variant="ghost" size="sm" disabled={inventoryBusy || busy} onClick={() => void loadInventory()}>Retry inventory</Button></div>}

      </>}
      <details
        open={manualOpen}
        className="mt-4 border-t border-line pt-3"
      >
        <summary className="cursor-pointer text-sm font-semibold text-ink-heading" onClick={(event) => { event.preventDefault(); setManualOpen((current) => !current); }}>Advanced manual entry</summary>
        <p className="mt-2 text-micro text-warn">
          Manual values are not verified against connected-agent inventory. The server validates the existing compatibility request.
        </p>
        <div className="mt-3 space-y-3">
          <Field label="Service name">
            <Input
              disabled={!manualOpen}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. api"
            />
          </Field>
          <Field label="Namespace">
            <Input
              disabled={!manualOpen}
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              placeholder="e.g. prod"
            />
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <div>
              <Field label="Port">
                <Input
                  disabled={!manualOpen}
                  type="number"
                  min={1}
                  max={65535}
                  value={port}
                  aria-invalid={port !== "" && !portValid ? true : undefined}
                  aria-describedby={port !== "" && !portValid ? "k8s-manual-port-error" : undefined}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="e.g. 443"
                />
              </Field>
              {port !== "" && !portValid && (
                <p id="k8s-manual-port-error" role="alert" className="mt-1 text-xs text-amber-400">Enter a single port between 1 and 65535.</p>
              )}
            </div>
            <Field label="Protocol">
              <Select
                disabled={!manualOpen}
                value={protocol}
                onChange={(e) => setProtocol(e.target.value as "tcp" | "udp")}
              >
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </Select>
            </Field>
          </div>
        </div>
      </details>
      <ErrorText>{err}</ErrorText>
      </div>
    </Modal>
  );
}

function UnexposeServiceModal({
  orgId,
  service,
  onClose,
  onDone,
}: {
  orgId: string;
  service: Pick<ServiceRow, "id" | "name" | "fqdn" | "vip">;
  onClose: () => void;
  onDone: () => void;
}) {
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      const { error } = await api.DELETE(
        "/api/v1/organizations/{orgId}/k8s/services/{serviceId}",
        { params: { path: { orgId, serviceId: service.id } } },
      );
      if (error) return setErr(apiErrorMessage(error, "Could not unexpose the Service."));
      onClose();
      onDone();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      placement="right" showClose
      title={`Unexpose ${service.name}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" onClick={submit} disabled={busy}>
            {busy ? "Unexposing…" : "Unexpose"}
          </Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
        <p>Withdraw <strong>{service.fqdn}</strong> and its VIP <strong>{service.vip}</strong>. Grants to this Service identity stop compiling.</p>
        <p className="kubernetes-action-impact">Recovery requires a new exposure with a new Service identity. The freed VIP may be reused.</p>
        <details><summary>Dependencies and audit</summary><p>Live Agent Access requests or immutable Agent Policy Template references may refuse the change. Cluster-scope memberships remain as vanished, ineffective evidence. A successful withdrawal is recorded in the audit log.</p></details>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

function DeregisterClusterModal({
  orgId,
  card,
  onClose,
  onDone,
}: {
  orgId: string;
  card: ClusterCard;
  onClose: () => void;
  onDone: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (busy || typed !== card.name) return;
    setBusy(true);
    setErr(null);
    try {
      const { error } = await api.DELETE(
        "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}",
        {
          params: { path: { orgId, clusterId: card.id } },
        },
      );
      if (error) return setErr(apiErrorMessage(error, "Could not deregister the cluster."));
      onClose();
      onDone();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      placement="right" showClose
      title={`Deregister ${card.name}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={submit}
            disabled={busy || typed !== card.name}
          >
            {busy ? "Deregistering…" : "Deregister"}
          </Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
        <p>Permanently delete <strong>{card.name}</strong> and its <strong>{card.services.length} exposed service{card.services.length === 1 ? "" : "s"}</strong>. Direct Service grants are removed; VIP and DNS allocations are freed.</p>
        <p className="kubernetes-action-impact">This has no restore. Recovery requires registering the cluster again and recreating its connector, Services, grants and scopes.</p>
        <details><summary>Dependencies and audit</summary><p>Live Agent Access requests, immutable Agent Policy Template references or Kubernetes cluster scopes block deletion until cleared. Connector-pool HA state and retained inventory are deleted with the cluster. The audit records deleted Service and grant counts.</p></details>
      </div>
      <div className="mt-3">
        <Field label="Cluster name">
          <Input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={card.name}
            autoFocus
          />
        </Field>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}
