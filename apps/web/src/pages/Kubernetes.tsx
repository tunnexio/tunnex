import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import {
  api,
  apiErrorMessage,
  loadOne,
  type Loaded,
  type Member,
  type Role,
  type Site,
  type K8sCluster,
  type K8sService,
} from "../lib/api";
import { useAuth } from "../lib/auth";
import {
  Badge,
  Button,
  DataTable,
  EmptyState,
  ErrorText,
  Field,
  Input,
  Modal,
  PageHeader,
  Panel,
  Select,
} from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { Icon, type IconName } from "../components/Icon";
import { roleFromMembers } from "../lib/policyview";
import {
  assembleClusters,
  clusterConnectorState,
  k8sGate,
  managedEditWarning,
  objectControls,
  statTiles,
  type ClusterCard,
  type ServiceRow,
} from "../lib/k8sview";
// ⛔ EXPLICIT IMPORT, and it is load-bearing: without it `Node` resolves to the DOM's global `Node`, so
// `site_id` and `policy_degraded_kind` "do not exist" with no hint that a different type was found.
import type { Node } from "../lib/api";
import { ManagedBadge } from "../components/ManagedBadge";

// Kubernetes (S10.3): the in-cluster connectivity surface — register a cluster (a synthetic VIP range fronted
// by a site gateway) and expose its Services to the fabric. CONNECTIVITY is CORE (all editions): this whole
// page is k8s:manage-gated but never edition-gated; the GRANT that reaches an exposed Service (Access page)
// is the enterprise governance gate. Every rendered field is wire-truth; the FQDN is READ from the server
// (never constructed in the client — "copy, don't construct").

interface Raw {
  clusters: K8sCluster[];
  services: K8sService[];
  sites: Site[]; // the register-cluster site picker (one gateway = one site)
  // D9: gateways, for the reachability qualification. A cluster's Services must not read as reachable when a
  // gateway fronting its site has no endpoint view.
  nodes: Node[];
  // NULL = the read failed. Distinct from 0, which means "we looked and there are none".
  machineCreds: number | null;
}

export default function Kubernetes() {
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [orgId, setOrgId] = useState<string | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  const [raw, setRaw] = useState<Raw | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const selectedClusterRef = useRef<HTMLDivElement>(null);
  const priorSelectedRef = useRef<string | null>(null);
  const [params, setParams] = useSearchParams();
  const requestedSection = params.get("section");
  const section = requestedSection === "services" || requestedSection === "operations" ? requestedSection : "clusters";
  const query = params.get("q") ?? "";
  const selectedId = params.get("cluster");

  useEffect(() => {
    if (requestedSection !== null && requestedSection !== section) {
      const next = new URLSearchParams(params);
      next.set("section", section);
      setParams(next, { replace: true });
    }
  }, [params, requestedSection, section, setParams]);

  const reload = useCallback(async () => {
    setLoadError(null);
    setRaw(null);
    setRegistering(false);
    setExposeFor(null);
    setConnectorFor(null);
    setDeregisterFor(null);
    setUnexposeFor(null);
    // ⛔ THE ORG COMES FROM THE SEAM, NOT FROM INDEX ZERO (S12.5). This used to fetch the org list here and
    // take `[0]`, which meant a user in two organizations could reach only one of them and the switcher in
    // the header would have had nothing to switch.
    // ⛔ LOADING IS NOT ABSENCE (S12.5). See the note in Dashboard.tsx — three states, not two: still
    // loading (say nothing), the read failed (say THAT), genuinely no membership (say that).
    if (orgLoading) return;
    const first = currentOrg;
    if (!first)
      return setLoadError(
        orgFailed
          ? "Could not load your organizations."
          : "You are not a member of any organization yet.",
      );
    setOrgId(first.id);
    const memRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Member[]>;
    setMyRole(roleFromMembers(memRes, myId).role);
    const cRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/k8s/clusters", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<K8sCluster[]>;
    if (!cRes.ok) return setLoadError(cRes.error);
    const svcRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/k8s/services", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<K8sService[]>;
    if (!svcRes.ok) return setLoadError(svcRes.error);
    const sRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/sites", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Site[]>;
    // ⛔ TWO SECOND-CLASS READS. Both enrich a screen that is already correct, so a failure degrades a cell
    // rather than blanking the page — and `null` is carried through rather than collapsed to 0/[].
    const nRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/nodes", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Node[]>;
    const mcRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/machine-credentials", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<unknown[]>;
    setRaw({
      clusters: cRes.data,
      services: svcRes.data,
      sites: sRes.ok ? sRes.data : [],
      nodes: nRes.ok ? nRes.data : [],
      // NULL, not 0 — "we could not look" is a different fact from "there are none", and the tile says which.
      machineCreds: mcRes.ok ? mcRes.data.length : null,
    });
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, myId]);
  useEffect(() => {
    reload();
  }, [reload]);

  const gate = k8sGate({ role: myRole, emailVerified });
  const cards: ClusterCard[] = useMemo(
    () => (raw ? assembleClusters(raw.clusters, raw.services) : []),
    [raw],
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
  const tiles = useMemo(
    () => statTiles(cards, raw?.machineCreds ?? null),
    [cards, raw],
  );

  // ⛔ ONE MODAL OWNER AT PAGE LEVEL. The per-cluster card used to hold its own modal state; the wireframe's
  // layout is a TABLE, and a table row cannot own a modal without one instance per row. Hoisting it here is
  // what makes the table possible, and it keeps every mutation path (expose / unexpose / deregister) intact.
  const [exposeFor, setExposeFor] = useState<ClusterCard | null>(null);
  const [connectorFor, setConnectorFor] = useState<ClusterCard | null>(null);
  const [deregisterFor, setDeregisterFor] = useState<ClusterCard | null>(null);
  const [unexposeFor, setUnexposeFor] = useState<ServiceRow | null>(null);

  // Every exposed Service, flattened WITH its cluster, so the table is one scannable list rather than a list
  // per card. §6.2: the SERVICE list is the scaling surface, so it gets the table; the cluster list does not.
  const serviceRows = useMemo(
    () =>
      cards.flatMap((c) =>
        c.services.map((sv) => ({
          ...sv,
          clusterId: c.id,
          clusterName: c.name,
          configured: clusterConnectorState({ connectorNodeId: c.connectorNodeId, gateways })
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
    if (!selected || section !== "clusters" || priorSelectedRef.current === selected.id) return;
    priorSelectedRef.current = selected.id;
    // A navigation-owned target, not a global scroll reset: ordinary data rerenders retain operator position.
    selectedClusterRef.current?.scrollIntoView?.({ block: "start", behavior: "auto" });
  }, [selected, section]);
  useEffect(() => {
    if (selectedId && raw && !selected) updateQuery({ cluster: null });
  }, [raw, selected, selectedId]);
  function updateQuery(changes: Record<string, string | null>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === null || value === "") next.delete(key);
      else next.set(key, value);
    }
    setParams(next);
  }

  const clusterColumns = [
    {
      key: "cluster",
      header: "Cluster",
      cell: (c: ClusterCard) => (
        <span className="flex flex-col gap-0.5">
          <span className="flex items-center gap-2">
          <button type="button" className="font-mono text-ink-primary underline-offset-2 hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400" onClick={() => updateQuery({ cluster: c.id, section: "clusters" })}>{c.name}</button>
            {c.managedByOperator && <ManagedBadge />}
          </span>
          {/* The handoff's sub-line, and it carries the REASON the address is untouchable. */}
          {c.dnsVip !== null && (
            <span className="font-mono text-micro text-ink-faint">
              DNS VIP {c.dnsVip} (reserved, never handed to a Service)
            </span>
          )}
        </span>
      ),
    },
    {
      key: "site",
      header: "Fronted by",
      cell: (c: ClusterCard) => {
        const connector = clusterConnectorState({ connectorNodeId: c.connectorNodeId, gateways });
        const name = siteName.get(c.siteId) ?? null;
        return (
          <span className="flex flex-col gap-0.5">
            <span className="font-mono text-cell text-ink-body">
              {name === null ? "site unknown" : `site: ${name}`}
            </span>
            <span className="font-mono text-micro text-ink-faint">
              {c.connectorNodeId === null
                ? "connector: not selected"
                : `connector: ${nodeName.get(c.connectorNodeId) ?? "unavailable"}`}
            </span>
            {/* ⛔ D9 SITS HERE, ON THE THING IT IS ABOUT. The claim is about the GATEWAY fronting the site, so
                it belongs in this column and not on the Service rows, which would read as a fact about them. */}
            {!connector.configured && connector.why !== null && (
              <span className="text-micro text-warn">{connector.why}</span>
            )}
          </span>
        );
      },
    },
    {
      key: "vip",
      header: "VIP range",
      cell: (c: ClusterCard) => (
        <span className="font-mono text-cell text-ink-body">{c.vipRange}</span>
      ),
    },
    {
      key: "svccidr",
      header: "Service CIDR",
      cell: (c: ClusterCard) => (
        <span className="font-mono text-cell text-ink-body">
          {c.serviceCidr}
        </span>
      ),
    },
    {
      key: "zone",
      header: "DNS zone",
      cell: (c: ClusterCard) => (
        <span className="font-mono text-cell text-ink-body">{c.dnsZone}</span>
      ),
    },
    {
      key: "owner",
      header: "Managed by",
      cell: (c: ClusterCard) => (
        <Badge tone="neutral">
          {c.managedByOperator ? "OPERATOR" : "DASHBOARD"}
        </Badge>
      ),
    },
    {
      key: "actions",
      header: "",
      // ⛔ `numeric` IS THE RIGHT-ALIGN PROP DataTable ALREADY HAS. The buttons sat mid-column with a gap to
      // the table edge, so the row's actions read as unrelated to the row. Using the existing prop rather than
      // a wrapper div keeps one alignment mechanism in the table, not two.
      numeric: true,
      cell: (c: ClusterCard) =>
        !gate.canManage ? null : objectControls(c.managedByOperator)
            .withheld ? (
          // The destructive control is WITHHELD, not faked: a dashboard edit would be reconciled away.
          //
          // ⛔ THE ACCESSIBLE NAME CARRIES THE FULL GUIDANCE, and it is load-bearing rather than decoration:
          // the visible text is a fragment that fits a table cell, so a screen-reader user would otherwise get
          // "edit the CR, not here" with no statement of WHAT is managed or WHY the control is absent. My first
          // pass rendered the visible text only and the wiring test caught the regression.
          <span
            className="text-micro text-ink-faint"
            aria-label={managedEditWarning("cluster")}
          >
            edit the CR, not here
          </span>
        ) : (
          <span className="flex items-center justify-end gap-2">
            <Button size="sm" variant="ghost" onClick={() => updateQuery({ cluster: c.id, section: "clusters" })}>Manage</Button>
          </span>
        ),
    },
  ];

  type SvcRow = (typeof serviceRows)[number];
  const serviceColumns = [
    {
      key: "fqdn",
      header: "Exposed Service — FQDN (copy, don't construct)",
      cell: (r: SvcRow) => (
        <span className="flex flex-col gap-0.5">
          <span className="font-mono text-ink-primary">{r.fqdn}</span>
          <span className="text-micro text-ink-faint">
            ns {r.namespace} · name {r.name}
            {cards.length > 1 ? ` · cluster ${r.clusterName}` : ""}
          </span>
        </span>
      ),
    },
    {
      key: "vip",
      header: "VIP",
      cell: (r: SvcRow) => (
        <span className="font-mono text-cell text-ink-body">{r.vip}</span>
      ),
    },
    {
      key: "ports",
      header: "Ports",
      cell: (r: SvcRow) => (
        <span className="font-mono text-cell text-ink-body">
          {r.protocol} {r.ports}
        </span>
      ),
    },
    {
      key: "owner",
      header: "Managed by",
      cell: (r: SvcRow) => (
        <Badge tone="neutral">
          {r.managedByOperator ? "OPERATOR" : "DASHBOARD"}
        </Badge>
      ),
    },
    {
      key: "actions",
      header: "",
      numeric: true,
      cell: (r: SvcRow) =>
        !gate.canManage ? null : objectControls(r.managedByOperator)
            .withheld ? (
          <span
            className="text-micro text-ink-faint"
            aria-label={managedEditWarning("Service")}
          >
            edit the CR, not here
          </span>
        ) : (
          <Button size="sm" variant="ghost" onClick={() => setUnexposeFor(r)}>
            Unexpose
          </Button>
        ),
    },
  ];

  const TILE_ICON: Record<string, IconName> = {
    Clusters: "boxes",
    "Exposed Services": "route",
    "Machine credentials": "key",
  };

  return (
    <div className="flex flex-col gap-3.5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <PageHeader
            title="Kubernetes"
            subtitle="Clusters, exposed Services and the VIPs clients reach them at. A Service is reached by name over the tunnel, never by its ClusterIP."
          />
        </div>
        {section === "clusters" && raw && gate.canManage && raw.sites.length > 0 && (
          <Button onClick={() => setRegistering(true)}>Register cluster</Button>
        )}
      </div>

      <nav aria-label="Kubernetes workspace" className="flex flex-wrap gap-1 border-b border-line pb-2">
        {([
          ["clusters", "Clusters"],
          ["services", "Exposed services"],
          ["operations", "Setup & diagnostics"],
        ] as const).map(([id, label]) => (
          <Button
            key={id}
            size="sm"
            variant="ghost"
            aria-current={section === id ? "page" : undefined}
            className={section === id ? "bg-white/10 text-ink-heading" : ""}
            onClick={() => updateQuery({ section: id, cluster: id === "operations" ? null : selectedId })}
          >
            {label}
          </Button>
        ))}
      </nav>

      {loadError && <LoadRetry error={loadError} onRetry={reload} />}
      {!loadError && raw === null && (
        <p className="text-cell text-ink-faint">Loading…</p>
      )}

      {raw && !loadError && cards.length === 0 && (
        // ⛔ N=0 IS ONE EMPTY STATE, NOT EIGHT. Every panel below would render its own emptiness, and eight
        // simultaneous empty panels is the reassuring-empty defect multiplied. It names the precondition.
        <EmptyState>
          {raw.sites.length === 0
            ? "Register a site with a gateway first: a cluster is fronted by one site's gateway, and without one no VIP can be programmed."
            : "No clusters registered. Registering one reserves a VIP range and a DNS zone, and then in-cluster Services can be exposed by name."}
        </EmptyState>
      )}

      {raw && !loadError && cards.length > 0 && (
        <>
          {section === "clusters" && <div className="flex flex-wrap items-center justify-between gap-3">
            <label className="min-w-[14rem] flex-1 text-sm text-ink-tertiary">
              Search clusters
              <Input value={query} onChange={(event) => updateQuery({ q: event.target.value })} placeholder="Cluster name" />
            </label>
            <span className="text-micro text-ink-faint">{visibleCards.length} matching cluster{visibleCards.length === 1 ? "" : "s"}</span>
          </div>}
          {section === "clusters" && <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {tiles.slice(0, 2).map((t) => (
              <li
                key={t.label}
                className="rounded-card border border-line bg-surface px-3.5 py-3"
              >
                <p className="flex items-center gap-2 text-micro uppercase tracking-wide text-ink-tertiary">
                  <Icon name={TILE_ICON[t.label] ?? "boxes"} size={13} />
                  {t.label}
                </p>
                <p className="mt-1 text-[22px] font-semibold text-ink-heading">
                  {/* ⛔ "n/a", NOT AN EM-DASH. A null never renders 0 — "we could not look" is a different
                      fact from "there are none" — but the ABSENT MARKER ITSELF was the banned glyph.
                      S14.5 already resolved this exact collision on hubsetview: an em-dash "is not READ as
                      'we have no value' by anyone who has not been told that it means that. It reads as a
                      dash, as a minus, or as NOTHING AT ALL to a screen reader."
                      This site carried a WRITTEN EXEMPTION for the case that law had already decided — and
                      that law's closing line names the reflex verbatim: "the reflex in that moment is to
                      claim an exemption for the older rule." */}
                  {t.value === null ? "n/a" : t.value}
                </p>
                <p className="text-micro text-ink-faint">{t.hint}</p>
              </li>
            ))}
          </ul>}

          {section === "clusters" && <Panel title={`Clusters (${visibleCards.length})`}>
            <DataTable
              caption="Registered Kubernetes clusters"
              columns={clusterColumns}
              rows={visibleCards}
              rowKey={(c: ClusterCard) => c.id}
              empty="No clusters registered."
              failed={false}
            />
          </Panel>}

          {section === "clusters" && selected && (
            <div ref={selectedClusterRef} tabIndex={-1} aria-label={`Selected cluster: ${selected.name}`}>
            <Panel title={selected.name}>
              <div className="grid gap-3 text-cell text-ink-tertiary sm:grid-cols-3">
                <p><strong className="text-ink-body">Site</strong><br />{siteName.get(selected.siteId) ?? "Site record unavailable"}</p>
                <p><strong className="text-ink-body">Services</strong><br />{selected.services.length} exposed</p>
                <p><strong className="text-ink-body">Connector</strong><br />{selected.connectorNodeId ? (nodeName.get(selected.connectorNodeId) ?? "Unavailable") : "Not selected"}</p>
              </div>
              <p className="mt-3 text-micro text-ink-faint">Connector configuration is control-plane state, not workload readiness. Use the operator and workload telemetry for endpoint readiness.</p>
              {gate.canManage && !objectControls(selected.managedByOperator).withheld && <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="ghost" onClick={() => setConnectorFor(selected)}>{selected.connectorNodeId === null ? "Select connector" : "Change connector"}</Button>
                <Button size="sm" variant="ghost" onClick={() => setExposeFor(selected)}>Expose service</Button>
              </div>}
              {gate.canManage && !objectControls(selected.managedByOperator).withheld && <div className="mt-4 flex items-center justify-between gap-3 border-t border-danger/30 pt-3">
                <span className="text-micro text-ink-faint">Deregistering permanently removes this cluster and its exposed Services. Recovery is to register it again.</span>
                <Button size="sm" variant="danger" onClick={() => setDeregisterFor(selected)}>Deregister</Button>
              </div>}
            </Panel></div>
          )}


          {section === "services" && <div className="flex flex-wrap items-end justify-between gap-3">
            <Field label="Cluster filter">
              <Select value={selectedId ?? ""} onChange={(event) => updateQuery({ cluster: event.target.value || null })} width="auto">
                <option value="">All clusters</option>
                {cards.map((card) => <option key={card.id} value={card.id}>{card.name}</option>)}
              </Select>
            </Field>
            {gate.canManage && selected && !objectControls(selected.managedByOperator).withheld && <Button onClick={() => setExposeFor(selected)}>Expose service</Button>}
          </div>}

          <div className={section === "operations" ? "grid grid-cols-1 gap-3" : "grid grid-cols-1 items-start gap-3"}>
            <div className="flex min-w-0 flex-col gap-3">
              {section === "services" && <Panel title={`Exposed Services (${serviceRows.length})`}>
                <DataTable
                  caption="Exposed Kubernetes Services"
                  columns={serviceColumns}
                  rows={selectedId ? serviceRows.filter((row) => row.clusterId === selectedId) : serviceRows}
                  rowKey={(r: SvcRow) => r.id}
                  empty="No Services exposed yet. Exposing one allocates a VIP and gives it a name clients can reach."
                  failed={false}
                />
              </Panel>}

              {section === "operations" && <Panel title="How Kubernetes access works">
                {/* The handoff's HORIZONTAL flow, not a numbered list: the point is that these are four hops in
                    sequence, and a vertical list reads as four independent facts. */}
                <div className="flex flex-wrap items-center gap-1.5 text-micro">
                  {[
                    "device",
                    "DNS VIP answers the FQDN",
                    "the Service's VIP",
                    "gateway DNATs to a READY POD endpoint",
                    "pod endpoint",
                  ].map((step, i, all) => (
                    <span key={step} className="flex items-center gap-1.5">
                      <span className="rounded-input border border-line bg-surface-inset px-2 py-1 font-mono text-ink-body">
                        {step}
                      </span>
                      {i < all.length - 1 && (
                        <span aria-hidden className="text-ink-faint">
                          &rarr;
                        </span>
                      )}
                    </span>
                  ))}
                </div>
                <p className="mt-2 text-micro text-ink-tertiary">
                  <strong className="text-ink-body">
                    Not a ClusterIP DNAT.
                  </strong>{" "}
                  netfilter applies one destination NAT per prerouting pass, so
                  kube-proxy&rsquo;s ClusterIP rule would be a no-op after ours
                  and the packet would die addressed to the ClusterIP. The
                  gateway targets a ready pod directly, fed by an EndpointSlice
                  watch, and fails closed on every fault.
                </p>
                <p className="text-micro text-ink-faint">
                  <strong className="text-ink-body">
                    Enforcement keys the pre-DNAT VIP.
                  </strong>{" "}
                  The grant matches the original destination, so a bare
                  destination match cannot miss the post-DNAT pod IP and a broad
                  grant cannot slip past.
                </p>
              </Panel>}
            </div>

            {section === "operations" && <div className="flex min-w-0 flex-col gap-3">
              <Panel title="Operator and connector setup">
                {/* ⛔ NAMED AS COPY, NOT A CAPABILITY. This screen installs nothing. */}
                <p className="text-micro text-ink-tertiary">
                  Reference only. Run these yourself; this screen does not
                  install anything.
                </p>
                <pre className="overflow-x-auto rounded-input border border-line bg-surface-inset p-2.5 text-micro text-ink-body">
                  {`helm install gw tunnex/tunnex-gateway \\
  --set joinToken.secretRef=tunnex-join
helm install op tunnex/operator \\
  --set machineToken.secretRef=tunnex-machine`}
                </pre>
                <p className="text-micro text-ink-faint">
                  Both secrets are one-time ceremonies you create, never chart
                  values. The gateway pod runs with a read-only role on services
                  and endpointslices: it cannot read Secrets, write, or
                  escalate.
                </p>
              </Panel>

              <Panel title="Current control-plane visibility">
                <ul className="flex flex-col gap-1.5 text-micro text-ink-tertiary">
                  <li>
                    <strong className="text-ink-body">
                      The GitOps CR panel.
                    </strong>{" "}
                    The operator and its CRs are built and shipping; what does
                    not exist is any API reporting their status here. Reconcile
                    time, per-kind ready counts, refused grants and the
                    operator&rsquo;s version are not served, so every value on
                    that panel would be invented.{" "}
                    <strong className="text-ink-body">
                      What IS served is ownership
                    </strong>{" "}
                    — which is why the withheld control above is real.
                  </li>
                  <li>
                    <strong className="text-ink-body">
                      A per-Service ready state.
                    </strong>{" "}
                    The agent does watch endpoints, so readiness is observed; it
                    is not reported per Service. The node-level view is on
                    Gateways.
                  </li>
                  <li>
                    <strong className="text-ink-body">A state column.</strong>{" "}
                    The API returns live Services only, so the column would
                    carry one value forever. A grant pointing at a removed
                    Service is flagged on{" "}
                    <strong className="text-ink-body">Access Policies</strong>,
                    which is where that fact is served.
                  </li>
                </ul>
              </Panel>
            </div>}
          </div>
        </>
      )}

      {registering && orgId && raw && (
        <RegisterClusterModal
          orgId={orgId}
          sites={raw.sites}
          nodes={raw.nodes}
          onClose={() => setRegistering(false)}
          onDone={reload}
        />
      )}
      {exposeFor && orgId && (
        <ExposeServiceModal
          orgId={orgId}
          clusterId={exposeFor.id}
          onClose={() => setExposeFor(null)}
          onDone={reload}
        />
      )}
      {connectorFor && orgId && raw && (
        <SetConnectorModal
          orgId={orgId}
          cluster={connectorFor}
          nodes={raw.nodes}
          onClose={() => setConnectorFor(null)}
          onDone={reload}
        />
      )}
      {deregisterFor && orgId && (
        <DeregisterClusterModal
          orgId={orgId}
          card={deregisterFor}
          onClose={() => setDeregisterFor(null)}
          onDone={reload}
        />
      )}
      {unexposeFor && orgId && (
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

function RegisterClusterModal({
  orgId,
  sites,
  nodes,
  onClose,
  onDone,
}: {
  orgId: string;
  sites: Site[];
  nodes: Node[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [siteId, setSiteId] = useState(sites[0]?.id ?? "");
  const connectors = nodes.filter(
    (node) => node.status === "active" && node.site_id === siteId && node.endpoint,
  );
  const [connectorNodeId, setConnectorNodeId] = useState(connectors[0]?.id ?? "");
  useEffect(() => {
    setConnectorNodeId(connectors[0]?.id ?? "");
  }, [siteId, nodes]);
  const [name, setName] = useState("");
  const [vipRange, setVipRange] = useState("");
  const [serviceCidr, setServiceCidr] = useState("10.96.0.0/12");
  const [dnsZone, setDnsZone] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/k8s/clusters",
      {
        params: { path: { orgId } },
        body: {
          site_id: siteId,
          connector_node_id: connectorNodeId,
          name,
          vip_range: vipRange,
          service_cidr: serviceCidr,
          dns_zone: dnsZone,
        },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not register the cluster."));
    onClose();
    onDone();
  }

  return (
    <Modal
      title="Register a Kubernetes cluster"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={
              busy ||
              !siteId ||
              !connectorNodeId ||
              name.trim() === "" ||
              vipRange.trim() === "" ||
              dnsZone.trim() === ""
            }
          >
            Register
          </Button>
        </>
      }
    >
      <Field label="Fronting Site">
        <Select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="In-cluster connector node">
        <Select value={connectorNodeId} onChange={(e) => setConnectorNodeId(e.target.value)}>
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
        <p className="mt-1 text-micro text-ink-faint">
          This node watches ready Kubernetes endpoints and receives only the private service handoff. It is not the client-facing edge gateway.
        </p>
      </Field>
      <Field label="Cluster name (a DNS label: it becomes part of every Service hostname)">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. prod"
          autoFocus
        />
      </Field>
      <Field label="Synthetic VIP range (CIDR, disjoint from your pool, your sites, and other clusters)">
        <Input
          value={vipRange}
          onChange={(e) => setVipRange(e.target.value)}
          placeholder="e.g. 100.64.0.0/16"
        />
      </Field>
      <Field label="Kubernetes Service CIDR (where the cluster's ClusterIPs live)">
        <Input
          value={serviceCidr}
          onChange={(e) => setServiceCidr(e.target.value)}
          placeholder="e.g. 10.96.0.0/12"
        />
      </Field>
      <Field label="DNS zone (your domain suffix; need not be publicly registered)">
        <Input
          value={dnsZone}
          onChange={(e) => setDnsZone(e.target.value)}
          placeholder="e.g. k8s.acme.com"
        />
      </Field>
      <ErrorText>{err}</ErrorText>
    </Modal>
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
      node.status === "active" && node.site_id === cluster.siteId && node.endpoint,
  );
  const [connectorNodeId, setConnectorNodeId] = useState(
    cluster.connectorNodeId ?? connectors[0]?.id ?? "",
  );
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setErr(null);
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/connector",
      {
        params: { path: { orgId, clusterId: cluster.id } },
        body: { node_id: connectorNodeId },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not set the in-cluster connector."));
    onClose();
    onDone();
  }

  return (
    <Modal
      title={`Set connector for ${cluster.name}`}
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={busy || !connectorNodeId}>
            Save connector
          </Button>
        </>
      }
    >
      <p className="mb-3 text-cell text-ink-tertiary">
        The connector is the selected in-cluster Tunnex node. It resolves ready pod endpoints and receives the encrypted service handoff from the existing site edge gateway.
      </p>
      <Field label="In-cluster connector node">
        <Select value={connectorNodeId} onChange={(e) => setConnectorNodeId(e.target.value)}>
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
    </Modal>
  );
}

function ExposeServiceModal({
  orgId,
  clusterId,
  onClose,
  onDone,
}: {
  orgId: string;
  clusterId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [name, setName] = useState("");
  const [namespace, setNamespace] = useState("default");
  // WF-K5 M8/M9: an exposure needs a SINGLE specific port + a protocol — the gateway DNATs VIP:port ->
  // podIP:targetPort, so all-ports/ranges are refused server-side. The form must offer the port the refusal
  // teaches the user to supply (offering the refusal without the field would make the dashboard structurally
  // unable to produce a valid exposure). Protocol is tcp/udp (no "any" — a ported DNAT needs an L4 proto).
  const [port, setPort] = useState("");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Client-side UX validation ONLY — the server's ExposeService is the authoritative validator (one-validator):
  // its typed refusals (service_port_required / service_port_range_unsupported) render verbatim via apiErrorMessage.
  const portNum = Number(port);
  const portValid =
    Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535;

  async function submit() {
    setBusy(true);
    setErr(null);
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
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not expose the Service."));
    onClose();
    onDone();
  }

  return (
    <Modal
      title="Expose a Service"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={submit}
            disabled={
              busy ||
              name.trim() === "" ||
              namespace.trim() === "" ||
              !portValid
            }
          >
            Expose
          </Button>
        </>
      }
    >
      <Field label="Service name">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. api"
          autoFocus
        />
      </Field>
      <Field label="Namespace">
        <Input
          value={namespace}
          onChange={(e) => setNamespace(e.target.value)}
          placeholder="e.g. prod"
        />
      </Field>
      <Field label="Port">
        <Input
          type="number"
          min={1}
          max={65535}
          value={port}
          onChange={(e) => setPort(e.target.value)}
          placeholder="the Service port clients dial, e.g. 80"
        />
        {port !== "" && !portValid && (
          <p className="mt-1 text-xs text-amber-400">
            Enter a single port between 1 and 65535.
          </p>
        )}
      </Field>
      <Field label="Protocol">
        <Select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value as "tcp" | "udp")}
        >
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
        </Select>
      </Field>
      <ErrorText>{err}</ErrorText>
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
    setBusy(true);
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/k8s/services/{serviceId}",
      { params: { path: { orgId, serviceId: service.id } } },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not unexpose the Service."));
    onClose();
    onDone();
  }

  return (
    <Modal
      title={`Unexpose ${service.name}`}
      onDismiss={onClose}
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
      <div className="flex flex-col gap-2 text-sm text-ink-tertiary">
        <p>
          Unexpose <span className="font-medium text-ink-heading">{service.name}</span>{" "}
          at <span className="font-mono text-ink-body">{service.fqdn}</span> ({" "}
          <span className="font-mono text-ink-body">{service.vip}</span>). Its VIP and DNS
          answer withdraw on the next compile.
        </p>
        <p>
          This is not an undo. Immutable Agent Policy Template references and live Agent
          Access requests may refuse the change. If it succeeds, recovery is to expose the
          Service again; that creates a new Service identity.
        </p>
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
    setBusy(true);
    setErr(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}",
      {
        params: { path: { orgId, clusterId: card.id } },
      },
    );
    setBusy(false);
    if (error)
      return setErr(
        apiErrorMessage(error, "Could not deregister the cluster."),
      );
    onClose();
    onDone();
  }

  return (
    <Modal
      title={`Deregister ${card.name}`}
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={submit}
            disabled={busy || typed !== card.name}
          >
            Deregister
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-2 text-sm text-ink-tertiary">
        <p>
          This deletes the cluster, its exposed Services, and dependent policy
          rules. Its VIP range, reserved DNS VIP, and DNS zone are freed for
          reuse. Live Agent Access requests may refuse this change.
        </p>
        <p>
          There is no rollback or restore. Recovery requires registering the
          cluster again, choosing an in-cluster connector node, exposing its
          Services again, and recreating grants.
        </p>
        <p>
          Type the cluster name <span className="font-mono text-ink-body">{card.name}</span>{" "}
          to confirm.
        </p>
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
