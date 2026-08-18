import { useCallback, useEffect, useMemo, useState } from "react";
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
  type AgentPolicyTemplateDestinationImpact,
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
  clusterReachability,
  k8sGate,
  managedEditWarning,
  objectControls,
  statTiles,
  type ClusterCard,
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

  const reload = useCallback(async () => {
    setLoadError(null);
    setRaw(null);
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
  const [rowErr, setRowErr] = useState<string | null>(null);

  async function unexpose(service: Pick<K8sService, "id" | "name">) {
    setRowErr(null);
    const impact = (await loadOne(() =>
      api.GET(
        "/api/v1/organizations/{orgId}/agent-policy-template-destination-impact",
        {
          params: {
            path: { orgId: orgId ?? "" },
            query: {
              destination_kind: "k8s_service",
              destination_id: service.id,
            },
          },
        },
      ),
    )) as Loaded<AgentPolicyTemplateDestinationImpact>;
    if (!impact.ok)
      return setRowErr(
        "Could not read immutable template impact; the Service was not unexposed.",
      );
    if (impact.data.version_count > 0)
      return setRowErr(
        `${impact.data.version_count} immutable agent policy template ${impact.data.version_count === 1 ? "version references" : "versions reference"} ${service.name}; unexpose is blocked.`,
      );
    if (
      !window.confirm(
        `Unexpose ${service.name}? No immutable agent policy template version references it. Its VIP and DNS answer will be withdrawn.`,
      )
    )
      return;
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/k8s/services/{serviceId}",
      { params: { path: { orgId: orgId ?? "", serviceId: service.id } } },
    );
    if (error)
      return setRowErr(
        apiErrorMessage(error, "Could not unexpose the Service."),
      );
    reload();
  }

  // Every exposed Service, flattened WITH its cluster, so the table is one scannable list rather than a list
  // per card. §6.2: the SERVICE list is the scaling surface, so it gets the table; the cluster list does not.
  const serviceRows = useMemo(
    () =>
      cards.flatMap((c) =>
        c.services.map((sv) => ({
          ...sv,
          clusterName: c.name,
          reachable: clusterReachability({ connectorNodeId: c.connectorNodeId, gateways })
            .reachable,
        })),
      ),
    [cards, gateways],
  );

  const clusterColumns = [
    {
      key: "cluster",
      header: "Cluster",
      cell: (c: ClusterCard) => (
        <span className="flex flex-col gap-0.5">
          <span className="flex items-center gap-2">
            <span className="font-mono text-ink-primary">{c.name}</span>
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
        const reach = clusterReachability({ connectorNodeId: c.connectorNodeId, gateways });
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
            {!reach.reachable && reach.why !== null && (
              <span className="text-micro text-warn">{reach.why}</span>
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
      header: "Owner",
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
            <Button size="sm" variant="ghost" onClick={() => setExposeFor(c)}>
              Expose Service
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setConnectorFor(c)}>
              {c.connectorNodeId === null ? "Select connector" : "Change connector"}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setDeregisterFor(c)}
            >
              Deregister
            </Button>
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
      header: "Owner",
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
          <Button size="sm" variant="ghost" onClick={() => unexpose(r)}>
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
        {raw && gate.canManage && raw.sites.length > 0 && (
          <Button onClick={() => setRegistering(true)}>Register cluster</Button>
        )}
      </div>

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
          <ul className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {tiles.map((t) => (
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
          </ul>

          <Panel title={`Clusters (${cards.length})`}>
            <DataTable
              caption="Registered Kubernetes clusters"
              columns={clusterColumns}
              rows={cards}
              rowKey={(c: ClusterCard) => c.id}
              empty="No clusters registered."
              failed={false}
            />
          </Panel>

          <ErrorText>{rowErr}</ErrorText>

          <div className="grid grid-cols-1 items-start gap-3 lg:grid-cols-[8fr_4fr]">
            <div className="flex min-w-0 flex-col gap-3">
              <Panel title={`Exposed Services (${serviceRows.length})`}>
                <DataTable
                  caption="Exposed Kubernetes Services"
                  columns={serviceColumns}
                  rows={serviceRows}
                  rowKey={(r: SvcRow) => r.id}
                  empty="No Services exposed yet. Exposing one allocates a VIP and gives it a name clients can reach."
                  failed={false}
                />
              </Panel>

              <Panel title="How a client reaches a Service">
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
              </Panel>
            </div>

            <div className="flex min-w-0 flex-col gap-3">
              <Panel title="Installing the operator">
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

              <Panel title="Not shown, and why">
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
            </div>
          </div>

          <Panel title="Refusals this surface reports verbatim">
            <p className="text-micro text-ink-faint">
              Disjointness is an org-wide fact, so the control plane owns it,
              not a cluster.
            </p>
            <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {[
                [
                  "409 vip_range_overlap",
                  "A cluster's VIP range must be disjoint from the device pool, every site subnet, and other clusters' ranges.",
                ],
                [
                  "409 vip_range_exhausted",
                  "No address left to allocate. Unexposing frees a VIP for immediate reuse.",
                ],
                [
                  "409 service_exists",
                  "That namespace and name pair is already exposed: one stable identity per Service.",
                ],
              ].map(([code, why]) => (
                <div key={code}>
                  <dt className="font-mono text-micro text-ink-body">{code}</dt>
                  <dd className="text-micro text-ink-tertiary">{why}</dd>
                </div>
              ))}
            </dl>
          </Panel>
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
      <Field label="Fronting site gateway">
        <Select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="In-cluster Tunnex connector">
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
      <Field label="In-cluster Tunnex connector">
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
      <p className="text-sm text-slate-400">
        This removes the cluster, unexposes all {card.services.length} of its
        Services, and deletes any rule that reached one. Its VIP range and DNS
        zone are freed for reuse. Type the cluster name{" "}
        <span className="font-mono text-slate-300">{card.name}</span> to
        confirm.
      </p>
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
