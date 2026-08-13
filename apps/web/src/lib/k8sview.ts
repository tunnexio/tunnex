import type { K8sCluster, K8sService, Role } from "./api";
import { can } from "./rbac";

// k8sview — PURE, electron-free view-models for the Kubernetes page (S10.3). The page is a thin render over
// these. K8s cluster/Service exposure is CONNECTIVITY, so unlike sites it is CORE (all editions) — there is
// NO enterprise gate here; only the GRANT that reaches a Service (Access page) is enterprise. Every rendered
// field traces to a wire value (a real K8sCluster/K8sService property); the FQDN is READ from the server
// (service.fqdn — "copy, don't construct"), never assembled in the client.

// ── RBAC gate ──────────────────────────────────────────────────────────────────────
// canView: any member reads the connectivity surface (org:view — the member-read gate, like ListSites).
// canManage: register/expose/remove need k8s:manage + a verified email (mirrors the server). No edition bit.
export interface K8sGate {
  canView: boolean;
  canManage: boolean;
}

export function k8sGate(input: {
  role: Role | undefined;
  emailVerified: boolean;
}): K8sGate {
  return {
    canView: can(input.role, "org:view"),
    canManage: input.emailVerified && can(input.role, "k8s:manage"),
  };
}

// ── cluster + service assembly (the wire-truth join) ─────────────────────────────────
export interface ServiceRow {
  id: string;
  name: string;
  namespace: string;
  protocol: K8sService["protocol"];
  ports: string; // "any" | "80" | "8000–8100" — a display projection of the wire port_low/port_high
  vip: string;
  fqdn: string; // READ from the server (never constructed here)
  managedByOperator: boolean; // S10.2 D2 cond 1: GitOps-managed → badge + warn (edit the CR, not here)
}

export interface ClusterCard {
  id: string;
  siteId: string;
  connectorNodeId: string | null;
  name: string;
  vipRange: string;
  serviceCidr: string;
  dnsZone: string;
  dnsVip: string | null;
  services: ServiceRow[]; // the cluster's LIVE exposed Services
  managedByOperator: boolean; // S10.2 D2 cond 1: GitOps-managed → badge + warn
}

// S10.2 D2 cond 1 — the ownership surface strings (kept here so they're covered by the pure view-model
// tests). A managed object shows MANAGED_BADGE and its destructive dashboard control is withheld, replaced by
// managedEditWarning — surfacing the ownership AT THE POINT OF EDITING rather than silently reverting the edit
// on the next reconcile (the worst UX the ruling calls out).
export const MANAGED_BADGE = "Managed by GitOps";
export function managedEditWarning(kind: "cluster" | "Service"): string {
  return `This ${kind} is managed by the GitOps operator — edit its CR, not the dashboard.`;
}

// objectControls (M3) is the PURE, unit-pinned withhold decision for a cluster/Service: `withheld` true means
// the dashboard MUST NOT offer the destructive control (Deregister/Unexpose) — edit the CR instead. Extracted
// out of inline JSX so a refactor that re-exposes the control fails a test, not just review (the D2 ruling's
// worst case: an admin's dashboard edit silently reverted on the next reconcile).
export function objectControls(managedByOperator: boolean): {
  withheld: boolean;
} {
  return { withheld: managedByOperator };
}

// portLabel projects the wire port_low/port_high onto a human range. null/absent both = "any".
export function portLabel(
  portLow: number | null | undefined,
  portHigh: number | null | undefined,
): string {
  if (portLow == null && portHigh == null) return "any";
  if (portLow != null && (portHigh == null || portHigh === portLow))
    return String(portLow);
  if (portLow == null) return String(portHigh);
  return `${portLow}–${portHigh}`; // en-dash range
}

function serviceRow(s: K8sService): ServiceRow {
  return {
    id: s.id,
    name: s.name,
    namespace: s.namespace,
    protocol: s.protocol,
    ports: portLabel(s.port_low, s.port_high),
    vip: s.vip,
    fqdn: s.fqdn,
    managedByOperator: s.managed_by_operator,
  };
}

// assembleClusters joins the clusters with their org-wide Services (grouped by cluster_id). PURE — the only
// computation is the group-by + the port projection.
export function assembleClusters(
  clusters: K8sCluster[],
  services: K8sService[],
): ClusterCard[] {
  const byCluster: Record<string, ServiceRow[]> = {};
  for (const s of services) {
    (byCluster[s.cluster_id] ??= []).push(serviceRow(s));
  }
  return clusters.map((c) => ({
    id: c.id,
    siteId: c.site_id,
    connectorNodeId: c.connector_node_id ?? null,
    name: c.name,
    vipRange: c.vip_range,
    serviceCidr: c.service_cidr,
    dnsZone: c.dns_zone,
    dnsVip: c.dns_vip ?? null,
    services: byCluster[c.id] ?? [],
    managedByOperator: c.managed_by_operator,
  }));
}

// serviceFqdnById is the grant-picker's label source: id -> fqdn for a live Service (or null if absent).
export function serviceFqdnById(
  services: K8sService[],
  id: string,
): string | null {
  return services.find((s) => s.id === id)?.fqdn ?? null;
}

// ── S14.8 SECTION PASS ──────────────────────────────────────────────────────────────────────────────────
//
// ⛔ D3's `VANISHED` ROW CANNOT BE BUILT, AND THE REASON IS ONE LINE OF SQL.
//
// The design shows a dimmed fourth row: `legacy-api… — "unexposed — VIP already reusable"`. D3 ruled it in.
// But the only org-wide Service list the API serves is `ListActiveK8sServicesForOrg`:
//
//     WHERE s.org_id = $1 AND s.deleted_at IS NULL
//
// A soft-deleted Service is EXCLUDED FROM THE RESPONSE. There is no vanished row to dim — the client is never
// told one existed.
//
// SO `STATE` HAS EXACTLY ONE VALUE, AND THAT IS THE ROUTED-RANGES `STATUS` SITUATION VERBATIM: a column with
// one value in every row of every org is not information, it teaches the reader that another value is
// reachable here. CUT AS A CONSTANT COLUMN, same disposition, same reason, recorded rather than re-argued.
//
// (`dst_k8s_service_vanished` DOES exist — on `PolicyRule`. A grant pointing at a gone Service is visible on
// ACCESS POLICIES, not here. That is where the vanished concept is actually served.)

/** A stat tile. `absent` tiles render their reason instead of a number — never a zero standing in for unknown. */
export interface StatTile {
  label: string;
  value: number | null;
  hint: string;
}

/**
 * statTiles — three, not the handoff's four.
 *
 * ⛔ `Operator v0.5.0` IS CUT: `operator_version` appears NOWHERE in the spec or the Go tree. A tile whose
 * value would be invented is the render-floor violation, and a version number is the most quietly
 * authoritative thing a screen can invent.
 */
export function statTiles(
  clusters: ClusterCard[],
  machineCredentialCount: number | null,
): StatTile[] {
  const services = clusters.reduce((n, c) => n + c.services.length, 0);
  return [
    {
      label: "Clusters",
      value: clusters.length,
      hint: clusters.map((c) => c.name).join(" · ") || "none registered",
    },
    {
      label: "Exposed Services",
      value: services,
      hint: "reached by name at a synthetic VIP",
    },
    {
      // null when the read failed — a zero here would claim "no operator identity exists", which is a
      // different fact from "we could not look".
      label: "Machine credentials",
      value: machineCredentialCount,
      hint:
        machineCredentialCount === null
          ? "could not read"
          : "the GitOps operator's own org identity",
    },
  ];
}

/**
 * ⛔ D9 — REACHABILITY, NOT LIVENESS. A Service must not read as reachable when its fronting gateway reports
 * no endpoint view, because no VIP can be DNAT-programmed in that state.
 *
 * The predicate is deliberately NOT called "cluster down": `k8s_endpoints_unavailable` is true for an
 * unreachable cluster, an RBAC denial AND a watch that has not synced (measured at the producer,
 * `dnat_linux.go:174`). All three mean unreachable; only one means the cluster is gone. Naming the cause
 * would assert something we cannot know.
 *
 * SCOPED BY A3 AND NOT WAITING ON IT: the site→cluster mapping is 1:1 in the shipped deployment model but not
 * enforced by the schema, so this reads "a gateway fronting this cluster's site" — the honest claim available
 * from served fields today. If A3 lands, it narrows to the cluster by construction.
 *
 * ⚠ UNVERIFIABLE IN THE REVIEW STACK: no agent here watches the cluster, so the kind never fires. Substitute =
 * these unit tests; TRIGGER for the wire proof = the first in-cluster agent watching this cluster (S10.3's
 * hostNetwork helm deploy).
 */
export function clusterReachability(input: {
  connectorNodeId: string | null;
  gateways: Array<{
    id: string;
    endpointsUnavailable: boolean;
    revoked: boolean;
  }>;
}): { reachable: boolean; why: string | null } {
  if (input.connectorNodeId === null)
    return {
      reachable: false,
      why: "no in-cluster connector is selected, so Service VIPs are not programmed",
    };
  const connector = input.gateways.find((g) => g.id === input.connectorNodeId);
  if (connector === undefined || connector.revoked)
    return {
      reachable: false,
      why: "the selected in-cluster connector is unavailable, so Service VIPs are not programmed",
    };
  if (connector.endpointsUnavailable)
    return {
      reachable: false,
      why: "the selected in-cluster connector has no endpoint view, so Service VIPs are not programmed",
    };
  return { reachable: true, why: null };
}

/** Recessive styling for an unreachable cluster's rows: recession is the honest encoding for a degraded state. */
export function serviceRowClass(reachable: boolean): string {
  return reachable ? "" : "opacity-60";
}

// ── THE OVERVIEW DONUT ──────────────────────────────────────────────────────────────────────────────────
//
// ⛔ WHAT A DONUT NEEDS IS PARTS OF A WHOLE, AND "1 cluster / 3 services" IS NOT THAT. Two unrelated counts
// drawn as a ring would be a picture pretending to be a proportion.
//
// The honest proportion here is EXPOSED SERVICES BY CLUSTER: one total (everything reachable by name), split
// by which cluster carries it. That answers a real question — where is the exposure concentrated — and it is
// the split that gets MORE useful as an org grows, which is the opposite of the address-space bar.
//
// AT N=1 IT IS ONE FULL RING, AND THAT IS THE FACT, not a degenerate case: one cluster carries everything.
// The centre total and the legend rows carry the numbers as TEXT regardless, so the ring is never the only
// path to the value.
export function serviceSlices(clusters: ClusterCard[]): Array<{
  label: string;
  value: number;
  tone: "ok" | "warn" | "danger" | "neutral";
}> {
  // Tones cycle through the neutral-ish set rather than encoding health: a cluster is not "warn" for owning
  // more Services. Colour here is IDENTITY, not status — using ok/danger would imply a verdict.
  const TONES = ["ok", "neutral", "warn", "danger"] as const;
  return clusters
    .filter((c) => c.services.length > 0)
    .map((c, i) => ({
      label: c.name,
      value: c.services.length,
      tone: TONES[i % TONES.length],
    }));
}
