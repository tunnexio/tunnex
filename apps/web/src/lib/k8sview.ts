import type { components } from "@tunnex/shared";
import type { K8sCluster, K8sService, Role } from "./api";
import { can } from "./rbac";

// k8sview — PURE, electron-free view-models for the Kubernetes page. K8s cluster/Service exposure is a
// Community core connectivity surface; named capabilities remain server-authoritative. Every rendered
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
  namespaceRuleId: string | null; // K8N-4: set when a namespace rule created this exposure
}

export interface ClusterCard {
  id: string;
  siteId: string;
  connectorNodeId: string | null;
  provider: K8sCluster["provider"];
  platform: K8sCluster["platform"];
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
  return `This ${kind} is managed by the GitOps operator, edit its CR, not the dashboard.`;
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
    namespaceRuleId: s.namespace_rule_id ?? null,
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
    provider: c.provider,
    platform: c.platform,
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
 * Connector configuration is not Service readiness. The server currently reports whether a selected connector
 * is available to receive desired state, not whether a workload endpoint is live.
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
export function clusterConnectorState(input: {
  connectorNodeId: string | null;
  gateways: Array<{
    id: string;
    endpointsUnavailable: boolean;
    revoked: boolean;
  }>;
}): { configured: boolean; reachable: boolean; why: string | null } {
  if (input.connectorNodeId === null)
    return {
      configured: false, reachable: false,
      why: "no in-cluster connector is selected, so Service VIPs are not programmed",
    };
  const connector = input.gateways.find((g) => g.id === input.connectorNodeId);
  if (connector === undefined || connector.revoked)
    return {
      configured: false, reachable: false,
      why: "the selected in-cluster connector is unavailable, so Service VIPs are not programmed",
    };
  if (connector.endpointsUnavailable)
    return {
      configured: false, reachable: false,
      why: "the selected in-cluster connector has no endpoint view, so Service VIPs are not programmed",
    };
  return { configured: true, reachable: true, why: null };
}

/** @deprecated Use clusterConnectorState: this reports configuration availability, never workload readiness. */
export const clusterReachability = clusterConnectorState;

/** Recessive styling for an unreachable cluster's rows: recession is the honest encoding for a degraded state. */
export function serviceRowClass(configured: boolean): string {
  return configured ? "" : "opacity-60";
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

// ── K8N-4: namespace rules ("expose every Service in this namespace") ───────────────────────────────────
//
// A rule gives every Service of ONE namespace an address and a name, now and as Services are added. It
// never grants access. The server decides everything; what is here is the wording, the withhold decision
// and the "what will happen" arithmetic shown BEFORE the administrator confirms.

export type K8sNamespaceRule = components["schemas"]["K8sNamespaceRule"];
type InventoryService = components["schemas"]["K8sInventoryService"];

export const NAMESPACE_RULE_BADGE = "Namespace rule";

/** Who owns an exposure row. A row is the operator's, a rule's, or was made by hand in the dashboard. */
export function serviceOwner(row: Pick<ServiceRow, "managedByOperator" | "namespaceRuleId" | "namespace">): {
  label: "GitOps" | typeof NAMESPACE_RULE_BADGE | "Dashboard";
  /** true = the dashboard must not offer Unexpose for this row. */
  withheld: boolean;
  why: string | null;
} {
  if (row.managedByOperator)
    return { label: "GitOps", withheld: true, why: managedEditWarning("Service") };
  if (row.namespaceRuleId !== null)
    return {
      label: NAMESPACE_RULE_BADGE,
      withheld: true,
      why: `This Service is exposed by the namespace rule for ${row.namespace}. Exclude it from the rule, or remove the rule, to unexpose it; removing it here would be undone on the gateway's next report.`,
    };
  return { label: "Dashboard", withheld: false, why: null };
}

/**
 * Mirrors the server's refusal so the reason shows while typing. The server (and the database) still
 * decide; a namespace this lets through can be refused there.
 */
export function namespaceIneligibleReason(namespace: string): string | null {
  const ns = namespace.trim();
  if (ns === "") return "Choose one namespace.";
  if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(ns) || ns.length > 63)
    return "Name one namespace: lowercase letters, digits and hyphens. There is no wildcard and no all-namespaces rule.";
  if (ns === "kube-system" || ns === "kube-public" || ns === "kube-node-lease")
    return `${ns} is a Kubernetes system namespace and cannot be exposed by a namespace rule.`;
  if (ns === "tunnex" || ns.startsWith("tunnex-"))
    return `${ns} is Tunnex's own namespace and cannot be exposed by a namespace rule.`;
  return null;
}

/** Namespaces from the gateway's report that a rule may name and that have no rule yet. */
export function ruleableNamespaces(
  inventory: Pick<InventoryService, "namespace">[],
  existingRules: Pick<K8sNamespaceRule, "namespace">[],
): string[] {
  const taken = new Set(existingRules.map((rule) => rule.namespace));
  return [...new Set(inventory.map((item) => item.namespace))]
    .filter((ns) => !taken.has(ns) && namespaceIneligibleReason(ns) === null)
    .sort();
}

export interface NamespaceRulePreview {
  services: number; // Services the gateway reports in the namespace right now
  ports: number;
  portsAlreadyExposed: number; // left exactly as they are
  servicesToExpose: number; // Services that get at least one new exposure
  portsToExpose: number;
  newAddresses: number; // Services with no exposure yet: each takes one address from the cluster's range
}

/** What creating the rule would do with the Services reported right now. Later Services follow the same rule. */
export function namespaceRulePreview(
  inventory: InventoryService[],
  exposed: Pick<ServiceRow, "namespace" | "name" | "protocol" | "ports">[],
  namespace: string,
): NamespaceRulePreview {
  const inNamespace = exposed.filter((row) => row.namespace === namespace);
  const out: NamespaceRulePreview = { services: 0, ports: 0, portsAlreadyExposed: 0, servicesToExpose: 0, portsToExpose: 0, newAddresses: 0 };
  for (const item of inventory) {
    if (item.namespace !== namespace) continue;
    out.services += 1;
    const rows = inNamespace.filter((row) => row.name === item.service);
    let missing = 0;
    for (const port of item.ports) {
      out.ports += 1;
      const covered = rows.some(
        (row) => row.ports === "any" || (row.ports === String(port.service_port) && (row.protocol === port.protocol || row.protocol === "any")),
      );
      if (covered) out.portsAlreadyExposed += 1;
      else missing += 1;
    }
    if (missing > 0) {
      out.servicesToExpose += 1;
      out.portsToExpose += missing;
      if (rows.length === 0) out.newAddresses += 1;
    }
  }
  return out;
}

/** Mirrors the server's refusal of an excluded Service name. Exact names only; the server still decides. */
export function excludedServiceReason(name: string, alreadyExcluded: string[]): string | null {
  const svc = name.trim();
  if (svc === "") return null;
  if (!/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(svc) || svc.length > 63)
    return "Name one Service exactly: lowercase letters, digits and hyphens. Patterns are not supported.";
  if (alreadyExcluded.includes(svc)) return `${svc} is already excluded.`;
  if (alreadyExcluded.length >= 100) return "A namespace rule can exclude at most 100 Services.";
  return null;
}

export interface NamespaceRuleExclusionImpact {
  added: string[]; // names newly excluded
  removed: string[]; // names taken off the list: exposed again as NEW exposures
  withdrawPorts: number; // exposures THIS rule made that the change withdraws
  withdrawServices: number;
}

/** What saving a new exclusion list would do, from the exposures shown right now. Only the rule's own rows count. */
export function namespaceRuleExclusionImpact(
  rule: Pick<K8sNamespaceRule, "id" | "namespace" | "excluded_services">,
  exposed: { namespace: string; name: string; namespaceRuleId?: string | null }[],
  next: string[],
): NamespaceRuleExclusionImpact {
  const before = new Set(rule.excluded_services);
  const after = new Set(next);
  const added = next.filter((name) => !before.has(name)).sort();
  const removed = rule.excluded_services.filter((name) => !after.has(name)).sort();
  const rows = exposed.filter((row) => row.namespace === rule.namespace && row.namespaceRuleId === rule.id && added.includes(row.name));
  return { added, removed, withdrawPorts: rows.length, withdrawServices: new Set(rows.map((row) => row.name)).size };
}

const LABEL_NAME = /^[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$/;
const LABEL_PREFIX = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;

/** A rule's selector as text: "app=web, tier=frontend". Empty for a whole-namespace rule. */
export function selectorText(selector: Record<string, string>): string {
  return Object.keys(selector).sort().map((key) => `${key}=${selector[key]}`).join(", ");
}

/**
 * Reads "key=value, key=value". Equality only: the server has no set operators, negation or wildcards,
 * so those are refused here with the reason rather than sent. The server still decides.
 */
export function parseSelector(text: string): { selector: Record<string, string>; error: string | null } {
  const selector: Record<string, string> = {};
  const fail = (error: string) => ({ selector: {}, error });
  for (const raw of text.split(",")) {
    const pair = raw.trim();
    if (pair === "") continue;
    const at = pair.indexOf("=");
    if (at <= 0) return fail(`"${pair}" is not key=value. A selector is key=value pairs separated by commas.`);
    const key = pair.slice(0, at).trim();
    const value = pair.slice(at + 1).trim();
    const slash = key.lastIndexOf("/");
    const name = slash >= 0 ? key.slice(slash + 1) : key;
    const prefix = slash >= 0 ? key.slice(0, slash) : null;
    if (!LABEL_NAME.test(name) || (prefix !== null && (!LABEL_PREFIX.test(prefix) || prefix.length > 253)))
      return fail(`"${key}" is not a Kubernetes label key. Operators such as !=, in and ! are not supported.`);
    if (value !== "" && !LABEL_NAME.test(value))
      return fail(`"${value}" is not a Kubernetes label value. Wildcards and lists are not supported.`);
    if (key in selector) return fail(`The key ${key} is given twice.`);
    selector[key] = value;
  }
  if (Object.keys(selector).length > 8) return fail("A selector can have at most 8 key=value pairs.");
  return { selector, error: null };
}

/** The rule's state in words. Anything but "applied" is a rule that is NOT fully in effect, with the reason. */
export function namespaceRuleStatus(rule: Pick<K8sNamespaceRule, "status" | "status_message" | "waiting_services">): {
  tone: "ok" | "warn" | "danger" | "neutral";
  label: string;
  message: string | null;
} {
  const message = rule.status_message.trim() === "" ? null : rule.status_message;
  switch (rule.status) {
    case "applied":
      return { tone: "ok", label: "Applied", message };
    case "pending":
      return { tone: "neutral", label: "Waiting for first report", message: message ?? "Nothing is exposed until the cluster's gateway reports its Services." };
    case "inventory_stale":
      return { tone: "warn", label: "Report is stale", message };
    case "inventory_unavailable":
      return { tone: "warn", label: "No current report", message };
    case "vip_range_exhausted":
      return { tone: "danger", label: `Address range full · ${rule.waiting_services} waiting`, message };
    case "scope_review_limit":
      return { tone: "danger", label: `Review limit reached · ${rule.waiting_services} waiting`, message };
    case "withdrawal_blocked":
      return { tone: "warn", label: "Withdrawal blocked", message };
    case "gateway_too_old":
      return { tone: "danger", label: "Gateway too old for label selectors", message: message ?? "The cluster's gateway reports Services without labels. Upgrade the gateway; until then this rule exposes nothing." };
    case "labels_incomplete":
      return { tone: "warn", label: "Some Services cannot be matched", message };
    default:
      return { tone: "danger", label: "Not applied", message };
  }
}
