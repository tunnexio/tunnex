import type { components } from "@tunnex/shared";
import type { Role } from "./api";
import { HUMAN_ROLES, can } from "./rbac";

// K8N-3 stage 1 — a cluster's Kubernetes API as a named destination.
//
// PURE view logic for the "API access" section of a cluster's page and for every place a rule that reaches
// a cluster's API is named. API access is a NETWORK PATH: Tunnex carries TCP 443 to the API server and
// holds no cluster credential. Nothing here builds a kubeconfig, and nothing here ever tells anyone to turn
// certificate checking off.

export type K8sApiAccess = components["schemas"]["K8sApiAccess"];

export const K8S_API_ACCESS_PATH = "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/api-access" as const;

/** The permission that turns API access on or off. Deliberately not k8s:manage. */
export const K8S_API_MANAGE = "k8s_api:manage";

/** The only port a rule for a cluster's API opens. */
export const K8S_API_PORT_LABEL = "TCP 443";

/** The word for the destination kind where a rule's kinds are spelled out. */
export const K8S_API_KIND_LABEL = "Kubernetes API";

/** How a rule's destination reads everywhere it is named: never a Service name, never an id alone. */
export function k8sApiLabel(clusterName: string): string {
  return `Kubernetes API of ${clusterName}`;
}

/** A served value is used only when it has the fields this screen renders. */
export function isK8sApiAccess(value: unknown): value is K8sApiAccess {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return typeof v.cluster_id === "string" && typeof v.enabled === "boolean" && typeof v.fqdn === "string" && v.fqdn !== ""
    && typeof v.rule_count === "number" && typeof v.ordinary_exposure === "boolean";
}

export interface K8sApiGate {
  /** May turn API access on or off: k8s_api:manage and a verified email, as the server requires. */
  canManage: boolean;
  /** One line for everyone else, saying who can. null when the viewer can. */
  whoCan: string | null;
}

export function k8sApiGate(input: { role: Role | readonly Role[] | undefined; emailVerified: boolean }): K8sApiGate {
  const permitted = can(input.role, K8S_API_MANAGE);
  if (permitted && input.emailVerified) return { canManage: true, whoCan: null };
  if (permitted) return { canManage: false, whoCan: "Verify your email address to turn API access on or off." };
  // Read from the generated grant table, so the sentence cannot drift from who the server allows.
  const roles = HUMAN_ROLES.filter((role) => can(role, K8S_API_MANAGE));
  const who = roles.length === 0 ? "nobody in this organization" : roles.length === 1 ? `an organization ${roles[0]}`
    : `an organization ${roles.slice(0, -1).join(", ")} or ${roles[roles.length - 1]}`;
  return { canManage: false, whoCan: `Only ${who} can turn API access on or off.` };
}

/** The placeholder a person replaces with the host of their kubeconfig's original server line. */
export const TLS_SERVER_NAME_PLACEHOLDER = "<host from your original server line>";

/**
 * The two kubeconfig lines to change, and nothing else. The name is the served one (never assembled here).
 * tls-server-name keeps certificate checking working: the API server's certificate covers the original
 * host, not the Tunnex name.
 */
export function kubeconfigLines(fqdn: string): [string, string] {
  return [`server: https://${fqdn}`, `tls-server-name: ${TLS_SERVER_NAME_PLACEHOLDER}`];
}

/** The organization's enforcement mode as far as this screen could read it. */
export type K8sApiEnforcement = "off" | "enforcing" | "unknown";

export function ruleCountPhrase(count: number): string {
  return `${count} rule${count === 1 ? "" : "s"}`;
}

/** What the operator is told after the change was made, from the state the server returned. */
export function k8sApiChangeNotice(access: Pick<K8sApiAccess, "enabled" | "rule_count">, clusterName: string, enforcement: K8sApiEnforcement): string {
  const n = access.rule_count;
  if (!access.enabled) {
    const rules = n === 0 ? "No access rule names this cluster's API."
      : `${ruleCountPhrase(n)} that name${n === 1 ? "s" : ""} this cluster's API ${n === 1 ? "is" : "are"} kept and allow${n === 1 ? "s" : ""} nothing until API access is turned on again.`;
    return `API access is off for ${clusterName}. kubectl through Tunnex has stopped for everyone. ${rules}`;
  }
  const reach = enforcement === "off"
    ? "Zero Trust enforcement is off, so every connected device can reach the cluster's API address now."
    : n === 0 ? "Nobody can reach it until an access rule grants a person or a group."
      : `${ruleCountPhrase(n)} for this cluster's API ${n === 1 ? "is" : "are"} in effect again.`;
  return `API access is on for ${clusterName}. ${reach}`;
}

// ── rules ──────────────────────────────────────────────────────────────────────────────

/** A rule for a cluster's API may name a person or a group. The server refuses every other source. */
export function k8sApiSourceAllowed(srcKind: string): boolean {
  return srcKind === "group" || srcKind === "user";
}

export const K8S_API_SOURCE_REASON = "A cluster's Kubernetes API can be granted to a person or a group only.";
export const K8S_API_OFF_REASON = "API access is off for this cluster. Turn it on on the cluster's page first.";
export const K8S_API_UNREAD_REASON = "Could not read whether API access is on for this cluster. Refresh.";

/** One cluster as the rule builder offers it. `access` null = its API access could not be read. */
export interface K8sApiTarget {
  clusterId: string;
  clusterName: string;
  access: Pick<K8sApiAccess, "enabled" | "fqdn" | "vip"> | null;
}

/** Why a cluster's API cannot be chosen as a destination right now, or undefined when it can. */
export function k8sApiUnavailable(target: K8sApiTarget, srcKind: string): string | undefined {
  if (!k8sApiSourceAllowed(srcKind)) return K8S_API_SOURCE_REASON;
  if (target.access === null) return K8S_API_UNREAD_REASON;
  if (!target.access.enabled) return K8S_API_OFF_REASON;
  return undefined;
}

/** The rule warning, mirroring the vanished-Service one: the rule is kept and allows nothing. */
export const K8S_API_ACCESS_OFF_BADGE = "API access off · allows nothing";
export const K8S_API_ACCESS_OFF_EXPLAIN = "API access is off for this cluster. The rule is kept and allows nothing until API access is turned on again.";
