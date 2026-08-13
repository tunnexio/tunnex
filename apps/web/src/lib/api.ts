import { createTunnexClient, type components } from "@tunnex/shared";

// One typed client for the whole SPA (same-origin; the session cookie rides along).
export const api = createTunnexClient("/");

// The X-Tunnex-CSRF header is attached to every unsafe-method request by
// createTunnexClient itself (see packages/shared) — no per-call plumbing.

export type AuthUser = components["schemas"]["AuthUser"];
export type Meta = components["schemas"]["Meta"];
export type Org = components["schemas"]["Organization"];
export type Node = components["schemas"]["Node"];
export type HubSet = components["schemas"]["HubSet"];
export type HubMember = components["schemas"]["HubMember"];
export type Device = components["schemas"]["Device"];
export type OrgOverview = components["schemas"]["OrgOverview"];
export type Member = components["schemas"]["Member"];
export type MachineCredential = components["schemas"]["MachineCredential"];
export type Role = Member["role"];
export type SsoConfigView = components["schemas"]["SsoConfigView"];
export type ResizeConflict = components["schemas"]["ResizeConflict"];
export type AuditLogEntry = components["schemas"]["AuditLogEntry"];
// S7.4a — Zero Trust admin UI DTOs.
export type UserGroup = components["schemas"]["UserGroup"];
export type GroupMember = components["schemas"]["GroupMember"];
export type Resource = components["schemas"]["Resource"];
export type PolicyRule = components["schemas"]["PolicyRule"];
export type ZeroTrustMode = components["schemas"]["ZeroTrustMode"];
export type AffectedDevice = components["schemas"]["AffectedDevice"];
// S7.5.4 — per-user + temporary grants.
export type CreatePolicyRuleRequest =
  components["schemas"]["CreatePolicyRuleRequest"];
export type ExtendGrantRequest = components["schemas"]["ExtendGrantRequest"];
export type DeviceApproval = components["schemas"]["DeviceApproval"];
// S7.5.3 — device posture config DTO. (HealthCheckInput / DeviceHealthResult are
// consumed by the Electron client, not the SPA — the web app only reads/writes the
// check config, so only HealthCheck is surfaced here.)
export type HealthCheck = components["schemas"]["HealthCheck"];
// S8.3 — site management UI.
export type Site = components["schemas"]["Site"];
export type SiteSubnet = components["schemas"]["SiteSubnet"];
export type SiteReferences = components["schemas"]["SiteReferences"];
export type DNSForward = components["schemas"]["DNSForward"];
// S10.3 — Kubernetes cluster/Service connectivity.
export type K8sCluster = components["schemas"]["K8sCluster"];
export type K8sService = components["schemas"]["K8sService"];

// apiErrorMessage pulls the human message out of the standard error envelope.
export function apiErrorMessage(error: unknown, fallback: string): string {
  const e = error as { error?: { message?: string } } | undefined;
  return e?.error?.message ?? fallback;
}

// Loaded<T> normalizes a GET result. openapi-fetch is a STANDING FOOTGUN: it returns
// {data:undefined, error} on a non-2xx (it does NOT throw) and REJECTS on a network
// failure — two paths that, if a component only reads `data`, silently render a
// reassuring EMPTY state for a real failure (the S7.4a review's dominant cluster).
// loadOne collapses BOTH into a discriminated result so callers render a legible
// "failed — retry", never "none".
//
// SANCTIONED CALL PATTERN: a raw `api.GET` in a component whose emptiness is
// user-meaningful (a list, a role, a count that gates a destructive action) is
// review-refused — route it through loadOne so a fetch failure can't read as absence.
export type Loaded<T> = { ok: true; data: T } | { ok: false; error: string };

export async function loadOne<T>(
  call: () => Promise<{ data?: T; error?: unknown }>,
): Promise<Loaded<T>> {
  try {
    const { data, error } = await call();
    if (error)
      return { ok: false, error: apiErrorMessage(error, "Could not load.") };
    if (data === undefined) return { ok: false, error: "Could not load." };
    return { ok: true, data };
  } catch {
    return { ok: false, error: "Could not reach the API." };
  }
}

// apiErrorCode pulls the stable machine-readable code out of the error envelope
// (e.g. "org_limit_reached") so callers can branch on it instead of matching prose.
export function apiErrorCode(error: unknown): string | undefined {
  const e = error as { error?: { code?: string } } | undefined;
  return e?.error?.code;
}
