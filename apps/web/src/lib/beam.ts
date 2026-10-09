import { apiErrorCode, apiErrorMessage } from "./api";

import { createTunnexClient } from "@tunnex/shared";
import type { paths, components } from "./beam-api";
export type BeamGrant = components["schemas"]["BeamGrant"];
export type BeamPolicy = components["schemas"]["BeamPolicy"];
export type BeamShare = components["schemas"]["BeamShare"];
export type BeamAudience = components["schemas"]["BeamAudience"];
export type BeamPolicyImpact = components["schemas"]["BeamPolicyImpact"];
export type BeamGrantsImpact = components["schemas"]["BeamGrantsImpact"];
export type BeamDiagnostics = components["schemas"]["BeamDiagnostics"];
export type BeamShareFilters = { scope?: "active" | "history"; state?: BeamShare["state"]; connectivity?: "online" | "offline" | "origin_unavailable" };
export type BeamEventFilters = { q?: string; action?: string; outcome?: string; share_id?: string };
export type BeamEvent = components["schemas"]["BeamEvent"];
export type BeamReadiness = components["schemas"]["BeamReadiness"];
export type BeamDomainSettings = components["schemas"]["BeamDomainSettings"];
export type BeamDomainSettingsInput = components["schemas"]["BeamDomainSettingsInput"];
export type BeamPage<T> = { items: T[]; limit: number; offset: number; server_time?: string; quota?: components["schemas"]["BeamQuota"] };
// Dedicated generated Beam contract, with the same session/CSRF/no-cache
// middleware as the rest of the console. No connector credential DTO is exposed.
const client = createTunnexClient<paths>("/");
export type BeamResult<T> = { ok: true; data: T; server_time?: string } | { ok: false; error: string; code?: string };
async function request<T>(call: () => Promise<{ data?: T; error?: unknown; response?: Response }>): Promise<BeamResult<T>> {
  try {
    const result = await call();
    if (result.error || result.data === undefined) return { ok: false, error: apiErrorMessage(result.error, "Could not complete the Local Sharing request."), code: apiErrorCode(result.error) };
    const server_time = result.response?.headers.get("Date") ?? undefined;
    return { ok: true, data: result.data, ...(server_time && Number.isFinite(Date.parse(server_time)) ? { server_time } : {}) };
  } catch { return { ok: false, error: "Could not reach the server. Refresh to check the current state before trying again." }; }
}
export const beamApi = {
  domainSettings: () => request(() => client.GET("/api/v1/admin/beam/settings")),
  saveDomainSettings: (input: BeamDomainSettingsInput) => request(() => client.PUT("/api/v1/admin/beam/settings", { body: input })),
  readiness: () => request(() => client.GET("/api/v1/admin/beam/readiness")),
  checkReadiness: (configuration_version: string) => request(() => client.POST("/api/v1/admin/beam/readiness", { body: { expected_configuration_version: configuration_version } })),
  policy: (orgId: string) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/policy", { params: { path: { orgId } } })),
  audience: (orgId: string) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/audience", { params: { path: { orgId } } })),
  shares: (orgId: string, shared: boolean, offset = 0, q?: string, filters: BeamShareFilters = {}, limit = 20) => request(() => client.GET(shared ? "/api/v1/organizations/{orgId}/beam/shared" : "/api/v1/organizations/{orgId}/beam/shares", { params: { path: { orgId }, query: { limit, offset, ...(q ? { q } : {}), ...filters } } })),
  share: (orgId: string, id: string) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/shares/{id}", { params: { path: { orgId, id } } })),
  action: (orgId: string, share: BeamShare, action: "pause" | "resume" | "stop" | "extend", expires_at?: string) => request(() => client.POST("/api/v1/organizations/{orgId}/beam/shares/{id}/actions", { params: { path: { orgId, id: share.id } }, body: { expected_version: share.version, action, ...(expires_at ? { expires_at } : {}) } })),
  grants: (orgId: string, share: BeamShare, grants: BeamGrant[], confirm_reviewer_removal = false) => request(() => client.PUT("/api/v1/organizations/{orgId}/beam/shares/{id}/grants", { params: { path: { orgId, id: share.id } }, body: { expected_version: share.version, grants, confirm_reviewer_removal } })),
  grantsImpact: (orgId: string, share: BeamShare, grants: BeamGrant[]) => request(() => client.POST("/api/v1/organizations/{orgId}/beam/shares/{id}/grants/impact", { params: { path: { orgId, id: share.id } }, body: { expected_version: share.version, grants, confirm_reviewer_removal: false } })),
  launch: (orgId: string, id: string, nonce: string, relative_target = "/") => request(() => client.POST("/api/v1/organizations/{orgId}/beam/shares/{id}/launch", { params: { path: { orgId, id } }, body: { relative_target, nonce_hash: nonce } })),
  savePolicy: (orgId: string, policy: BeamPolicy, confirm_end_active_shares = false) => request(() => client.PUT("/api/v1/organizations/{orgId}/beam/policy", { params: { path: { orgId } }, body: { expected_version: policy.version, enabled: policy.enabled, open_for_all_users: policy.open_for_all_users, max_duration_seconds: policy.max_duration_seconds, max_shares: policy.max_shares, publisher_group_ids: policy.publisher_group_ids, reviewer_user_ids: policy.reviewer_user_ids, reviewer_group_ids: policy.reviewer_group_ids, require_mfa: policy.require_mfa, confirm_end_active_shares } })),
  policyImpact: (orgId: string, policy: BeamPolicy) => request(() => client.POST("/api/v1/organizations/{orgId}/beam/policy/impact", { params: { path: { orgId } }, body: { expected_version: policy.version, enabled: policy.enabled, open_for_all_users: policy.open_for_all_users, max_duration_seconds: policy.max_duration_seconds, max_shares: policy.max_shares, publisher_group_ids: policy.publisher_group_ids, reviewer_user_ids: policy.reviewer_user_ids, reviewer_group_ids: policy.reviewer_group_ids, require_mfa: policy.require_mfa, confirm_end_active_shares: false } })),
  diagnostics: (orgId: string, id: string) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/shares/{id}/diagnostics", { params: { path: { orgId, id } } })),
  shareEvents: (orgId: string, id: string, offset = 0, filters: BeamEventFilters = {}, limit = 20) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/shares/{id}/events", { params: { path: { orgId, id }, query: { limit, offset, ...filters } } })),
  events: (orgId: string, offset = 0, filters: BeamEventFilters = {}, limit = 20) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/events", { params: { path: { orgId }, query: { limit, offset, ...filters } } })),
};
export function beamIsTerminal(share: BeamShare, now = Date.now()): boolean { return ["stopped", "expired", "revoked"].includes(share.state) || !Number.isFinite(Date.parse(share.expires_at)) || Date.parse(share.expires_at) <= now; }
export function beamCanOpen(share: BeamShare, now = Date.now()): boolean { return share.can_open && !beamIsTerminal(share, now) && share.state === "active" && share.connectivity === "online"; }
export function beamStatus(share: BeamShare, now = Date.now()): string {
  if (Date.parse(share.expires_at) <= now && !["stopped", "revoked"].includes(share.state)) return "Expired";
  if (share.state !== "active") return share.state.charAt(0).toUpperCase() + share.state.slice(1);
  return ({ online: "Live", reconnecting: "Reconnecting", offline: "Publisher offline", origin_unavailable: "Local app unavailable" } as const)[share.connectivity] ?? "Unavailable";
}
export function beamLaunchURL(raw: string, hostname: string): string | null {
  try { const url = new URL(raw); return url.protocol === "https:" && url.hostname === hostname && !url.username && !url.password && !url.port ? url.href : null; } catch { return null; }
}

export function beamHandoffURL(raw: string, hostname: string): string | null {
  const safe = beamLaunchURL(raw, hostname); if (!safe) return null;
  const url = new URL(safe); return url.pathname === "/_beam/redeem" && /^tnxbc_[A-Za-z0-9_-]{43}$/.test(url.searchParams.get("code") ?? "") && url.searchParams.size === 1 && !url.hash ? url.href : null;
}

// Deliberate allowlist: future DTO additions and unknown response fields cannot
// enter the support export. Targets, identities and credentials are excluded.
export function beamDiagnosticExport(value: BeamDiagnostics) {
  return { share_id: value.share_id, hostname: value.hostname, state: value.state,
    connectivity: value.connectivity, version: value.version, authority_version: value.authority_version,
    generation: value.generation, expires_at: value.expires_at, domain_ready: value.domain_ready,
    status: value.status, reason: value.reason };
}

export function beamAuditDetails(details: Record<string, unknown>): [string, string | number | boolean][] {
  const allowed = new Set(["outcome", "reason", "version", "authority_version", "generation"]);
  return Object.entries(details).filter((entry): entry is [string, string | number | boolean] => allowed.has(entry[0]) && ["string", "number", "boolean"].includes(typeof entry[1]));
}
