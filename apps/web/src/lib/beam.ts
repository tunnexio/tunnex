import { apiErrorCode, apiErrorMessage } from "./api";
import { personLabel } from "./personLabel";

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

// LS-UX-1: people read words, not codes. Unknown values still render readably.
const beamActionLabels: Record<string, string> = { "beam.share.created": "Share created", "beam.share.pause": "Share paused", "beam.share.resume": "Share resumed", "beam.share.stop": "Share stopped", "beam.share.extend": "Expiry extended", "beam.grants.updated": "Reviewers changed", "beam.policy.updated": "Sharing policy changed", "beam.access.allowed": "Reviewer opened the app", "beam.access.denied": "Reviewer access refused", "beam.connector.issued": "Publisher connected" };
const beamStateLabels: Record<string, string> = { starting: "Starting", active: "Active", paused: "Paused", stopped: "Stopped", expired: "Expired", revoked: "Ended by a policy or server change" };
const beamConnectivityLabels: Record<string, string> = { online: "Online", offline: "Publisher offline", reconnecting: "Reconnecting", origin_unavailable: "Local app unavailable" };
const beamOutcomeLabels: Record<string, string> = { success: "Succeeded", allowed: "Allowed", denied: "Refused" };
export function beamWords(code: string | undefined | null): string { const text = (code ?? "").replace(/^beam\./, "").replace(/[._]+/g, " ").trim(); return text ? text[0].toUpperCase() + text.slice(1) : ""; }
export const beamActionLabel = (code: string) => beamActionLabels[code] ?? beamWords(code);
export const beamStateLabel = (code: string) => beamStateLabels[code] ?? beamWords(code);
export const beamConnectivityLabel = (code: string) => beamConnectivityLabels[code] ?? beamWords(code);
export const beamOutcomeLabel = (code: string) => beamOutcomeLabels[code] ?? beamWords(code);

// LS-UX-2: who shared the app, always as "Name (email)". The publisher identity is only
// present on projections the server already let this person read.
export function beamPublisherLabel(share: Pick<BeamShare, "publisher_name" | "publisher_email">): string {
  return personLabel({ name: share.publisher_name, email: share.publisher_email }, "the publisher");
}
export type BeamViewer = "publisher" | "manager" | "reviewer";
/** How this person relates to the share: its publisher, an organization manager, or a reviewer. */
export function beamViewer(share: Pick<BeamShare, "publisher_id" | "can_manage">, userId: string): BeamViewer {
  return share.publisher_id === userId ? "publisher" : share.can_manage ? "manager" : "reviewer";
}
/**
 * LS-UX-2: one refusal for every "you cannot see this share" answer. The server answers the same
 * not-found for a share that does not exist, one you were never invited to and one whose access was
 * withdrawn, and the page must not tell them apart either.
 */
export const BEAM_SHARE_UNAVAILABLE = "This shared app isn't available to your account. The share may have ended, or the person who shared it hasn't given your account access. Ask them to check the link and who it is shared with.";
export function beamShareError(result: { error: string; code?: string }): string {
  return result.code === "beam_share_not_found" ? BEAM_SHARE_UNAVAILABLE : result.error;
}
/**
 * One plain sentence explaining the status to the person looking at it, or null when the app
 * can simply be opened. Reviewers are told who can change it; publishers are told what to do.
 */
export function beamStatusHint(share: BeamShare, viewer: BeamViewer, now = Date.now()): string | null {
  const hint = statusHint(share, viewer, now);
  return hint && hint[0].toUpperCase() + hint.slice(1);
}
function statusHint(share: BeamShare, viewer: BeamViewer, now: number): string | null {
  const publisher = beamPublisherLabel(share);
  const own = viewer === "publisher";
  if (beamIsTerminal(share, now)) {
    if (share.state === "revoked") return own ? "This share was ended by a sharing policy or server change. Publish again from the CLI or desktop client if you still need it." : `This share was ended by a sharing policy or server change. Ask ${publisher} to share the app again if you still need to review it.`;
    return own ? "This share has ended. Publish again from the CLI or desktop client to share the app again." : viewer === "manager" ? "This share has ended. Only its publisher can share the app again." : `This share has ended. Ask ${publisher} for a new link if you still need to review it.`;
  }
  if (share.state === "paused") return own ? "This share is paused. Reviewers can't open it until you resume it." : `${publisher} has paused this share. You can open it again when they resume it.`;
  if (share.state === "starting") return own ? "Waiting for your CLI or desktop client to connect." : `Waiting for ${publisher} to start sharing. Check again in a moment.`;
  if (share.connectivity === "offline" || share.connectivity === "reconnecting") return own ? "Your CLI or desktop client is not connected. Keep it running to serve reviewers." : `${publisher}'s computer is offline or reconnecting. The app opens again when it is back.`;
  if (share.connectivity === "origin_unavailable") return own ? "Your local app is not responding. Check that it is running on the shared port." : `${publisher}'s local app is not responding right now. Try again shortly or let them know.`;
  if (!share.can_open && viewer === "manager") return "You manage this share but are not one of its reviewers, so you can't open the app.";
  return null;
}
