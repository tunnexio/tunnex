// THE EDITION SEAM — enumerated from the spec, not from memory.
//
// ⛔ THE DEFECT THIS CLOSES, TWICE OVER. `403 edition_required` is a SUCCESSFUL REFUSAL: the server answered,
// correctly, that the capability does not exist for this edition. Read through `loadOne` alone it becomes
// `failed`, and the open edition renders a red "could not load" for a feature it was never sold.
//
// It was fixed once, at ONE call site (the Pending-approvals card), and the SAME defect was still live two
// cards over on Access Rules — because a fix at a call site does not reach the call sites beside it. That is
// the missing-primitive law's shape: only an ENUMERATION finds the rest.
//
// SO THE SET IS DATA, DERIVED FROM `openapi.yaml`, AND A TEST HOLDS IT TO THE SPEC. A new enterprise card
// cannot be added without registering its endpoint here, because the census will not find it guarded.

/**
 * Every enterprise-gated operation path in the spec, as the `api.GET`-style template.
 *
 * ⚠ MEASURED, and the measurement exposed a spec inconsistency worth recording: **37 operations are marked
 * enterprise, but only 7 document `403 edition_required` in their own responses.** The other 30 declare it
 * only in their `summary` text. So a scan for the documented error code finds a fifth of the surface — which
 * is precisely how the first sweep would have missed Access Rules a second time.
 */
export const ENTERPRISE_PATHS: readonly string[] = [
  // S15.3 — the agent surface. ⛔ The client must KNOW this is enterprise, so a 403 renders as ABSENCE
  // rather than as a failure: edition_required is a SUCCESSFUL refusal.
  "/api/v1/organizations/{orgId}/agents",
  "/api/v1/organizations/{orgId}/access-events",
  "/api/v1/organizations/{orgId}/access-log/health",
  "/api/v1/organizations/{orgId}/device-approval",
  "/api/v1/organizations/{orgId}/devices/pending",
  // ⛔ ADDED S14.5 BY A WIDENED CENSUS. These three were enterprise on the SERVER all along —
  // `ApproveDevice`/`RejectDevice` call `deviceApprovalEditionRequired()` and `ReportDeviceHealth` gates on
  // `deviceHealthEnabled` — and were missed here because the census matched `(enterprise)` alone while their
  // summaries read `(…, enterprise)`. The gate existed; the client did not know about it.
  "/api/v1/organizations/{orgId}/devices/{deviceId}/approve",
  "/api/v1/organizations/{orgId}/devices/{deviceId}/health",
  "/api/v1/organizations/{orgId}/devices/{deviceId}/reject",
  "/api/v1/organizations/{orgId}/groups",
  "/api/v1/organizations/{orgId}/groups/{groupId}",
  "/api/v1/organizations/{orgId}/groups/{groupId}/members",
  "/api/v1/organizations/{orgId}/groups/{groupId}/members/{userId}",
  "/api/v1/organizations/{orgId}/health-checks",
  "/api/v1/organizations/{orgId}/health-checks/{checkKind}",
  "/api/v1/organizations/{orgId}/idp-sync/{provider}",
  "/api/v1/organizations/{orgId}/idp-sync/{provider}/groups",
  "/api/v1/organizations/{orgId}/idp-sync/{provider}/groups/{groupId}",
  "/api/v1/organizations/{orgId}/idp-sync/{provider}/health",
  "/api/v1/organizations/{orgId}/idp-sync/{provider}/trigger",
  "/api/v1/organizations/{orgId}/members/{userId}/mfa-reset",
  "/api/v1/organizations/{orgId}/mfa-enforce",
  "/api/v1/organizations/{orgId}/policies",
  "/api/v1/organizations/{orgId}/policies/{ruleId}",
  "/api/v1/organizations/{orgId}/resources",
  "/api/v1/organizations/{orgId}/resources/{resourceId}",
  "/api/v1/organizations/{orgId}/sso/{provider}",
  "/api/v1/organizations/{orgId}/zero-trust-mode",
  "/api/v1/auth/sso/{provider}/start",
  "/api/v1/auth/sso/{provider}/callback",
] as const;

export function isEnterprisePath(path: string): boolean {
  return ENTERPRISE_PATHS.includes(path);
}

/**
 * The edition, as a THREE-state answer — because "we have not asked yet" is not "open".
 *
 * `unknown` behaves as NOT enterprise on purpose: a slow `/meta` must never flash an enterprise surface at an
 * org that does not have it. Absent-until-known, the same rule the nav counts follow.
 */
export type Edition = "unknown" | "open" | "enterprise";

export function isEnterprise(e: Edition): boolean {
  return e === "enterprise";
}

/**
 * The FOURTH state, named.
 *
 * A screen that enumerates loading / failed / ok pushes the danger onto the state it did not enumerate, and
 * that state gets absorbed by whichever existing one is nearest. `403 edition_required` is nearest to "error"
 * in SHAPE and furthest from it in MEANING, which is exactly why it landed there twice.
 */
export type Gated<T> =
  | { state: "loading" }
  | { state: "failed" }
  | { state: "absent" }
  | { state: "ok"; data: T };

/**
 * Decide what a gated surface shows, BEFORE any fetch.
 *
 * Returning `absent` without calling the endpoint is deliberate: it is faster, it produces no 403 noise in the
 * server log, and — the real reason — it makes the edition decision a RENDER decision taken at the seam rather
 * than an error interpreted at the call site. The interpretation is what drifted.
 */
export function gate<T>(
  edition: Edition,
  path: string,
  result: Gated<T> | null,
): Gated<T> {
  if (isEnterprisePath(path) && !isEnterprise(edition))
    return { state: "absent" };
  return result ?? { state: "loading" };
}
