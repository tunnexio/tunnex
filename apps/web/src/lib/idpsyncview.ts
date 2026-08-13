// Directory sync (IdP) — the view-model.
//
// FIVE ENDPOINTS, ZERO CALL SITES before this story (censused against `apps/web/src`, excluding
// `edition.ts` which is a path MANIFEST and would have matched by construction):
//
//   PUT    …/idp-sync/{provider}                     putIdpSyncConfig    unreachable
//   GET    …/idp-sync/{provider}/health              getIdpSyncHealth    unreachable
//   POST   …/idp-sync/{provider}/trigger             triggerIdpSync      unreachable
//   POST   …/idp-sync/{provider}/groups              mapIdpGroup         unreachable
//   DELETE …/idp-sync/{provider}/groups/{groupId}    unmapIdpGroup       unreachable
//
// Three of them are in EPIC 14's unreachable-eleven. This file is the consuming layer.

import type { Role } from "./api";
import { can } from "./rbac";

/**
 * ⛔ THIS PANEL DOES NOT RUN ON `org:update`, AND THAT IS A MEASURED FACT ABOUT THE SERVER.
 *
 * Every handler gates on POLICY permissions, not org ones — `PermPolicyManage` for the four
 * mutations (`idp_sync_handlers.go:31/78/96/125`) and `PermPolicyView` for health (`:60`).
 * The wireframe places directory sync under Settings, and it is built there because it is a
 * CREDENTIAL surface that shares SSO's providers and sealed-secret shape — but the gate is the
 * server's, not the screen's.
 *
 * CONSEQUENCE, STATED RATHER THAN DISCOVERED LATER: an operator with `org:update` and without
 * `policy:manage` reaches Settings and cannot use this panel. The panel is HIDDEN for them, not
 * rendered-and-refusing — a control that only ever produces a 403 is a worse answer than no
 * control (S14.11/S14.12: permission BEFORE edition, and never imply an action you cannot take).
 */
export type IdpGate =
  { kind: "hidden" } | { kind: "upsell" } | { kind: "ready" };

export function idpGate(i: {
  role: Role | null;
  isEnterprise: boolean;
}): IdpGate {
  // Permission first, mirroring the handlers: authorize runs before the edition check.
  if (!i.role || !can(i.role, "policy:manage")) return { kind: "hidden" };
  if (!i.isEnterprise) return { kind: "upsell" };
  return { kind: "ready" };
}

export type SyncTier = "ok" | "degraded" | "escalated";

export type IdpHealth = {
  provider: string;
  sync_health: string;
  last_sync_ok: boolean;
  last_sync_error?: string | null;
  last_sync_at?: string | null;
};

/**
 * ⛔ "NOT CONFIGURED" IS A STATE. A FAILED READ IS NOT. — the third instance of this shape, and
 * the first where it was built right the first time rather than repaired.
 *
 * Unlike domain claims, this surface CAN be read: `GET …/health` answers `404` with a stable
 * `idp_sync_not_configured` (`enterprise/idpsync/service.go:141`) when no credential exists. So
 * existence is knowable and gets its own arm, and only a NON-404 failure lands in `unknown`.
 *
 * ⚠ WHAT IS STILL NOT READABLE IS THE CREDENTIAL ITSELF. There is no GET for the config, so
 * `client_id`, `tenant_id`, `enabled` and the secret fingerprint are returned ONLY by the PUT
 * that wrote them — the third member of the write-only-state trio, registered at S14.13. The
 * panel therefore renders health from the server and shows credential detail only for a config
 * written in this session; it must never present an empty credential form as "not configured".
 */
export type IdpConfigState =
  | { kind: "unknown" }
  | { kind: "unsupported" }
  | { kind: "unconfigured" }
  | { kind: "configured"; health: IdpHealth };

/**
 * ⛔ THE FOURTH ARM, FOUND BY READING THE SERVED PAYLOAD RATHER THAN THE SPEC.
 *
 * The OpenAPI enum lists `[microsoft, google]` for every idp-sync path, so the panel was built
 * for two providers. The SERVER answers Google with **`400 provider_not_supported`** — *"directory
 * sync currently supports microsoft only"* — and it is deliberate: `supportedProvider`
 * (`enterprise/idpsync/service.go:83`) rejects at CONFIG time on purpose, with a comment saying
 * the enum keeps Google for forward-compat and the capability gate lives in the service.
 *
 *   THE SPEC DESCRIBES THE SHAPE OF THE REQUEST. IT DOES NOT PROMISE THE CAPABILITY EXISTS.
 *
 * Without this arm a non-404 falls into `unknown` and Google renders "status unknown — Retry", a
 * button that can never succeed, over a Configure form for a provider the server refuses to
 * store. That is the "never imply an action it did not perform" rule, and only the live payload
 * exposed it — the spec, the handler and the schema all read as though Google works.
 */
export function idpConfigState(i: {
  errorCode?: string | null;
  failed: boolean;
  health: IdpHealth | null;
}): IdpConfigState {
  if (i.errorCode === "provider_not_supported") return { kind: "unsupported" };
  if (i.errorCode === "idp_sync_not_configured")
    return { kind: "unconfigured" };
  if (i.failed || !i.health) return { kind: "unknown" };
  return { kind: "configured", health: i.health };
}

/** Stated as a roadmap fact, not an error — the server calls Google a planned fast-follow. */
export const UNSUPPORTED_NOTE =
  "Directory sync currently supports Microsoft Entra only. Google Workspace is not available yet.";

export function syncTier(h: IdpHealth): SyncTier {
  return h.sync_health === "ok" ||
    h.sync_health === "degraded" ||
    h.sync_health === "escalated"
    ? h.sync_health
    : // A tier the client does not know is NOT quietly rendered as healthy. `escalated` is the
      // safe direction: it is the one that asks a human to look.
      "escalated";
}

/**
 * The two-tier state in words, with the ceiling named.
 *
 * MEASURED from `ClassifySyncHealth` (`enterprise/idpsync/health.go`), not invented:
 * `EscalationCeiling` is **3× the 10-minute poll interval = 30 minutes**, anchored on the last
 * SUCCESSFUL sync — or on the config's creation time if it has never synced, so a credential
 * that is wrong from birth still escalates. The tier is DERIVED at read time, never a stored
 * dead-green field.
 */
export function tierCopy(t: SyncTier): {
  label: string;
  text: string;
  loud: boolean;
} {
  switch (t) {
    case "ok":
      return {
        label: "OK",
        text: "The last directory poll succeeded.",
        loud: false,
      };
    case "degraded":
      return {
        label: "DEGRADED",
        text: "A poll is failing, but the last successful sync is recent (under 30 minutes). Group membership is still being enforced from the last good sync.",
        loud: false,
      };
    case "escalated":
      return {
        label: "ESCALATED",
        text: "Polls have been failing for more than 30 minutes — three whole cycles. Group membership is frozen at the last successful sync and is drifting from the directory.",
        loud: true,
      };
  }
}

/**
 * ⛔ WHAT A STALE SYNC ACTUALLY MEANS FOR ACCESS, which no health badge conveys on its own.
 *
 * The reconciler is fail-static (S7.5.2): a failing poll does NOT empty the groups, it leaves
 * the last good membership in place. That is the safe choice for availability and the unsafe one
 * for deprovisioning — someone removed from a directory group KEEPS their access for as long as
 * the sync is broken. An operator reading only "degraded" would not know that.
 */
export const FAIL_STATIC_NOTE =
  "Membership is kept from the last successful sync, not emptied — so while sync is broken, a user removed in the directory keeps their access here until it recovers.";

/** A Tunnex group the directory owns. Derived from the groups list; there is no mappings read. */
export type MappedGroup = {
  id: string;
  name: string;
  origin?: string;
  idp_provider?: string;
  idp_group_id?: string;
};

/**
 * The mapped-group list, derived rather than fetched.
 *
 * There is NO endpoint that lists mappings — but `GET …/groups` returns `origin`,
 * `idp_provider` and `idp_group_id` (`openapi.yaml:2442-2444`), and `user_groups` carries a
 * CHECK constraint (`user_groups_origin_shape`) guaranteeing an `idp_sync` row has BOTH idp
 * fields. So the list is knowable from a read the app already makes, and no endpoint is owed.
 */
export function mappedGroups<T extends MappedGroup>(
  groups: T[],
  provider: string,
): T[] {
  return groups.filter(
    (g) => g.origin === "idp_sync" && g.idp_provider === provider,
  );
}

/**
 * ⛔ THE UNMAP BLAST RADIUS — check 7b, and it is the S14.12 cascade one screen over.
 *
 * `UnmapGroup` (`enterprise/idpsync/service.go:276`) does three things and the 204 mentions none
 * of them: it unbinds the group, **deletes every member row**
 * (`DeleteGroupMembersByGroup`), and calls `PushOrgNodes` because "the group's grants disappear
 * org-wide". The group SURVIVES as an empty manual group, so any policy rule referencing it is
 * NOT cascade-deleted — it stays and compiles to nothing, which is the quietest possible failure:
 * the rule is still listed, still looks enforced, and matches no device.
 *
 * ⚠ NO NUMBER IS NAMED HERE. The server serves no preview and the 204 has no body; a
 * client-computed member count would be a second source of truth about what the server is about
 * to do (S14.12's law). The RISK is named; the COUNT is not.
 */
export const UNMAP_CONSEQUENCES = [
  "Every member is removed from this group.",
  "The group stays, as an empty manual group — it is not deleted.",
  "Any access rule using this group keeps existing but will match nobody.",
  "Nodes are re-pushed org-wide, so access changes immediately.",
] as const;

/** The confirm is armed only by typing the group's own name — a delete-shaped verb. */
export function unmapConfirmSatisfied(typed: string, name: string): boolean {
  return (
    typed.trim().toLowerCase() === name.trim().toLowerCase() &&
    name.trim() !== ""
  );
}

/**
 * ⛔ AND UN-MAPPING WRITES NO AUDIT ROW. Measured: `Service.UpsertConfig` audits
 * (`idp_sync.config_updated`, service.go:123) and the reconciler audits its own membership
 * writes, but `UnmapGroup`'s transaction contains **zero** `humanAudit` calls — it unbinds and
 * deletes every member with no record that a human did it.
 *
 * Same shape as S14.13's `SuspendDomainClaim`: an access-affecting state change with no trail.
 * Registered, not fixed here — it is a server change and this slice is the consuming layer.
 */
export const UNMAP_UNAUDITED = true;

/**
 * ⛔ MAPPING TAKES A DIRECTORY GROUP **ID**, AND THERE IS NO ENDPOINT TO BROWSE ONE.
 *
 * `mapIdpGroup` accepts an `idp_group_id` string; nothing in the spec lists the directory's
 * groups, so a picker CANNOT be built and the field is necessarily free text. The panel says
 * where to find the value instead of pretending to offer a choice — a select box the product
 * cannot populate would be the "imply an action it did not perform" failure in its purest form.
 */
export const IDP_GROUP_ID_HELP: Record<string, string> = {
  microsoft:
    "The Entra group's Object ID (a GUID) — Entra admin centre › Groups › the group › Object ID.",
  google:
    "The Google Workspace group's email address or immutable ID — Admin console › Directory › Groups.",
};

export function idpGroupIdHelp(provider: string): string {
  return (
    IDP_GROUP_ID_HELP[provider] ??
    "The directory group's unique identifier, as your directory shows it."
  );
}

/** Server error codes, each read off the service rather than guessed. */
export function idpErrorCopy(code: string | null | undefined): string {
  switch (code) {
    case "idp_sync_not_configured": // service.go:141/160/228
      return "Configure this provider's credential before mapping groups.";
    case "group_not_empty": // service.go:253 — D1 refuse-unless-empty
      return "Only an empty group can be converted to directory sync. Remove its members first, or map to a new group instead.";
    case "group_already_synced": // service.go:249
      return "That group is already directory-managed.";
    case "group_not_found":
      return "That group no longer exists.";
    case "invalid_request":
      return "Provide either a name (to create a group) or an existing group, not both.";
    case "provider_not_supported":
      return "Directory sync currently supports Microsoft Entra only.";
    case "edition_required":
      return "Directory sync is an enterprise capability.";
    default:
      return "Could not complete the request.";
  }
}

/**
 * ⛔ A DIRECTORY-OWNED GROUP CANNOT BE HAND-EDITED, AND THE ACCESS SCREEN WAS OFFERING IT ANYWAY.
 *
 * MEASURED: `AddGroupMember` refuses with **`409 idp_managed_group`** — *"this group is managed
 * by directory sync; members cannot be edited manually"* (`enterprise/policy/service.go:125`).
 * The web read `origin` NOWHERE, so `GroupRow` gated its Add/Remove controls on `canManage`
 * alone and rendered them on synced groups too. Every use was a guaranteed 409.
 *
 * That is the "never imply an action it did not perform" rule in its plainest form, and it is
 * S14.14's finding about a screen S14.12 shipped: the reconciler owned those rows all along, and
 * the only place that fact was written down was a server error string nobody could reach without
 * clicking.
 *
 * ⚠ The DELETE control stays. Deleting a synced group is genuinely allowed (it is un-mapping
 * plus removal); it is only MEMBERSHIP the reconciler owns. Hiding the wrong verb would trade
 * one wrong affordance for another.
 */
export function isDirectoryManaged(g: { origin?: string }): boolean {
  return g.origin === "idp_sync";
}

export const DIRECTORY_MANAGED_NOTE =
  "Members are synced from the directory and cannot be edited here. Change the group in your directory, or un-map it in Settings › Directory sync.";

/** The row badge. Short, because it sits inline next to the group name. */
export const DIRECTORY_MANAGED_BADGE = "DIRECTORY";
