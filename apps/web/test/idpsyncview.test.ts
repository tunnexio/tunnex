import { describe, expect, it } from "vitest";
import {
  FAIL_STATIC_NOTE,
  UNMAP_CONSEQUENCES,
  UNSUPPORTED_NOTE,
  idpConfigState,
  idpErrorCopy,
  idpGate,
  idpGroupIdHelp,
  mappedGroups,
  syncTier,
  tierCopy,
  unmapConfirmSatisfied,
  isDirectoryManaged,
  DIRECTORY_MANAGED_NOTE,
  DIRECTORY_MANAGED_BADGE,
} from "../src/lib/idpsyncview";
import { can } from "../src/lib/rbac";

// ⛔ THE GATE IS THE SERVER'S, NOT THE SCREEN'S. Directory sync lives under Settings but every
// handler gates on POLICY permissions — PermPolicyManage for the four mutations
// (idp_sync_handlers.go:31/78/96/125), PermPolicyView for health (:60). An operator with
// org:update and without policy:manage must not see a control that can only ever 403.
describe("idpGate", () => {
  it("hides the panel from an org admin who lacks policy:manage", () => {
    // The load-bearing case for putting a policy-gated panel on an org screen.
    expect(idpGate({ role: "member", isEnterprise: true })).toEqual({
      kind: "hidden",
    });
  });

  it("checks permission BEFORE edition", () => {
    // Reversed, an open-edition member is upsold a capability they still could not use.
    expect(idpGate({ role: "member", isEnterprise: false })).toEqual({
      kind: "hidden",
    });
  });

  it("upsells an admin on the open edition and is ready on enterprise", () => {
    expect(idpGate({ role: "admin", isEnterprise: false })).toEqual({
      kind: "upsell",
    });
    expect(idpGate({ role: "admin", isEnterprise: true })).toEqual({
      kind: "ready",
    });
  });

  // ⛔ A MUTATION SURVIVED HERE AND THE HONEST ANSWER IS THAT IT SHOULD HAVE.
  //
  // Swapping the gate to `org:update` changed NOTHING at owner/admin/member. Measured against the
  // generated RBAC mirror, the two permissions are held by exactly the same USER-ASSIGNABLE roles:
  //
  //   role      org:update   policy:manage
  //   owner     yes          yes
  //   admin     yes          yes
  //   member    no           no
  //   operator  NO           YES     <- MACHINE-ONLY. Not user-assignable: `memberships` CHECKs
  //                                     role IN (owner, admin, member), and a machine credential
  //                                     never renders a UI. It cannot make this gate observable.
  //
  // So no behavioural test can distinguish the two gates today, and writing one against
  // `operator` would have been a test about a session that cannot exist — the generated `Role`
  // type rejects it for exactly that reason.
  //
  // WHAT IS GUARDED INSTEAD IS THE PREMISE. If the mirror ever grants a human role one
  // permission without the other, the gate stops being cosmetic and this test says so.
  it("⛔ pins the PREMISE: for every user-assignable role, the two permissions agree today", () => {
    for (const role of ["owner", "admin", "member"] as const) {
      expect(can(role, "policy:manage")).toBe(can(role, "org:update"));
    }
  });

  it("treats an unknown role as hidden", () => {
    expect(idpGate({ role: null, isEnterprise: true })).toEqual({
      kind: "hidden",
    });
  });
});

// ⛔ FOUR ARMS, AND THE FOURTH CAME FROM THE SERVED PAYLOAD — the spec, the handler and the
// schema all read as though Google works. The live API answers 400 provider_not_supported
// ("directory sync currently supports microsoft only", service.go:83).
describe("idpConfigState", () => {
  const h = { provider: "microsoft", sync_health: "ok", last_sync_ok: true };

  it("⛔ an unsupported provider is NOT 'unknown' — no Retry, no Configure form", () => {
    // Without this arm Google renders "status unknown" with a Retry that can never succeed,
    // above a Configure form for a credential the server refuses to store.
    expect(
      idpConfigState({
        errorCode: "provider_not_supported",
        failed: true,
        health: null,
      }),
    ).toEqual({ kind: "unsupported" });
  });

  it("not-configured is a knowable state, distinct from a failed read", () => {
    expect(
      idpConfigState({
        errorCode: "idp_sync_not_configured",
        failed: true,
        health: null,
      }),
    ).toEqual({ kind: "unconfigured" });
    expect(
      idpConfigState({ errorCode: "boom", failed: true, health: null }),
    ).toEqual({ kind: "unknown" });
  });

  it("a 200 with no body is unknown, not configured", () => {
    expect(idpConfigState({ failed: false, health: null })).toEqual({
      kind: "unknown",
    });
  });

  it("renders configured when the health read succeeds", () => {
    expect(idpConfigState({ failed: false, health: h })).toEqual({
      kind: "configured",
      health: h,
    });
  });

  it("states the unsupported case as a roadmap fact, not an error", () => {
    expect(UNSUPPORTED_NOTE).toMatch(/Microsoft Entra only/i);
    expect(UNSUPPORTED_NOTE).toMatch(/not available yet/i);
  });
});

// The tier is DERIVED at read time from ClassifySyncHealth (health.go); the ceiling is 3× the
// 10-minute poll interval = 30 minutes, anchored on the last SUCCESSFUL sync.
describe("syncTier + tierCopy", () => {
  it("⛔ an unrecognised tier fails toward ESCALATED, never toward ok", () => {
    // A tier the client does not know must not render as healthy — escalated is the one that
    // asks a human to look. This is the direction that matters, so it is pinned.
    expect(
      syncTier({ provider: "microsoft", sync_health: "", last_sync_ok: false }),
    ).toBe("escalated");
    expect(
      syncTier({
        provider: "microsoft",
        sync_health: "something_new",
        last_sync_ok: true,
      }),
    ).toBe("escalated");
  });

  it("passes the three known tiers through", () => {
    for (const t of ["ok", "degraded", "escalated"] as const) {
      expect(
        syncTier({ provider: "microsoft", sync_health: t, last_sync_ok: true }),
      ).toBe(t);
    }
  });

  it("names the 30-minute ceiling in both failing tiers, and only escalated is loud", () => {
    expect(tierCopy("degraded").text).toMatch(/30 minutes/);
    expect(tierCopy("escalated").text).toMatch(/30 minutes/);
    expect(tierCopy("degraded").loud).toBe(false);
    expect(tierCopy("escalated").loud).toBe(true);
    expect(tierCopy("ok").loud).toBe(false);
  });

  it("⛔ says that a broken sync KEEPS access rather than removing it", () => {
    // Fail-static is the safe choice for availability and the unsafe one for deprovisioning; a
    // health badge alone conveys the opposite intuition.
    expect(FAIL_STATIC_NOTE).toMatch(/kept from the last successful sync/i);
    expect(FAIL_STATIC_NOTE).toMatch(/keeps their access/i);
  });
});

// There is no endpoint that lists mappings. GET /groups returns origin + idp_provider +
// idp_group_id (openapi.yaml:2442-2444), and user_groups_origin_shape CHECKs that an idp_sync
// row carries both idp fields — so the list is derivable and no endpoint is owed.
describe("mappedGroups", () => {
  const gs = [
    { id: "1", name: "Manual", origin: "manual" },
    { id: "2", name: "Eng", origin: "idp_sync", idp_provider: "microsoft" },
    { id: "3", name: "Goog", origin: "idp_sync", idp_provider: "google" },
    { id: "4", name: "NoOrigin" },
  ];

  it("keeps only this provider's synced groups", () => {
    expect(mappedGroups(gs, "microsoft").map((g) => g.id)).toEqual(["2"]);
  });

  it("never counts a manual group as directory-managed", () => {
    // The regression that would silently offer Un-map on a hand-managed group.
    const ids = mappedGroups(gs, "microsoft").map((g) => g.id);
    expect(ids).not.toContain("1");
    expect(ids).not.toContain("4");
  });
});

// ⛔ CHECK 7b — the un-map blast radius, one screen over from S14.12's cascade.
// UnmapGroup (service.go:276) unbinds, DELETES EVERY MEMBER, and pushes org-wide. The group
// SURVIVES, so rules referencing it are not cascade-deleted — they stay and match nobody.
describe("UNMAP_CONSEQUENCES", () => {
  it("names every effect the 204 does not mention", () => {
    const all = UNMAP_CONSEQUENCES.join(" ");
    expect(all).toMatch(/every member is removed/i);
    expect(all).toMatch(/not deleted/i); // the group survives — that is why rules survive
    expect(all).toMatch(/match nobody/i); // the quietest failure: a rule that still looks enforced
    expect(all).toMatch(/immediately/i); // PushOrgNodes
  });

  it("⛔ names no COUNT — the server serves no preview and the 204 has no body", () => {
    // A client-computed member count would be a second source of truth about what the server is
    // about to do (S14.12). Name the risk, omit the number.
    for (const c of UNMAP_CONSEQUENCES) expect(c).not.toMatch(/\d/);
  });
});

describe("unmapConfirmSatisfied", () => {
  it("requires the group's own name, case- and space-insensitively", () => {
    expect(unmapConfirmSatisfied(" directory · eng ", "Directory · Eng")).toBe(
      true,
    );
    expect(unmapConfirmSatisfied("Directory", "Directory · Eng")).toBe(false);
  });

  it("is never satisfied by empty input against an empty name", () => {
    // Otherwise a group with a blank name would arm a destructive confirm for free.
    expect(unmapConfirmSatisfied("", "")).toBe(false);
    expect(unmapConfirmSatisfied("  ", "  ")).toBe(false);
  });
});

// mapIdpGroup takes an idp_group_id string and nothing lists the directory's groups, so a picker
// cannot be built. Telling the operator where to find the value is the honest alternative to a
// select box the product cannot populate.
describe("idpGroupIdHelp", () => {
  it("tells the operator where the ID comes from, per provider", () => {
    expect(idpGroupIdHelp("microsoft")).toMatch(/Object ID/i);
    expect(idpGroupIdHelp("google")).toMatch(/Admin console|email address/i);
  });

  it("falls back without naming a directory it does not know", () => {
    expect(idpGroupIdHelp("okta")).toMatch(/unique identifier/i);
    expect(idpGroupIdHelp("okta")).not.toMatch(/Entra|Object ID/i);
  });
});

describe("idpErrorCopy", () => {
  it("explains refuse-unless-empty with the way out", () => {
    const c = idpErrorCopy("group_not_empty"); // service.go:253
    expect(c).toMatch(/only an empty group/i);
    expect(c).toMatch(/remove its members first|map to a new group/i);
  });

  it("covers the rest of the service's codes", () => {
    expect(idpErrorCopy("idp_sync_not_configured")).toMatch(/configure/i);
    expect(idpErrorCopy("group_already_synced")).toMatch(/already/i);
    expect(idpErrorCopy("provider_not_supported")).toMatch(/Microsoft Entra/i);
    expect(idpErrorCopy("edition_required")).toMatch(/enterprise/i);
  });

  it("does not invent a diagnosis for an unknown code", () => {
    expect(idpErrorCopy("brand_new")).toBe("Could not complete the request.");
    expect(idpErrorCopy(null)).toBe("Could not complete the request.");
  });
});

// ⛔ S14.12 SHIPPED A SCREEN THAT OFFERED AN ACTION THE SERVER ALWAYS REFUSES.
//
// AddGroupMember answers 409 idp_managed_group — "this group is managed by directory sync;
// members cannot be edited manually" (enterprise/policy/service.go:125). The web read `origin`
// NOWHERE, so Access's GroupRow gated Add/Remove on canManage alone and rendered them on synced
// groups too. Every use was a guaranteed refusal.
describe("isDirectoryManaged", () => {
  it("identifies a directory-owned group", () => {
    expect(isDirectoryManaged({ origin: "idp_sync" })).toBe(true);
  });

  it("⛔ never claims a manual or origin-less group is directory-managed", () => {
    // The direction that matters: a false positive would REMOVE working controls from a group an
    // operator is entitled to edit, which is the same defect pointed the other way.
    expect(isDirectoryManaged({ origin: "manual" })).toBe(false);
    expect(isDirectoryManaged({})).toBe(false);
  });

  it("tells the operator where the membership CAN be changed", () => {
    // A refusal that names no alternative is a dead end.
    expect(DIRECTORY_MANAGED_NOTE).toMatch(/cannot be edited here/i);
    expect(DIRECTORY_MANAGED_NOTE).toMatch(/directory/i);
    expect(DIRECTORY_MANAGED_NOTE).toMatch(/un-map/i);
    expect(DIRECTORY_MANAGED_BADGE).toMatch(/directory/i);
  });
});
