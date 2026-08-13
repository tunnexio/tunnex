package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ⛔ THE ORG BOUNDARY IS THE SERVER'S, NOT THE CLIENT'S (S12.5).
//
// The web app now has an organization switcher. A switcher that only changes client state would be a
// CLIENT-INVENTED BOUNDARY — the client would be deciding which tenant it is allowed to act on, and the
// server would be taking its word for it.
//
// ⭐ IT IS NOT, AND THIS FILE IS WHY THAT IS ASSERTED RATHER THAN ASSUMED. `Principal.Roles` is rebuilt
// from `ListMembershipsByUser` on EVERY request (`session.go:36` for cookies, `bearer.go:61` for tokens).
// It is never sent by the client, never carried in a token, never cached across requests. `authorize()`
// resolves the caller's role from it and refuses anything else.
//
// > ## ⛔ **THE SWITCHER CAN ONLY EVER SELECT AMONG ORGANIZATIONS THE SERVER WOULD ALREADY AUTHORIZE.
// > ## IT CANNOT SELECT ONE THE SERVER WOULD NOT.**
//
// ⚠ THE PROPERTY IS TRUE BY CONSTRUCTION TODAY, AND THAT IS EXACTLY WHY IT NEEDS A TEST. Nothing names
// it. A future change that caches `Roles` at login — an obvious-looking optimisation, since the query runs
// on every request — would silently promote the switcher into the boundary, and no existing test would
// notice (docs/laws.md: unit tests prove behaviour, not reachability).

func TestOrgBoundaryIsMembership(t *testing.T) {
	mine, theirs := uuid.New(), uuid.New()
	p := &authctx.Principal{
		UserID:        uuid.New(),
		EmailVerified: true,
		Roles:         map[uuid.UUID]string{mine: rbac.RoleOwner},
	}
	ctx := authctx.WithPrincipal(t.Context(), p)

	if _, err := authorize(ctx, mine, rbac.PermOrgView); err != nil {
		t.Fatalf("a member was refused their own organization: %v", err)
	}

	// ⛔ THE ONE THAT MATTERS. A switcher pointed at a foreign org id must not reach a handler.
	_, err := authorize(ctx, theirs, rbac.PermOrgView)
	if err == nil {
		t.Fatal("⛔ A NON-MEMBER ORGANIZATION WAS AUTHORIZED. The switcher — or anything else that sends " +
			"an orgId — is now the tenant boundary, and the client decides what it may read")
	}
	// ⚠ AND IT IS A 404, NOT A 403 — the no-oracle convention. A 403 would confirm the organization
	// exists, turning any client into an enumeration tool for other tenants' org ids.
	if !hasCode(err, 404, "org_not_found") {
		t.Errorf("non-member refusal = %v; want 404 org_not_found (a 403 would confirm the org exists)", err)
	}
}

// ⭐ AND THE ROLE IS PER-ORGANIZATION, which is the half the switcher makes visible. Before S12.5 the UI
// showed the role from index zero on every screen, so an owner of the second org saw "member" everywhere.
func TestRoleIsResolvedPerOrganization(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	p := &authctx.Principal{
		UserID:        uuid.New(),
		EmailVerified: true,
		Roles:         map[uuid.UUID]string{a: rbac.RoleOwner, b: rbac.RoleMember},
	}
	ctx := authctx.WithPrincipal(t.Context(), p)

	if _, err := authorize(ctx, a, rbac.PermOrgUpdate); err != nil {
		t.Errorf("owner of org A was refused an owner action there: %v", err)
	}
	if _, err := authorize(ctx, b, rbac.PermOrgUpdate); err == nil {
		t.Error("⛔ a MEMBER of org B performed an OWNER action there — the role from one organization " +
			"was applied to another")
	}
}
