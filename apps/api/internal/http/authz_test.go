package http

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func principalWithRole(orgID uuid.UUID, role string) context.Context {
	return authctx.WithPrincipal(context.Background(),
		&authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{orgID: role}})
}

func TestAuthorizeRequiresVerifiedForMutations(t *testing.T) {
	org := uuid.New()
	unverified := authctx.WithPrincipal(context.Background(),
		&authctx.Principal{UserID: uuid.New(), EmailVerified: false, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}})

	// Reads are allowed while unverified.
	if _, err := authorize(unverified, org, rbac.PermOrgView); err != nil {
		t.Fatalf("unverified read: unexpected %v", err)
	}
	// Mutations are blocked until verified.
	if _, err := authorize(unverified, org, rbac.PermOrgUpdate); !hasCode(err, 403, "email_not_verified") {
		t.Fatalf("unverified mutation: want email_not_verified, got %v", err)
	}
}

func TestAuthorizeFailClosedAndProgression(t *testing.T) {
	orgA := uuid.New()
	orgB := uuid.New()

	// Unauthenticated -> 401.
	if _, err := authorize(context.Background(), orgA, rbac.PermOrgView); !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("no principal: want 401, got %v", err)
	}

	// Non-member -> 404 (existence not leaked), even for a low permission.
	member := principalWithRole(orgA, rbac.RoleMember)
	if _, err := authorize(member, orgB, rbac.PermOrgView); !hasCode(err, 404, "org_not_found") {
		t.Fatalf("non-member: want 404, got %v", err)
	}

	// Member has view; the authorized org is placed in context.
	ctx, err := authorize(member, orgA, rbac.PermOrgView)
	if err != nil {
		t.Fatalf("member view: unexpected %v", err)
	}
	if got, ok := authctx.OrgFrom(ctx); !ok || got != orgA {
		t.Fatalf("authorized org not in context")
	}

	// Member lacks update -> 403 (they ARE a member, so not 404).
	if _, err := authorize(member, orgA, rbac.PermOrgUpdate); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member update: want 403, got %v", err)
	}
}

func TestAuthorizePermissionByRole(t *testing.T) {
	org := uuid.New()
	cases := []struct {
		role string
		perm rbac.Permission
		ok   bool
	}{
		{rbac.RoleMember, rbac.PermOrgView, true},
		{rbac.RoleMember, rbac.PermOrgUpdate, false},
		{rbac.RoleMember, rbac.PermOrgDelete, false},
		{rbac.RoleAdmin, rbac.PermOrgUpdate, true},
		{rbac.RoleAdmin, rbac.PermOrgDelete, false},
		{rbac.RoleOwner, rbac.PermOrgDelete, true},
	}
	for _, c := range cases {
		_, err := authorize(principalWithRole(org, c.role), org, c.perm)
		if c.ok && err != nil {
			t.Errorf("%s/%s: want allow, got %v", c.role, c.perm, err)
		}
		if !c.ok && !hasCode(err, 403, "forbidden") {
			t.Errorf("%s/%s: want 403 forbidden, got %v", c.role, c.perm, err)
		}
	}
}

func hasCode(err error, status int, code string) bool {
	var apiErr *apierr.Error
	return errors.As(err, &apiErr) && apiErr.Status == status && apiErr.Code == code
}
