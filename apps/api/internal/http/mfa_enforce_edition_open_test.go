//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Org-level MFA ENFORCE (S7.5.5) is enterprise-only. In the open build mfaEnforceEnabled is false
// (its own NAMED wire file), so an authenticated + authorized owner still gets 403 edition_required
// on the enforce/admin endpoints — server-side enforcement AND the D2 downgrade-release seam (on
// enterprise->open the enforce endpoints refuse; the enrollment gate never engages). authorize()
// runs FIRST (sessionless -> 401, covered by the spec-walk); the edition gate fires for authed callers.
// Self-service ENROLLMENT is NOT gated here — it is OPEN in every edition (tested in internal/mfa).
func TestMfaEnforceEditionGatedInOpenBuild(t *testing.T) {
	s := apiServer{} // open build: mfaEnforceEnabled defaults to false
	org, user := uuid.New(), uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner)

	if _, err := s.GetMfaEnforce(ctx, api.GetMfaEnforceRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("GetMfaEnforce: want 403 edition_required, got %v", err)
	}
	if _, err := s.SetMfaEnforce(ctx, api.SetMfaEnforceRequestObject{OrgId: org, Body: &api.MfaEnforce{Enforce: true}}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("SetMfaEnforce: want 403 edition_required, got %v", err)
	}
	if _, err := s.AdminResetMfa(ctx, api.AdminResetMfaRequestObject{OrgId: org, UserId: user}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("AdminResetMfa: want 403 edition_required, got %v", err)
	}
}

// RBAC deliberate-red: a MEMBER-role caller lacks mfa:manage, so authorize() refuses BEFORE the
// edition gate — 403 forbidden, not edition_required. Proves the enforce/admin surface is
// owner/admin-gated (a member cannot mandate MFA or reset another's factor even in enterprise).
func TestMfaEnforceRefusesMemberRole(t *testing.T) {
	s := apiServer{mfaEnforceEnabled: true} // pretend enterprise so the gate isn't what refuses
	org, user := uuid.New(), uuid.New()
	ctx := principalWithRole(org, rbac.RoleMember)

	if _, err := s.SetMfaEnforce(ctx, api.SetMfaEnforceRequestObject{OrgId: org, Body: &api.MfaEnforce{Enforce: true}}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("SetMfaEnforce member: want 403 forbidden, got %v", err)
	}
	if _, err := s.AdminResetMfa(ctx, api.AdminResetMfaRequestObject{OrgId: org, UserId: user}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("AdminResetMfa member: want 403 forbidden, got %v", err)
	}
}
