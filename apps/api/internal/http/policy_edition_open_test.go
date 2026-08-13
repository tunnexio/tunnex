package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// Zero Trust policy is enterprise-only. In the open build the policy port is nil,
// so an authenticated + authorized owner still gets 403 edition_required —
// server-side enforcement, not merely a hidden UI. authorize() runs FIRST (a
// sessionless request 401s — the spec walk stays honest); the edition gate fires
// for authenticated callers. One read + one mutate + the mode toggle cover the
// three permission classes (PermPolicyView / PermPolicyManage on data + on mode).
func TestPolicyEditionGatedInOpenBuild(t *testing.T) {
	s := apiServer{} // open build: policy port is nil
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner) // authed + verified owner

	if _, err := s.ListGroups(ctx, api.ListGroupsRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("ListGroups: want 403 edition_required, got %v", err)
	}
	if _, err := s.CreateGroup(ctx, api.CreateGroupRequestObject{OrgId: org, Body: &api.CreateGroupJSONRequestBody{Name: "eng"}}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("CreateGroup: want 403 edition_required, got %v", err)
	}
	if _, err := s.ListResources(ctx, api.ListResourcesRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("ListResources: want 403 edition_required, got %v", err)
	}
	if _, err := s.ListPolicyRules(ctx, api.ListPolicyRulesRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("ListPolicyRules: want 403 edition_required, got %v", err)
	}
	if _, err := s.GetZeroTrustMode(ctx, api.GetZeroTrustModeRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("GetZeroTrustMode: want 403 edition_required, got %v", err)
	}
	mode := api.ZeroTrustModeMode("enforcing")
	if _, err := s.SetZeroTrustMode(ctx, api.SetZeroTrustModeRequestObject{OrgId: org, Body: &api.SetZeroTrustModeJSONRequestBody{Mode: mode}}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("SetZeroTrustMode: want 403 edition_required, got %v", err)
	}
}

// A NON-member owner-role principal still 401/404s before the edition gate is even
// reached is covered by the spec 401-walk; here we assert the gate itself is the
// 403 (not a nil-panic) for the authorized caller — i.e. the port nil-check is
// after authorize, mirroring the SSO precedent.
// ⛔ REVERSED (S12.1). This asserted the open build wired NO policy port. There is one binary now and Zero
// Trust is COMMUNITY — it must be wired for everyone. Rewritten rather than deleted: the invariant did not
// disappear, it inverted.
func TestPolicyPortIsAlwaysWired(t *testing.T) {
	if NewPolicyPort(nil, nil) == nil {
		t.Fatal("⛔ the policy port is nil — Zero Trust is Community and must be wired unconditionally. " +
			"A nil port here means the free tier lost the engine that is the reason to choose Tunnex.")
	}
}
