package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// A missing policy dependency is an internal availability fault, never a plan
// refusal. Community has the same core Zero Trust policy API as every paid plan.
// authorize() still runs first, preserving the no-oracle ordering.
func TestPolicyServiceUnavailableIsNotAPlanRefusal(t *testing.T) {
	s := apiServer{}
	org := uuid.New()
	ctx := principalWithRole(org, rbac.RoleOwner) // authed + verified owner

	if _, err := s.ListGroups(ctx, api.ListGroupsRequestObject{OrgId: org}); !hasCode(err, 503, "policy_service_unavailable") {
		t.Fatalf("ListGroups: want 503 policy_service_unavailable, got %v", err)
	}
	if _, err := s.CreateGroup(ctx, api.CreateGroupRequestObject{OrgId: org, Body: &api.CreateGroupJSONRequestBody{Name: "eng"}}); !hasCode(err, 503, "policy_service_unavailable") {
		t.Fatalf("CreateGroup: want 503 policy_service_unavailable, got %v", err)
	}
	if _, err := s.ListResources(ctx, api.ListResourcesRequestObject{OrgId: org}); !hasCode(err, 503, "policy_service_unavailable") {
		t.Fatalf("ListResources: want 503 policy_service_unavailable, got %v", err)
	}
	if _, err := s.ListPolicyRules(ctx, api.ListPolicyRulesRequestObject{OrgId: org}); !hasCode(err, 503, "policy_service_unavailable") {
		t.Fatalf("ListPolicyRules: want 503 policy_service_unavailable, got %v", err)
	}
	if _, err := s.GetZeroTrustMode(ctx, api.GetZeroTrustModeRequestObject{OrgId: org}); !hasCode(err, 503, "policy_service_unavailable") {
		t.Fatalf("GetZeroTrustMode: want 503 policy_service_unavailable, got %v", err)
	}
	mode := api.ZeroTrustModeMode("enforcing")
	if _, err := s.SetZeroTrustMode(ctx, api.SetZeroTrustModeRequestObject{OrgId: org, Body: &api.SetZeroTrustModeJSONRequestBody{Mode: mode}}); !hasCode(err, 503, "policy_service_unavailable") {
		t.Fatalf("SetZeroTrustMode: want 503 policy_service_unavailable, got %v", err)
	}
}

// This is deliberately a wiring invariant rather than a plan test. Production
// always injects NewPolicyPort; a nil port must be observable as a service fault.
func TestPolicyPortIsAlwaysWired(t *testing.T) {
	if NewPolicyPort(nil, nil) == nil {
		t.Fatal("⛔ the policy port is nil — Zero Trust is Community and must be wired unconditionally. " +
			"A nil port here means the free tier lost the engine that is the reason to choose Tunnex.")
	}
}
