//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentProfilePermissionPrecedesCommunityState(t *testing.T) {
	orgID := uuid.New()
	deviceID := uuid.New()
	ctx := principalWithRole(orgID, rbac.RoleMember)
	s := apiServer{}

	if _, err := s.GetAgentProfile(ctx, api.GetAgentProfileRequestObject{OrgId: orgID, DeviceId: deviceID}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member profile GET must fail permission before state lookup, got %v", err)
	}
	environment := "production"
	if _, err := s.UpdateAgentProfile(ctx, api.UpdateAgentProfileRequestObject{
		OrgId: orgID, DeviceId: deviceID,
		Body: &api.UpdateAgentProfileRequest{Environment: &environment},
	}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member profile PATCH must fail permission before state lookup, got %v", err)
	}
}
