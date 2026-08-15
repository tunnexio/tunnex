//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentProfileEditionGatedInOpenBuild(t *testing.T) {
	orgID := uuid.New()
	deviceID := uuid.New()
	ctx := principalWithRole(orgID, rbac.RoleOwner)
	s := apiServer{}

	if _, err := s.GetAgentProfile(ctx, api.GetAgentProfileRequestObject{OrgId: orgID, DeviceId: deviceID}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open profile GET: want edition_required, got %v", err)
	}
	environment := "production"
	if _, err := s.UpdateAgentProfile(ctx, api.UpdateAgentProfileRequestObject{
		OrgId: orgID, DeviceId: deviceID,
		Body: &api.UpdateAgentProfileRequest{Environment: &environment},
	}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("open profile PATCH: want edition_required, got %v", err)
	}
}
