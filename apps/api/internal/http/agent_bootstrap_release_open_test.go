//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestIssueAgentBootstrapMetadataCommunityReportsOperationalAvailability(t *testing.T) {
	org := uuid.New()
	_, err := (apiServer{}).IssueAgentBootstrapToken(principalWithRole(org, rbac.RoleOwner), api.IssueAgentBootstrapTokenRequestObject{
		OrgId: org,
		Body:  &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "agent"},
	})
	if !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("Community issue must report release availability, got %v", err)
	}
}
