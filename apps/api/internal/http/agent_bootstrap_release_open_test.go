//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestIssueAgentBootstrapMetadataOpenEditionRefusesBeforeMutation(t *testing.T) {
	org := uuid.New()
	_, err := (apiServer{}).IssueAgentBootstrapToken(principalWithRole(org, rbac.RoleOwner), api.IssueAgentBootstrapTokenRequestObject{
		OrgId: org,
		Body:  &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "agent"},
	})
	if !hasCode(err, 403, "edition_required") {
		t.Fatalf("open issue: want edition_required, got %v", err)
	}
}
