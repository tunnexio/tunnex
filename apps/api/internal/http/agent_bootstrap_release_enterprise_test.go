//go:build enterprise

package http

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestIssueAgentBootstrapMetadataEnterpriseRefusesWithoutVerifiedDescriptor(t *testing.T) {
	org := uuid.New()
	s := apiServer{policy: NewPolicyPort(nil, nil), licence: licence.NewTestManager("scale", time.Now().Add(time.Hour))}
	_, err := s.IssueAgentBootstrapToken(principalWithRole(org, rbac.RoleOwner), api.IssueAgentBootstrapTokenRequestObject{
		OrgId: org,
		Body:  &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "agent"},
	})
	if !hasCode(err, 503, "bootstrap_unavailable") {
		t.Fatalf("enterprise missing descriptor: want bootstrap_unavailable, got %v", err)
	}
}
