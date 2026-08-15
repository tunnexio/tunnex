package http

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
)

func TestIssueAgentBootstrapMetadataRequiresAuthenticationBeforeReleaseLookup(t *testing.T) {
	org := uuid.New()
	_, err := (apiServer{}).IssueAgentBootstrapToken(context.Background(), api.IssueAgentBootstrapTokenRequestObject{
		OrgId: org,
		Body:  &api.AgentBootstrapTokenRequest{GatewayId: uuid.New(), Name: "agent"},
	})
	if !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("unauthenticated issue: want 401, got %v", err)
	}
}
