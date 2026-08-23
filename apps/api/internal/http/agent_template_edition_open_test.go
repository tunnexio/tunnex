package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentTemplatesPermissionPrecedesServiceAvailability(t *testing.T) {
	org := uuid.New()
	owner := principalWithRole(org, rbac.RoleOwner)
	member := principalWithRole(org, rbac.RoleMember)
	s := apiServer{}
	if _, err := s.ListAgentGroups(owner, api.ListAgentGroupsRequestObject{OrgId: org}); !hasCode(err, 503, "agent_templates_unavailable") {
		t.Fatalf("authorized owner: want service-unavailable, got %v", err)
	}
	if _, err := s.ListAgentGroups(member, api.ListAgentGroupsRequestObject{OrgId: org}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unauthorized member: permission must precede service availability, got %v", err)
	}
}

func TestAgentTemplatePortIsPresentInOneBinary(t *testing.T) {
	if NewAgentTemplatePort(nil, nil) == nil {
		t.Fatal("agent template port must be wired in the single binary")
	}
}
