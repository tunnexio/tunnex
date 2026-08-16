//go:build !enterprise

package http

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentTemplatesEditionGatedAfterPermission(t *testing.T) {
	org := uuid.New()
	owner := principalWithRole(org, rbac.RoleOwner)
	member := principalWithRole(org, rbac.RoleMember)
	s := apiServer{}
	if _, err := s.ListAgentGroups(owner, api.ListAgentGroupsRequestObject{OrgId: org}); !hasCode(err, 403, "edition_required") {
		t.Fatalf("authorized owner: want edition_required, got %v", err)
	}
	if _, err := s.ListAgentGroups(member, api.ListAgentGroupsRequestObject{OrgId: org}); !hasCode(err, 403, "forbidden") {
		t.Fatalf("unauthorized member: permission must precede edition, got %v", err)
	}
}

func TestAgentTemplatePortIsAbsentInOpenBuild(t *testing.T) {
	if NewAgentTemplatePort(nil, nil) != nil {
		t.Fatal("F09 enterprise port must be absent in the open build")
	}
}
