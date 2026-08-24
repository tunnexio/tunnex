//go:build !enterprise

package http

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentJITAccessPermissionBeforeFeature(t *testing.T) {
	org, owner, member := uuid.New(), uuid.New(), uuid.New()
	with := func(user uuid.UUID, role string) context.Context {
		return authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: user, EmailVerified: true, Roles: map[uuid.UUID]string{org: role}})
	}
	s := apiServer{}
	setting := api.SetOrganizationAgentJITAccessEnabledRequestObject{OrgId: org, Body: &api.SetAgentJITAccessSettingRequest{Enabled: true}}
	if _, err := s.SetOrganizationAgentJITAccessEnabled(with(member, rbac.RoleMember), setting); !hasCode(err, 403, "forbidden") {
		t.Fatalf("member must fail permission before plan capability: %v", err)
	}
	if _, err := s.SetOrganizationAgentJITAccessEnabled(with(owner, rbac.RoleOwner), setting); !hasCode(err, 403, "feature_required") {
		t.Fatalf("owner must reach plan capability gate: %v", err)
	}
	body := &api.CreateAgentAccessRequest{
		DeviceId: uuid.New(), DestinationKind: "resource", DestinationId: uuid.New(),
		Reason: "incident response", DurationSeconds: 3600, IdempotencyKey: "open-create",
	}
	if _, err := s.CreateAgentAccessRequest(with(owner, rbac.RoleOwner), api.CreateAgentAccessRequestRequestObject{OrgId: org, Body: body}); !hasCode(err, 403, "feature_required") {
		t.Fatalf("authorized create must reach plan capability gate: %v", err)
	}
}
