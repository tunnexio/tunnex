package http

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestAgentProfilePermissionBeforeData(t *testing.T) {
	org := uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember},
	})
	if err := (apiServer{}).requireAgentPermission(ctx, org, uuid.New(), rbac.PermAgentViewPrivileged); !hasCode(err, 403, "forbidden") {
		t.Fatalf("permission refusal without a device service: %v", err)
	}
}

func TestAgentProfileGlobalLifecycleAuthority(t *testing.T) {
	for _, status := range []string{"active", "suspended"} {
		if !agentProfileLifecycleAllowed(rbac.RoleAdmin, status) {
			t.Errorf("admin should manage %s", status)
		}
	}
	for _, status := range []string{"pending", "revoked", "bogus"} {
		if agentProfileLifecycleAllowed(rbac.RoleAdmin, status) {
			t.Errorf("admin must not use profile PATCH for %s", status)
		}
	}
	if agentProfileLifecycleAllowed(rbac.RoleMember, "suspended") {
		t.Fatal("member role alone must not grant lifecycle authority; scoped owner/team authority is relational")
	}
}

func TestAgentProfileBodylessPatchIsRejectedBeforeDataLoad(t *testing.T) {
	org := uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{
		UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleMember},
	})
	_, err := (apiServer{}).UpdateAgentProfile(ctx, api.UpdateAgentProfileRequestObject{OrgId: org, DeviceId: uuid.New()})
	if !hasCode(err, 400, "invalid_request") {
		t.Fatalf("bodyless profile PATCH: want invalid_request, got %v", err)
	}
}

func TestAgentProfileLifecycleContractRejectsApprovalAndRevokeStates(t *testing.T) {
	for _, status := range []string{"pending", "revoked", "enrolled", "bogus"} {
		if agentProfileLifecycleAllowed(rbac.RoleAdmin, status) {
			t.Fatalf("profile lifecycle contract must reject %q", status)
		}
	}
}
