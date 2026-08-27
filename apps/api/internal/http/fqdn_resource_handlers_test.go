package http

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func TestFQDNEnableChecksPermissionBeforeEntitlement(t *testing.T) {
	org := uuid.New()
	req := api.SetFQDNResourceEnabledRequestObject{OrgId: org, Body: &api.FQDNResourceSetting{Enabled: true}}
	s := apiServer{}
	_, err := s.SetFQDNResourceEnabled(context.Background(), req)
	if !hasCode(err, 401, "unauthenticated") {
		t.Fatalf("anonymous error = %v", err)
	}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}})
	_, err = s.SetFQDNResourceEnabled(ctx, req)
	if !hasCode(err, 403, "entitlement_required") {
		t.Fatalf("owner unentitled error = %v", err)
	}
}
