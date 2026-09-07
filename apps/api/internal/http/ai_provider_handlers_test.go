package http

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"testing"
)

func TestAIProviderHandlerAuthorization(t *testing.T) {
	org := uuid.New()
	srv := apiServer{}
	for _, tc := range []struct {
		name, role string
		status     int
	}{{"anonymous", "", 401}, {"viewer", "viewer", 403}, {"member", "member", 403}, {"owner", "owner", 503}, {"admin", "admin", 503}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.role != "" {
				ctx = authctx.WithPrincipal(ctx, &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: tc.role}})
			}
			_, err := srv.CreateAIProvider(ctx, api.CreateAIProviderRequestObject{OrgId: org})
			var e *apierr.Error
			if !errors.As(err, &e) || e.Status != tc.status {
				t.Fatalf("authorization before body/availability: %v", err)
			}
		})
	}
	for _, role := range []string{"owner", "admin"} {
		if !rbac.Can(role, rbac.PermAIProviderView) || !rbac.Can(role, rbac.PermAIProviderManage) {
			t.Fatal("missing provider grant")
		}
	}
	if rbac.IsMutating(rbac.PermAIProviderView) || !rbac.IsMutating(rbac.PermAIProviderManage) {
		t.Fatal("provider permission polarity")
	}
}
