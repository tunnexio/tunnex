package http

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type crossGatewayStore struct {
	calls   int
	org     uuid.UUID
	enabled bool
	err     error
}

func (s *crossGatewayStore) SetCrossGatewayClientsEnabled(ctx context.Context, org uuid.UUID, enabled bool) (sqlc.Organization, error) {
	s.calls++
	s.org = org
	s.enabled = enabled
	return sqlc.Organization{ID: org, CrossGatewayClientsEnabled: enabled}, s.err
}

func TestCrossGatewaySettingPermissionAndTenantBoundary(t *testing.T) {
	org := uuid.New()
	req := api.SetCrossGatewayClientsEnabledRequestObject{OrgId: org, Body: &api.CrossGatewaySetting{Enabled: true}}
	for _, tc := range []struct {
		name, role string
		verified   bool
		code       int
		errorCode  string
	}{
		{"anonymous", "", false, 401, "unauthenticated"},
		{"member", rbac.RoleMember, true, 403, "forbidden"},
		{"other_org", rbac.RoleOwner, true, 404, "org_not_found"},
		{"unverified_owner", rbac.RoleOwner, false, 403, "email_not_verified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &crossGatewayStore{}
			notify := &fqdnSettingNotifyRecorder{}
			server := apiServer{crossGatewaySettings: store, crossGatewaySettingsNotify: notify}
			ctx := context.Background()
			if tc.role != "" {
				target := org
				if tc.name == "other_org" {
					target = uuid.New()
				}
				ctx = authctx.WithPrincipal(ctx, &authctx.Principal{UserID: uuid.New(), EmailVerified: tc.verified, Roles: map[uuid.UUID]string{target: tc.role}})
			}
			_, err := server.SetCrossGatewayClientsEnabled(ctx, req)
			if !hasCode(err, tc.code, tc.errorCode) || store.calls != 0 || len(notify.orgs) != 0 {
				t.Fatalf("permission boundary: err=%v calls=%d wake=%v", err, store.calls, notify.orgs)
			}
		})
	}
}

func TestCrossGatewaySettingWakesOnlyAfterCommit(t *testing.T) {
	org := uuid.New()
	store := &crossGatewayStore{}
	notify := &fqdnSettingNotifyRecorder{}
	server := apiServer{crossGatewaySettings: store, crossGatewaySettingsNotify: notify}
	ctx := authctx.WithPrincipal(context.Background(), &authctx.Principal{UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{org: rbac.RoleOwner}})
	for _, enabled := range []bool{true, false} {
		out, err := server.SetCrossGatewayClientsEnabled(ctx, api.SetCrossGatewayClientsEnabledRequestObject{OrgId: org, Body: &api.CrossGatewaySetting{Enabled: enabled}})
		if err != nil {
			t.Fatal(err)
		}
		response := out.(api.SetCrossGatewayClientsEnabled200JSONResponse)
		if response.Body.Enabled != enabled || store.org != org || notify.orgs[len(notify.orgs)-1] != org {
			t.Fatal("setting or tenant lost on commit")
		}
	}
	store.err = errors.New("audit transaction failed")
	_, err := server.SetCrossGatewayClientsEnabled(ctx, api.SetCrossGatewayClientsEnabledRequestObject{OrgId: org, Body: &api.CrossGatewaySetting{Enabled: true}})
	if err == nil || len(notify.orgs) != 2 {
		t.Fatal("failed persistence must not wake gateways")
	}
}
