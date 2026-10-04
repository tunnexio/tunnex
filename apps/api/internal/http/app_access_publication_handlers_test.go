package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"testing"
)

func TestAppAccessPublicationHumanManageBeforeService(t *testing.T) {
	org := uuid.New()
	app := uuid.New()
	for _, tc := range []struct {
		name, role, method, session, reason string
		verified, wall                      bool
	}{
		{"member", rbac.RoleMember, authctx.AuthLocalPassword, "s", "forbidden", true, false},
		{"unverified", rbac.RoleOwner, authctx.AuthLocalPassword, "s", "email_not_verified", false, false},
		{"password wall", rbac.RoleOwner, authctx.AuthLocalPassword, "s", "password_change_required", true, true},
		{"machine", rbac.RoleOwner, authctx.AuthMachine, "s", "human_session_required", true, false},
		{"agent", rbac.RoleOwner, authctx.AuthAgent, "s", "human_session_required", true, false},
		{"bearer", rbac.RoleOwner, authctx.AuthBearer, "s", "human_session_required", true, false},
		{"no parent", rbac.RoleOwner, authctx.AuthLocalPassword, "", "human_session_required", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := appAccessPrincipal(org, tc.role)
			p.AuthMethod = tc.method
			p.SessionID = tc.session
			p.EmailVerified = tc.verified
			p.MustChangePassword = tc.wall
			ctx := authctx.WithPrincipal(context.Background(), p)
			s := apiServer{}
			methods := []func() error{
				func() error {
					_, e := s.CreateAppAccessPublicationOperation(ctx, api.CreateAppAccessPublicationOperationRequestObject{OrgId: org, AppId: app})
					return e
				},
				func() error {
					_, e := s.CancelAppAccessPublicationOperation(ctx, api.CancelAppAccessPublicationOperationRequestObject{OrgId: org, AppId: app})
					return e
				},
				func() error {
					_, e := s.DisableAppAccessPublication(ctx, api.DisableAppAccessPublicationRequestObject{OrgId: org, AppId: app})
					return e
				},
				func() error {
					_, e := s.RollbackAppAccessDraft(ctx, api.RollbackAppAccessDraftRequestObject{OrgId: org, AppId: app})
					return e
				},
				func() error {
					_, e := s.ArchiveAppAccessApplication(ctx, api.ArchiveAppAccessApplicationRequestObject{OrgId: org, AppId: app})
					return e
				},
			}
			for _, method := range methods {
				if err := method(); !hasCode(err, 403, tc.reason) {
					t.Fatalf("authority not checked first: %v", err)
				}
			}
		})
	}
}
