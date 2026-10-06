package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http/httptest"
	"testing"
)

func TestTerminalManagementChecksHumanAuthorityBeforeService(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		role, method, session, reason string
		verified, wall                bool
	}{{rbac.RoleMember, authctx.AuthLocalPassword, "s", "forbidden", true, false}, {rbac.RoleAdmin, authctx.AuthBearer, "s", "human_session_required", true, false}, {rbac.RoleAdmin, authctx.AuthMachine, "s", "human_session_required", true, false}, {rbac.RoleAdmin, authctx.AuthAgent, "s", "human_session_required", true, false}, {rbac.RoleAdmin, authctx.AuthLocalPassword, "", "human_session_required", true, false}, {rbac.RoleAdmin, authctx.AuthLocalPassword, "s", "email_not_verified", false, false}, {rbac.RoleAdmin, authctx.AuthLocalPassword, "s", "password_change_required", true, true}} {
		p := appAccessPrincipal(org, tc.role)
		p.AuthMethod = tc.method
		p.SessionID = tc.session
		p.EmailVerified = tc.verified
		p.MustChangePassword = tc.wall
		ctx := authctx.WithPrincipal(context.Background(), p)
		s := apiServer{}
		calls := []func() error{func() error {
			_, e := s.UpdateServerAccessSettings(ctx, api.UpdateServerAccessSettingsRequestObject{OrgId: org})
			return e
		}, func() error {
			_, e := s.CreateServerAccessGrant(ctx, api.CreateServerAccessGrantRequestObject{OrgId: org})
			return e
		}, func() error {
			_, e := s.CheckServerAccessServer(ctx, api.CheckServerAccessServerRequestObject{OrgId: org})
			return e
		}}

		calls = append(calls, func() error {
			_, e := s.RemoveServerAccessServer(ctx, api.RemoveServerAccessServerRequestObject{OrgId: org, ServerId: uuid.New()})
			return e
		}, func() error {
			_, e := s.GetServerAccessRecordingArchive(ctx, api.GetServerAccessRecordingArchiveRequestObject{OrgId: org})
			return e
		}, func() error {
			_, e := s.UpdateServerAccessRecordingArchive(ctx, api.UpdateServerAccessRecordingArchiveRequestObject{OrgId: org})
			return e
		}, func() error {
			_, e := s.TestServerAccessRecordingArchive(ctx, api.TestServerAccessRecordingArchiveRequestObject{OrgId: org})
			return e
		})
		for _, call := range calls {
			if e := call(); !hasCode(e, 403, tc.reason) {
				t.Fatalf("role %s method %s authority checked too late: %v", tc.role, tc.method, e)
			}
		}
	}
}

func TestTerminalTimeoutExemptionIsAnExactUpgrade(t *testing.T) {
	base := "/api/v1/organizations/" + uuid.NewString() + "/server-access/sessions/" + uuid.NewString() + "/terminal"
	for _, tc := range []struct {
		method, path, upgrade string
		want                  bool
	}{{"GET", base, "websocket", true}, {"GET", base, "", false}, {"POST", base, "websocket", false}, {"GET", base + "/extra", "websocket", false}, {"GET", "/api/v1/organizations/bad/server-access/sessions/bad/terminal", "websocket", false}} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Upgrade", tc.upgrade)
		if got := isTerminalUpgradeRequest(req); got != tc.want {
			t.Fatalf("%s %s upgrade %s got %v", tc.method, tc.path, tc.upgrade, got)
		}
	}
}

func TestTerminalExportAndDownloadRejectNonHumanAuthorityBeforeService(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		method, session, reason string
		verified, wall          bool
	}{
		{authctx.AuthBearer, "s", "human_session_required", true, false},
		{authctx.AuthMachine, "s", "human_session_required", true, false},
		{authctx.AuthAgent, "s", "human_session_required", true, false},
		{authctx.AuthLocalPassword, "", "human_session_required", true, false},
	} {
		principal := appAccessPrincipal(org, rbac.RoleMember)
		principal.AuthMethod, principal.SessionID = tc.method, tc.session
		principal.EmailVerified, principal.MustChangePassword = tc.verified, tc.wall
		ctx := authctx.WithPrincipal(context.Background(), principal)
		server := apiServer{}
		for _, action := range []func() error{
			func() error {
				_, err := server.ImportServerAccessRecordingPackage(ctx, api.ImportServerAccessRecordingPackageRequestObject{OrgId: org})
				return err
			},
			func() error {
				_, err := server.ExportServerAccessRecordingS3(ctx, api.ExportServerAccessRecordingS3RequestObject{OrgId: org, SessionId: uuid.New()})
				return err
			},
			func() error {
				_, err := server.DownloadServerAccessRecording(ctx, api.DownloadServerAccessRecordingRequestObject{OrgId: org, SessionId: uuid.New()})
				return err
			},
		} {
			if err := action(); !hasCode(err, 403, tc.reason) {
				t.Fatalf("export/download auth method %s checked too late: %v", tc.method, err)
			}
		}
	}
}
