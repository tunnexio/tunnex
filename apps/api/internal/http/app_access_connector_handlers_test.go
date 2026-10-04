package http

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type appAccessCheckRecorder struct{ appAccessRecorder }

func (f *appAccessCheckRecorder) RequestCheck(_ context.Context, org, actor, app uuid.UUID, version int64, entitled bool) (appaccess.Check, error) {
	f.calls++
	f.org = org
	f.actor = actor
	f.version = version
	f.entitled = entitled
	return appaccess.Check{ID: uuid.New(), OrgID: org, AppID: app, GatewayID: uuid.New(), Generation: uuid.New(), Revision: 1, Digest: strings.Repeat("a", 64), Purpose: "origin_check", Status: "queued", CreatedAt: time.Now(), Deadline: time.Now().Add(10 * time.Second), DNSStatus: "pending", ConnectStatus: "pending", TLSStatus: "pending", ErrorCode: ""}, f.err
}
func (f *appAccessCheckRecorder) GetCheck(ctx context.Context, org, app, id uuid.UUID) (appaccess.Check, error) {
	return f.RequestCheck(ctx, org, uuid.Nil, app, 1, false)
}
func (f *appAccessCheckRecorder) GetGatewayRuntime(_ context.Context, org, gateway uuid.UUID) (appaccess.GatewayRuntime, error) {
	f.calls++
	return appaccess.GatewayRuntime{OrgID: org, GatewayID: gateway, Status: "unknown"}, f.err
}
func TestAppAccessCheckAuthorityBeforeCapabilityAndEntitlement(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name, role, method string
		verified           bool
		want               int
	}{
		{"member", rbac.RoleMember, authctx.AuthLocalPassword, true, 403},
		{"unverified", rbac.RoleOwner, authctx.AuthLocalPassword, false, 403},
		{"bearer", rbac.RoleOwner, authctx.AuthBearer, true, 403},
		{"machine", rbac.RoleOwner, authctx.AuthMachine, true, 403},
		{"community", rbac.RoleOwner, authctx.AuthLocalPassword, true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := &appAccessCheckRecorder{}
			server := apiServer{appAccess: port}
			p := appAccessPrincipal(org, tc.role)
			p.AuthMethod = tc.method
			p.EmailVerified = tc.verified
			_, err := server.RequestAppAccessCheck(authctx.WithPrincipal(context.Background(), p), api.RequestAppAccessCheckRequestObject{OrgId: org, AppId: uuid.New(), Body: &api.AppAccessCheckInput{ExpectedVersion: 1}})
			var out *apierr.Error
			ok := errors.As(err, &out)
			if !ok || out.Status != tc.want || port.calls != 0 {
				t.Fatalf("err%v calls%d", err, port.calls)
			}
		})
	}
}
func TestAppAccessCheckHistoryAndUnknownGatewaySurviveLoss(t *testing.T) {
	org, gateway := uuid.New(), uuid.New()
	port := &appAccessCheckRecorder{}
	server := apiServer{appAccess: port}
	ctx := authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, rbac.RoleOwner))
	_, err := server.GetAppAccessCheck(ctx, api.GetAppAccessCheckRequestObject{OrgId: org, AppId: uuid.New(), CheckId: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.GetAppAccessGatewayStatus(ctx, api.GetAppAccessGatewayStatusRequestObject{OrgId: org, GatewayId: gateway})
	if err != nil {
		t.Fatal(err)
	}
	result := response.(api.GetAppAccessGatewayStatus200JSONResponse)
	if result.Body.Status != "unknown" || result.Body.ReportedAt != nil || result.Body.CapabilityVersion != 0 {
		t.Fatalf("fabricated readiness %#v", result.Body)
	}
}
