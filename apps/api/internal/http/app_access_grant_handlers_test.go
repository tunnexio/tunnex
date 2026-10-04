package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"testing"
)

func TestAppAccessGrantPermissionBeforeEntitlement(t *testing.T) {
	org := uuid.New()
	grant := uuid.New()
	for _, tc := range []struct {
		name, role, method, session string
		verified                    bool
		code                        int
		reason                      string
	}{
		{"member", rbac.RoleMember, authctx.AuthLocalPassword, "s", true, 403, "forbidden"},
		{"unverified", rbac.RoleOwner, authctx.AuthLocalPassword, "s", false, 403, "email_not_verified"},
		{"bearer", rbac.RoleOwner, authctx.AuthBearer, "s", true, 403, "human_session_required"},
		{"machine", rbac.RoleOwner, authctx.AuthMachine, "s", true, 403, "human_session_required"},
		{"no cookie", rbac.RoleOwner, authctx.AuthLocalPassword, "", true, 403, "human_session_required"},
		{"paid denied", rbac.RoleOwner, authctx.AuthLocalPassword, "s", true, 403, "entitlement_required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := appAccessPrincipal(org, tc.role)
			p.AuthMethod = tc.method
			p.SessionID = tc.session
			p.EmailVerified = tc.verified
			ctx := authctx.WithPrincipal(context.Background(), p)
			f := &appAccessRecorder{}
			s := apiServer{appAccess: f}
			_, err := s.UpdateAppAccessGrant(ctx, api.UpdateAppAccessGrantRequestObject{OrgId: org, GrantId: grant, Body: &api.AppAccessGrantUpdateInput{Enabled: true, ExpectedVersion: 1}})
			if !hasCode(err, tc.code, tc.reason) || f.calls != 0 {
				t.Fatalf("want%s got%v calls%d", tc.reason, err, f.calls)
			}
		})
	}
}
func TestAppAccessGrantReadDisableRevokeSurviveLoss(t *testing.T) {
	org, id := uuid.New(), uuid.New()
	p := appAccessPrincipal(org, rbac.RoleOwner)
	ctx := authctx.WithPrincipal(context.Background(), p)
	f := &appAccessRecorder{}
	s := apiServer{appAccess: f}
	got, err := s.ListAppAccessGrants(ctx, api.ListAppAccessGrantsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	if got.(api.ListAppAccessGrants200JSONResponse).Body.Items == nil {
		t.Fatal("nil array projection")
	}
	_, err = s.UpdateAppAccessGrant(ctx, api.UpdateAppAccessGrantRequestObject{OrgId: org, GrantId: id, Body: &api.AppAccessGrantUpdateInput{Enabled: false, ExpectedVersion: 1}})
	if err != nil || f.enabled || f.entitled || f.org != org || f.actor != p.UserID {
		t.Fatal("lapse disable failed", err)
	}
	_, err = s.RevokeAppAccessGrant(ctx, api.RevokeAppAccessGrantRequestObject{OrgId: org, GrantId: id, Body: &api.AppAccessGrantRevokeInput{ExpectedVersion: 2}})
	if err != nil || f.version != 2 {
		t.Fatal("lapse revoke failed", err)
	}
	preview, err := s.PreviewAppAccessEffectiveAccess(ctx, api.PreviewAppAccessEffectiveAccessRequestObject{OrgId: org, AppId: uuid.New(), Body: &api.AppAccessEffectiveAccessInput{UserId: p.UserID}})
	if err != nil {
		t.Fatal(err)
	}
	decision := preview.(api.PreviewAppAccessEffectiveAccess200JSONResponse).Body
	if !decision.GrantMatch || bool(decision.AccessAllowed) || decision.DenyReason != "app_unpublished" || decision.MatchingGrantIds == nil {
		t.Fatalf("false publication/session proof %#v", decision)
	}
	impact, err := s.GetAppAccessGrantRevokeImpact(ctx, api.GetAppAccessGrantRevokeImpactRequestObject{OrgId: org, GrantId: id})
	if err != nil {
		t.Fatal(err)
	}
	counts := impact.(api.GetAppAccessGrantRevokeImpact200JSONResponse).Body
	if bool(counts.SessionImpactAvailable) || counts.MatchingUserCount != 2 || counts.UsersLosingGrantMatchCount != 1 {
		t.Fatalf("incorrect impact %#v", counts)
	}
}
func TestAppAccessGrantFilterAndVersionValidation(t *testing.T) {
	org, id := uuid.New(), uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, rbac.RoleOwner))
	f := &appAccessRecorder{}
	s := apiServer{appAccess: f}
	_, err := s.ListAppAccessGrants(ctx, api.ListAppAccessGrantsRequestObject{OrgId: org, Params: api.ListAppAccessGrantsParams{SubjectId: &id}})
	if !hasCode(err, 400, "invalid_grant_filter") || f.calls != 0 {
		t.Fatal("subject filter without kind accepted")
	}
	huge := int(1 << 40)
	_, err = s.ListAppAccessGrants(ctx, api.ListAppAccessGrantsRequestObject{OrgId: org, Params: api.ListAppAccessGrantsParams{Offset: &huge}})
	if !hasCode(err, 400, "invalid_grant_filter") {
		t.Fatal("filter cast overflow")
	}
	_, err = s.RevokeAppAccessGrant(ctx, api.RevokeAppAccessGrantRequestObject{OrgId: org, GrantId: id, Body: &api.AppAccessGrantRevokeInput{ExpectedVersion: 0}})
	if !hasCode(err, 400, "invalid_version") || f.calls != 0 {
		t.Fatal("zero version allowed")
	}
}
