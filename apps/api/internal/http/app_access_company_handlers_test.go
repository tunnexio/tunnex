package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type companyRecorder struct {
	appAccessRecorder
	app     uuid.UUID
	company appaccess.CompanyApps
	managed appaccess.ManagedApps
}

func (f *companyRecorder) record(org, actor, app uuid.UUID) {
	f.calls++
	f.org = org
	f.actor = actor
	f.app = app
}
func (f *companyRecorder) GetAccessManagement(_ context.Context, org, actor, app uuid.UUID) (appaccess.AccessManagement, error) {
	f.record(org, actor, app)
	return appaccess.AccessManagement{AppID: app, Version: 1}, f.err
}
func (f *companyRecorder) UpdateAccessManagement(_ context.Context, org, actor, app uuid.UUID, v bool, u *uuid.UUID, version int64) (appaccess.AccessManagement, error) {
	f.record(org, actor, app)
	return appaccess.AccessManagement{AppID: app, Version: version + 1, CatalogVisible: v, AppAdminUserID: u}, f.err
}
func (f *companyRecorder) CompanyApps(_ context.Context, org, actor uuid.UUID, _ string, _ string, _, _ int32, _ bool) (appaccess.CompanyApps, error) {
	f.record(org, actor, uuid.Nil)
	return f.company, f.err
}
func (f *companyRecorder) ManagedApps(_ context.Context, org, actor uuid.UUID, app *uuid.UUID, _, _ int32) (appaccess.ManagedApps, error) {
	id := uuid.Nil
	if app != nil {
		id = *app
	}
	f.record(org, actor, id)
	return f.managed, f.err
}
func (f *companyRecorder) AccessRequests(_ context.Context, org, actor uuid.UUID, _ bool, _ string, _ *uuid.UUID, _, _ int32) (appaccess.AccessRequests, error) {
	f.record(org, actor, uuid.Nil)
	return appaccess.AccessRequests{Items: []appaccess.AccessRequest{}}, f.err
}
func (f *companyRecorder) CreateAccessRequest(_ context.Context, org, actor, app uuid.UUID, _ string, _ bool) (appaccess.AccessRequest, error) {
	f.record(org, actor, app)
	return appaccess.AccessRequest{ID: uuid.New(), AppID: app, Status: "pending", Version: 1}, f.err
}
func (f *companyRecorder) DecideAccessRequest(_ context.Context, org, actor, id uuid.UUID, in appaccess.AccessDecision, _ bool) (appaccess.AccessRequest, error) {
	f.record(org, actor, id)
	return appaccess.AccessRequest{ID: id, Status: in.Decision, Version: in.ExpectedVersion + 1}, f.err
}
func (f *companyRecorder) GrantSubjects(_ context.Context, org, actor, app uuid.UUID, _, _ string, _, _ int32) ([]appaccess.GrantSubject, error) {
	f.record(org, actor, app)
	return []appaccess.GrantSubject{}, f.err
}
func (f *companyRecorder) ManagedGrants(_ context.Context, org, actor, app uuid.UUID, _, _ int32, _ ...appaccess.GrantListFilter) ([]appaccess.Grant, error) {
	f.record(org, actor, app)
	return []appaccess.Grant{}, f.err
}
func (f *companyRecorder) CreateManagedGrant(_ context.Context, org, actor, app uuid.UUID, in appaccess.GrantInput, _ bool) (appaccess.Grant, error) {
	f.record(org, actor, app)
	return appaccess.Grant{AppID: in.AppID, SubjectID: in.SubjectID, SubjectKind: in.SubjectKind, Version: 1}, f.err
}
func (f *companyRecorder) UpdateManagedGrant(_ context.Context, org, actor, app, id uuid.UUID, _ appaccess.GrantUpdate, _ int64, _ bool) (appaccess.Grant, error) {
	f.record(org, actor, app)
	return appaccess.Grant{ID: id, AppID: app}, f.err
}
func (f *companyRecorder) RevokeManagedGrant(_ context.Context, org, actor, app, id uuid.UUID, _ int64) (appaccess.Grant, error) {
	f.record(org, actor, app)
	return appaccess.Grant{ID: id, AppID: app}, f.err
}
func TestCompanyHTTPManagementAndProjection(t *testing.T) {
	org, app := uuid.New(), uuid.New()
	f := &companyRecorder{company: appaccess.CompanyApps{Availability: "available", Items: []appaccess.CompanyApp{
		{MyApp: appaccess.MyApp{ID: app, Name: "Visible", LaunchURL: "https://must-not-disclose.example", RequireMFA: true}, AccessGranted: false},
		{MyApp: appaccess.MyApp{ID: uuid.New(), Name: "Granted", LaunchURL: "https://granted.apps.fixture.test/__tunnex_app/start", RequireMFA: true, MFARequired: true, MFASetupRequired: true}, AccessGranted: true},
	}}}
	s := apiServer{appAccess: f}
	p := appAccessPrincipal(org, rbac.RoleMember)
	ctx := authctx.WithPrincipal(context.Background(), p)
	out, err := s.ListCompanyApps(ctx, api.ListCompanyAppsRequestObject{OrgId: org})
	if err != nil {
		t.Fatal(err)
	}
	response := out.(api.ListCompanyApps200JSONResponse)
	if response.Headers.CacheControl != "no-store" || response.Body.Items[0].LaunchUrl != nil || response.Body.Items[0].AccessGranted || response.Body.Items[1].LaunchUrl == nil || !response.Body.Items[1].MfaRequired {
		t.Fatal("grant/MFA/redaction projection", response)
	}
	raw, err := json.Marshal(response.Body.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"must-not-disclose", "origin_url", "gateway_id", "public_hostname", "origin_ca", "allowed_destination"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("member DTO leaked", secret)
		}
	}
	before := f.calls
	_, err = s.UpdateAppAccessManagement(ctx, api.UpdateAppAccessManagementRequestObject{OrgId: org, AppId: app, Body: &api.AppAccessAccessManagementInput{ExpectedVersion: 1}})
	if !hasCode(err, 403, "forbidden") || f.calls != before {
		t.Fatal("member could assign", err)
	}
	p = appAccessPrincipal(org, rbac.RoleAdmin)
	p.CPAdmin = false
	_, err = s.UpdateAppAccessManagement(authctx.WithPrincipal(context.Background(), p), api.UpdateAppAccessManagementRequestObject{OrgId: org, AppId: app, Body: &api.AppAccessAccessManagementInput{ExpectedVersion: 1}})
	if err != nil || f.actor != p.UserID || f.org != org || f.app != app {
		t.Fatal("existing org admin authority lost", err)
	}
	for _, method := range []string{authctx.AuthBearer, authctx.AuthMachine, authctx.AuthAgent} {
		p = appAccessPrincipal(org, rbac.RoleOwner)
		p.AuthMethod = method
		before = f.calls
		_, err = s.ListManagedAppAccessApps(authctx.WithPrincipal(context.Background(), p), api.ListManagedAppAccessAppsRequestObject{OrgId: org})
		if !hasCode(err, 403, "human_session_required") || f.calls != before {
			t.Fatal("non-browser inherited scope", method, err)
		}
	}
}
func TestCompanyHTTPGeneratedRoutesSecurity(t *testing.T) {
	org, app, grant, request := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	f := &companyRecorder{company: appaccess.CompanyApps{Availability: "available", Items: []appaccess.CompanyApp{}}}
	router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AppAccess: f, AppBaseURL: "https://internal.tunnex.app", AuthFn: func(r *http.Request) *authctx.Principal {
		cookie, err := r.Cookie("__Host-tunnex_session")
		if err != nil {
			return nil
		}
		return appAccessPrincipal(org, cookie.Value)
	}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/api/v1/organizations/" + org.String() + "/app-access"
	routes := []struct {
		method, path, body, role string
		want                     int
	}{
		{"GET", "/company-apps", "", rbac.RoleMember, 200},
		{"GET", "/managed-apps?app_id=" + app.String(), "", rbac.RoleMember, 200},
		{"GET", "/access-requests?scope=managed", "", rbac.RoleMember, 200},
		{"GET", "/applications/" + app.String() + "/access-management", "", rbac.RoleMember, 403},
		{"GET", "/applications/" + app.String() + "/access-management", "", rbac.RoleAdmin, 200},
		{"PATCH", "/applications/" + app.String() + "/access-management", "{\"expected_version\":1,\"catalog_visible\":false,\"app_admin_user_id\":null}", rbac.RoleAdmin, 200},
		{"POST", "/applications/" + app.String() + "/access-requests", "{}", rbac.RoleMember, 200},
		{"POST", "/access-requests/" + request.String() + "/decision", "{\"expected_version\":1,\"decision\":\"approved\",\"expires_at\":null}", rbac.RoleMember, 200},
		{"GET", "/applications/" + app.String() + "/grant-subjects?kind=user", "", rbac.RoleMember, 200},
		{"GET", "/applications/" + app.String() + "/managed-grants", "", rbac.RoleMember, 200},
		{"POST", "/applications/" + app.String() + "/managed-grants", "{\"app_id\":\"" + app.String() + "\",\"subject_kind\":\"user\",\"subject_id\":\"" + uuid.NewString() + "\",\"enabled\":true,\"starts_at\":null,\"expires_at\":null}", rbac.RoleMember, 200},
		{"PATCH", "/applications/" + app.String() + "/managed-grants/" + grant.String(), "{\"expected_version\":1,\"enabled\":false,\"starts_at\":null,\"expires_at\":null}", rbac.RoleMember, 200},
		{"POST", "/applications/" + app.String() + "/managed-grants/" + grant.String() + "/revoke", "{\"expected_version\":1}", rbac.RoleMember, 200},
		{"GET", "/grants", "", rbac.RoleMember, 403},
		{"GET", "/applications/" + app.String(), "", rbac.RoleMember, 403},
	}
	for _, route := range routes {
		t.Run(route.method+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, "https://internal.tunnex.app"+prefix+route.path, strings.NewReader(route.body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: route.role})
			req.Header.Set("Origin", "https://internal.tunnex.app")
			req.Header.Set("X-Tunnex-CSRF", "1")
			out := httptest.NewRecorder()
			router.ServeHTTP(out, req)
			if out.Code != route.want {
				t.Fatalf("status%d want%d: %s", out.Code, route.want, out.Body.String())
			}
		})
	}
	for _, tc := range []struct {
		name, cookie, origin string
		csrf                 bool
		want                 int
	}{
		{"no session", "", "https://internal.tunnex.app", true, 401},
		{"no CSRF", rbac.RoleMember, "https://internal.tunnex.app", false, 403},
		{"sibling origin", rbac.RoleMember, "https://wiki.internal.tunnex.app", true, 403},
		{"null origin", rbac.RoleMember, "null", true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := f.calls
			req := httptest.NewRequest("POST", "https://internal.tunnex.app"+prefix+"/applications/"+app.String()+"/access-requests", strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", tc.origin)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: tc.cookie})
			}
			if tc.csrf {
				req.Header.Set("X-Tunnex-CSRF", "1")
			}
			out := httptest.NewRecorder()
			router.ServeHTTP(out, req)
			if out.Code != tc.want || f.calls != before {
				t.Fatalf("unsafe route status%d want%d calls%d", out.Code, tc.want, f.calls-before)
			}
		})
	}
}

// Exercise the actual generated HTTP route. Persisted permission evaluation is
// covered by TestCompanyManagedNavigationPermissionsLocalDatabase.
func TestCompanyHTTPManagedNavigationCapabilities(t *testing.T) {
	org, app := uuid.New(), uuid.New()
	for _, tc := range []struct {
		name, sessionRole              string
		view, grant, assigned, cpAdmin bool
	}{
		{"organization administrator", rbac.RoleAdmin, true, true, false, false},
		{"ordinary member", rbac.RoleMember, false, false, false, false},
		{"assigned App admin", rbac.RoleMember, false, false, true, false},
		{"installation flag adds no org capability", rbac.RoleMember, false, false, false, true},
		{"stale admin session uses current service result", rbac.RoleAdmin, false, false, false, true},
		{"promoted member session uses current service result", rbac.RoleMember, true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &companyRecorder{managed: appaccess.ManagedApps{Items: []appaccess.ManagedApp{}, CanViewApplications: tc.view, CanManageGrants: tc.grant}}
			if tc.assigned {
				f.managed.Items = append(f.managed.Items, appaccess.ManagedApp{ID: app, Name: "Assigned app"})
			}
			principal := appAccessPrincipal(org, tc.sessionRole)
			principal.CPAdmin = tc.cpAdmin
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AppAccess: f, AppBaseURL: "https://internal.tunnex.app", AuthFn: func(r *http.Request) *authctx.Principal {
				if _, err := r.Cookie("__Host-tunnex_session"); err != nil {
					return nil
				}
				return principal
			}})
			if err != nil {
				t.Fatal(err)
			}
			for _, attempt := range []struct {
				name    string
				org     uuid.UUID
				session bool
				want    int
			}{
				{"current organization", org, true, 200},
				{"no session", org, false, 401},
				{"other organization", uuid.New(), true, 404},
			} {
				t.Run(attempt.name, func(t *testing.T) {
					before := f.calls
					req := httptest.NewRequest("GET", "https://internal.tunnex.app/api/v1/organizations/"+attempt.org.String()+"/app-access/managed-apps?limit=1", nil)
					if attempt.session {
						req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: "own-session"})
					}
					out := httptest.NewRecorder()
					router.ServeHTTP(out, req)
					if out.Code != attempt.want {
						t.Fatalf("status=%d want=%d body=%s", out.Code, attempt.want, out.Body.String())
					}
					if attempt.want != 200 {
						if f.calls != before || strings.Contains(out.Body.String(), "can_view_applications") || strings.Contains(out.Body.String(), "can_manage_grants") {
							t.Fatal("capabilities escaped authentication/organization scope")
						}
						return
					}
					if out.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("capabilities must not be cached")
					}
					var body struct {
						CanViewApplications *bool                     `json:"can_view_applications"`
						CanManageGrants     *bool                     `json:"can_manage_grants"`
						Items               []api.AppAccessManagedApp `json:"items"`
					}
					if err := json.Unmarshal(out.Body.Bytes(), &body); err != nil {
						t.Fatal(err)
					}
					if body.CanViewApplications == nil || body.CanManageGrants == nil || *body.CanViewApplications != tc.view || *body.CanManageGrants != tc.grant {
						t.Fatalf("required current permission hints missing/wrong: %s", out.Body.String())
					}
					if len(body.Items) != len(f.managed.Items) || f.actor != principal.UserID || f.org != org {
						t.Fatal("scoped application projection changed", body)
					}
				})
			}
		})
	}
}
