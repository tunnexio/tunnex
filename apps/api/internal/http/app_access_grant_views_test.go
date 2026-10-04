package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type managedViewRecorder struct {
	companyRecorder
	filter        appaccess.GrantListFilter
	limit, offset int32
}

func (f *managedViewRecorder) ManagedGrants(_ context.Context, org, actor, app uuid.UUID, limit, offset int32, filters ...appaccess.GrantListFilter) ([]appaccess.Grant, error) {
	f.record(org, actor, app)
	f.limit = limit
	f.offset = offset
	if len(filters) == 1 {
		f.filter = filters[0]
	}
	return []appaccess.Grant{}, nil
}
func TestManagedGrantViewsGeneratedRoute(t *testing.T) {
	org, app := uuid.New(), uuid.New()
	for _, tc := range []struct {
		name, role, query, view, status string
		foreign                         bool
		want                            int
	}{
		{"assigned member reaches scoped authority", rbac.RoleMember, "view=current&status=disabled&search=%20needle%20&limit=1&offset=2", "current", "disabled", false, 200},
		{"admin history", rbac.RoleAdmin, "view=history&status=expired&search=%20needle%20&limit=1&offset=2", "history", "expired", false, 200},
		{"unknown view", rbac.RoleMember, "view=unknown", "", "", false, 400},
		{"history excludes scheduled", rbac.RoleMember, "view=history&status=scheduled", "", "", false, 400},
		{"current excludes revoked", rbac.RoleMember, "view=current&status=revoked", "", "", false, 400},
		{"cross organization denied", rbac.RoleMember, "view=history", "", "", true, 404},
		{"no session", "", "view=current", "", "", false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &managedViewRecorder{}
			router, err := NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{AppAccess: recorder, AppBaseURL: "https://internal.tunnex.app", AuthFn: func(r *http.Request) *authctx.Principal {
				c, e := r.Cookie("__Host-tunnex_session")
				if e != nil {
					return nil
				}
				return appAccessPrincipal(org, c.Value)
			}})
			if err != nil {
				t.Fatal(err)
			}
			requestOrg := org
			if tc.foreign {
				requestOrg = uuid.New()
			}
			req := httptest.NewRequest("GET", "https://internal.tunnex.app/api/v1/organizations/"+requestOrg.String()+"/app-access/applications/"+app.String()+"/managed-grants?"+tc.query, nil)
			if tc.role != "" {
				req.AddCookie(&http.Cookie{Name: "__Host-tunnex_session", Value: tc.role})
			}
			out := httptest.NewRecorder()
			router.ServeHTTP(out, req)
			if out.Code != tc.want {
				t.Fatalf("status%d want%d: %s", out.Code, tc.want, out.Body.String())
			}
			if tc.want != 200 {
				if recorder.calls != 0 {
					t.Fatal("invalid/scoping request reached service")
				}
				return
			}
			if recorder.calls != 1 || recorder.org != org || recorder.app != app || recorder.filter.View != tc.view || recorder.filter.Status != tc.status || recorder.filter.Search != "needle" || recorder.limit != 1 || recorder.offset != 2 || out.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("scoped filter contract: %+v", recorder)
			}
		})
	}
}
