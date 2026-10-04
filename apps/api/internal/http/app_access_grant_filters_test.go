package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type grantFilterRecorder struct {
	appAccessRecorder
	filter        appaccess.GrantListFilter
	limit, offset int32
}

func (f *grantFilterRecorder) ListGrants(_ context.Context, org uuid.UUID, _ *uuid.UUID, _ string, _ *uuid.UUID, limit, offset int32, filters ...appaccess.GrantListFilter) ([]appaccess.Grant, error) {
	f.calls++
	f.org = org
	f.limit, f.offset = limit, offset
	if len(filters) == 1 {
		f.filter = filters[0]
	}
	return []appaccess.Grant{}, nil
}
func TestAppAccessGrantFilteredGeneratedRoute(t *testing.T) {
	org := uuid.New()
	for _, tc := range []struct {
		name, role, query string
		scoped            bool
		want              int
	}{
		{"literal search and pagination", rbac.RoleAdmin, "search=" + url.QueryEscape(" Needle_% ") + "&view=history&status=expired&limit=20&offset=20", true, 200},
		{"ordinary member remains denied", rbac.RoleMember, "search=person&status=active", true, 403},
		{"assigned member has no global grant authority", rbac.RoleMember, "status=disabled", true, 403},
		{"wrong current status", rbac.RoleAdmin, "view=current&status=expired", true, 400},
		{"wrong history status", rbac.RoleAdmin, "view=history&status=subject_unavailable", true, 400},
		{"unknown view", rbac.RoleAdmin, "view=unknown", true, 400},
		{"unknown status", rbac.RoleAdmin, "status=unknown", true, 400},
		{"oversized Unicode search", rbac.RoleAdmin, "search=" + url.QueryEscape(strings.Repeat("界", 201)), true, 400},
		{"foreign organization", rbac.RoleAdmin, "status=active", false, 404},
		{"no session", "", "search=person", true, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &grantFilterRecorder{}
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
			if !tc.scoped {
				requestOrg = uuid.New()
			}
			req := httptest.NewRequest("GET", "https://internal.tunnex.app/api/v1/organizations/"+requestOrg.String()+"/app-access/grants?"+tc.query, nil)
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
					t.Fatal("invalid/unauthorized filter reached service")
				}
				return
			}
			if recorder.calls != 1 || recorder.org != org || recorder.filter.Search != "Needle_%" || recorder.filter.Status != "expired" || recorder.filter.View != "history" || recorder.limit != 20 || recorder.offset != 20 || out.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("filter/paging contract changed: %+v", recorder)
			}
		})
	}
}
