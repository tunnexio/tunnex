package http

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"net/http"
	"strings"
)

// terminalRequestGuard checks human authority before parsing an untrusted body
// or identifier. This also covers websocket upgrades on the raw terminal route.
func (s apiServer) terminalRequestGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 6 || parts[1] != "api" || parts[2] != "v1" || parts[3] != "organizations" || parts[5] != "server-access" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if _, ok := authctx.PrincipalFrom(r.Context()); !ok {
			apierr.Write(w, r, apierr.New(401, "unauthenticated", "authentication required"))
			return
		}
		org, e := uuid.Parse(parts[4])
		if e != nil {
			apierr.Write(w, r, apierr.BadRequest("invalid_org", "Invalid organization"))
			return
		}
		perm := rbac.PermServerAccessUse
		if len(parts) == 7 && parts[6] == "recording-import" || len(parts) >= 9 && parts[6] == "sessions" && parts[8] == "recording" {
			perm = rbac.PermServerAccessReplay
		} else if len(parts) > 6 && (parts[6] == "trust" || parts[6] == "enrollments") {
			perm = rbac.PermServerAccessManage
		} else if r.Method != "GET" {
			switch {
			case len(parts) > 6 && parts[6] == "sessions":
				perm = rbac.PermServerAccessUse
			case len(parts) > 6 && parts[6] == "grants":
				perm = rbac.PermServerAccessGrant
			default:
				perm = rbac.PermServerAccessManage
			}
		}
		ctx, _, e := s.terminalContext(r.Context(), org, perm)
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isTerminalUpgradeRequest(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	if r.Method != "GET" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || len(parts) != 9 || parts[1] != "api" || parts[2] != "v1" || parts[3] != "organizations" || parts[5] != "server-access" || parts[6] != "sessions" || parts[8] != "terminal" {
		return false
	}
	_, orgError := uuid.Parse(parts[4])
	_, sessionError := uuid.Parse(parts[7])
	return orgError == nil && sessionError == nil
}

func isEditorUpgradeRequest(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	if r.Method != "GET" || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || len(parts) != 6 || parts[1] != "api" || parts[2] != "v1" || parts[3] != "server-access" || parts[4] != "editor" {
		return false
	}
	_, e := uuid.Parse(parts[5])
	return e == nil
}
