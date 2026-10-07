package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Beam routes inherit authentication, CSRF and MFA gates and decode strictly
// before the legacy generated request validator.
func beamMiddleware(service *beam.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/admin/beam/readiness" {
				serveBeamReadiness(w, r, service)
				return
			}
			if r.URL.Path == "/api/v1/admin/beam/settings" {
				serveBeamDomainSettings(w, r, service)
				return
			}
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			// The generated Access Events request does not carry raw headers.
			// Reject bearer/cookie fallback before it reaches the Beam evidence
			// projection, without changing the network source's authentication.
			if len(parts) == 5 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "organizations" && parts[4] == "access-events" && r.URL.Query().Get("source") == "beam" && len(r.Header.Values("Authorization")) > 0 {
				org, e := uuid.Parse(parts[3])
				if e != nil {
					apierr.Write(w, r, apierr.NotFound("org_not_found", "Organization not found"))
					return
				}
				if _, e = authorize(r.Context(), org, rbac.PermBeamAuditView); e != nil {
					apierr.Write(w, r, e)
					return
				}
				apierr.Write(w, r, apierr.Forbidden("human_browser_session_required", "Beam access evidence requires a current human browser session"))
				return
			}
			if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "organizations" || parts[4] != "beam" {
				next.ServeHTTP(w, r)
				return
			}
			org, e := uuid.Parse(parts[3])
			if e != nil {
				apierr.Write(w, r, apierr.NotFound("org_not_found", "Organization not found"))
				return
			}
			if service == nil {
				apierr.Write(w, r, apierr.New(503, "beam_unavailable", "Beam service unavailable"))
				return
			}
			path := strings.Join(parts[5:], "/")
			perm := rbac.PermBeamUse
			switch {
			case (path == "policy" && r.Method == http.MethodPut) || path == "policy/impact":
				perm = rbac.PermBeamPolicyManage
			case path == "events":
				perm = rbac.PermBeamAuditView
			case (path == "shares" && r.Method == http.MethodPost) || (strings.HasPrefix(path, "projects") && (r.Method == http.MethodPost || r.Method == http.MethodPut)):
				perm = rbac.PermBeamCreate
			case strings.HasSuffix(path, "/actions") || strings.HasSuffix(path, "/grants") || strings.HasSuffix(path, "/connector") || strings.HasSuffix(path, "/heartbeat") || strings.HasSuffix(path, "/grants/impact") || strings.HasSuffix(path, "/diagnostics") || strings.HasSuffix(path, "/events"):
				perm = rbac.PermBeamManageOwn
			}
			ctx, e := authorize(r.Context(), org, perm)
			if e != nil {
				apierr.Write(w, r, e)
				return
			}
			p, _ := authctx.PrincipalFrom(ctx)
			if p.UserID == uuid.Nil || p.IsMachine() || p.IsAgent() || (p.AuthMethod != authctx.AuthBearer && p.SessionID == "") {
				apierr.Write(w, r, apierr.Forbidden("human_session_required", "Beam requires a current human login"))
				return
			}
			if len(r.Header.Values("Authorization")) > 0 && p.AuthMethod != authctx.AuthBearer {
				apierr.Write(w, r, apierr.New(401, "unauthenticated", "Authentication required"))
				return
			}
			a := beam.Actor{ID: p.UserID, SessionID: p.SessionID, ManagePolicy: rbac.CanAny(p.RolesIn(org), rbac.PermBeamPolicyManage), ManageAll: rbac.CanAny(p.RolesIn(org), rbac.PermBeamManageAll)}
			if p.AuthMethod == authctx.AuthBearer {
				if len(r.Header.Values("Authorization")) != 1 {
					apierr.Write(w, r, apierr.New(401, "unauthenticated", "Authentication required"))
					return
				}
				raw, ok := bearerToken(r)
				if !ok {
					apierr.Write(w, r, apierr.New(401, "unauthenticated", "Authentication required"))
					return
				}
				a.CredentialID, e = service.Credential(ctx, p.UserID, raw)
				if e != nil {
					apierr.Write(w, r, e)
					return
				}
				a.SessionID = ""
			}
			if (path == "policy" && r.Method == http.MethodPut) || path == "policy/impact" || path == "events" || strings.HasSuffix(path, "/launch") {
				if a.CredentialID != uuid.Nil {
					apierr.Write(w, r, apierr.Forbidden("human_browser_session_required", "This operation requires a human browser session"))
					return
				}
			}
			r = r.WithContext(ctx)
			result, e := serveBeam(ctx, w, r, service, org, a, path)
			if e != nil {
				apierr.Write(w, r, e)
				return
			}
			if shot, ok := result.(beamScreenshotResponse); ok {
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
				_, _ = w.Write(shot)
				return
			}
			writeJSON(w, result)
		})
	}
}
func beamDecode(w http.ResponseWriter, r *http.Request, out any) error {
	return beamDecodeLimit(w, r, out, 32768)
}
func beamDecodeLimit(w http.ResponseWriter, r *http.Request, out any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	e := d.Decode(out)
	if e == nil {
		var extra any
		e = d.Decode(&extra)
		if e == io.EOF {
			return nil
		}
	}
	var max *http.MaxBytesError
	if errors.As(e, &max) {
		return apierr.New(413, "request_body_too_large", "Beam request exceeds the allowed size")
	}
	return apierr.BadRequest("beam_invalid", "Invalid Beam request")
}
func beamPage(r *http.Request) (int, int, error) {
	limit, offset := 50, 0
	var e error
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, e = strconv.Atoi(v)
		if e != nil {
			return 0, 0, apierr.BadRequest("invalid_pagination", "Invalid pagination")
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		offset, e = strconv.Atoi(v)
		if e != nil {
			return 0, 0, apierr.BadRequest("invalid_pagination", "Invalid pagination")
		}
	}
	if limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return 0, 0, apierr.BadRequest("invalid_pagination", "Invalid pagination")
	}
	return limit, offset, nil
}
func serveBeam(ctx context.Context, w http.ResponseWriter, r *http.Request, s *beam.Service, org uuid.UUID, a beam.Actor, path string) (any, error) {
	if result, handled, err := serveBeamRooms(ctx, w, r, s, org, a, path); handled {
		return result, err
	}
	switch path {
	case "policy":
		if r.Method == http.MethodGet {
			return s.GetPolicy(ctx, org, a)
		}
		if r.Method == http.MethodPut {
			var in beam.PolicyInput
			if e := beamDecode(w, r, &in); e != nil {
				return nil, e
			}
			return s.UpdatePolicy(ctx, org, a, in)
		}
	case "policy/impact":
		if r.Method == http.MethodPost {
			var in beam.PolicyInput
			if e := beamDecode(w, r, &in); e != nil {
				return nil, e
			}
			return s.PreviewPolicy(ctx, org, a, in)
		}
	case "audience":
		if r.Method == http.MethodGet {
			return s.Audience(ctx, org, a)
		}
	case "shares":
		if r.Method == http.MethodGet {
			l, o, e := beamPage(r)
			if e != nil {
				return nil, e
			}
			return s.ListQueryScope(ctx, org, a, false, l, o, r.URL.Query().Get("q"), r.URL.Query().Get("state"), r.URL.Query().Get("connectivity"), r.URL.Query().Get("scope"))
		}
		if r.Method == http.MethodPost {
			var in beam.CreateInput
			if e := beamDecode(w, r, &in); e != nil {
				return nil, e
			}
			return s.Create(ctx, org, a, in)
		}
	case "shared":
		if r.Method == http.MethodGet {
			l, o, e := beamPage(r)
			if e != nil {
				return nil, e
			}
			return s.ListQuery(ctx, org, a, true, l, o, r.URL.Query().Get("q"), r.URL.Query().Get("state"), r.URL.Query().Get("connectivity"))
		}
	case "events":
		if r.Method == http.MethodGet {
			l, o, e := beamPage(r)
			if e != nil {
				return nil, e
			}
			f, e := beamEventFilter(r)
			if e != nil {
				return nil, e
			}
			return s.EventsFiltered(ctx, org, l, o, f)
		}
	}
	parts := strings.Split(path, "/")
	if len(parts) >= 2 && parts[0] == "shares" {
		id, e := uuid.Parse(parts[1])
		if e != nil {
			return nil, apierr.NotFound("beam_share_not_found", "Share not found")
		}
		if len(parts) == 2 && r.Method == http.MethodGet {
			return s.Get(ctx, org, id, a)
		}
		if len(parts) == 4 && parts[2] == "grants" && parts[3] == "impact" && r.Method == http.MethodPost {
			var in beam.GrantsInput
			if e := beamDecode(w, r, &in); e != nil {
				return nil, e
			}
			return s.PreviewGrants(ctx, org, id, a, in)
		}
		if len(parts) == 3 {
			switch parts[2] {
			case "diagnostics":
				if r.Method == http.MethodGet {
					return s.Diagnostics(ctx, org, id, a)
				}
			case "events":
				if r.Method == http.MethodGet {
					l, o, e := beamPage(r)
					if e != nil {
						return nil, e
					}
					f, e := beamEventFilter(r)
					if e != nil {
						return nil, e
					}
					return s.ShareEvents(ctx, org, id, a, l, o, f)
				}
			case "actions":
				if r.Method == http.MethodPost {
					var in beam.ActionInput
					if e = beamDecode(w, r, &in); e != nil {
						return nil, e
					}
					return s.Action(ctx, org, id, a, in)
				}
			case "grants":
				if r.Method == http.MethodPut {
					var in beam.GrantsInput
					if e = beamDecode(w, r, &in); e != nil {
						return nil, e
					}
					return s.UpdateGrants(ctx, org, id, a, in)
				}
			case "connector":
				if r.Method == http.MethodPost {
					var in beam.ConnectorInput
					if e = beamDecode(w, r, &in); e != nil {
						return nil, e
					}
					return s.IssueConnector(ctx, org, id, a, in)
				}
			case "heartbeat":
				if r.Method == http.MethodPost {
					var in beam.Heartbeat
					if e = beamDecode(w, r, &in); e != nil {
						return nil, e
					}
					return s.Heartbeat(ctx, org, id, a, in)
				}
			case "launch":
				if r.Method == http.MethodPost {
					var in beam.LaunchInput
					if e = beamDecode(w, r, &in); e != nil {
						return nil, e
					}
					return s.Launch(ctx, org, id, a, in)
				}
			}
		}
	}
	return nil, apierr.New(405, "method_not_allowed", "Beam operation not available")
}

func beamEventFilter(r *http.Request) (beam.EventFilter, error) {
	q := r.URL.Query()
	f := beam.EventFilter{Search: q.Get("q"), Action: q.Get("action"), Outcome: q.Get("outcome")}
	if v := q.Get("share_id"); v != "" {
		id, e := uuid.Parse(v)
		if e != nil {
			return f, apierr.BadRequest("beam_invalid", "Invalid share filter")
		}
		f.ShareID = id
	}
	return f, nil
}
