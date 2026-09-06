package http

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sso"
	"net/http"
	"net/url"
)

func (s apiServer) connectionService() (*sso.Service, error) {
	a, ok := s.sso.(*ssoAdapter)
	if !ok {
		return nil, editionRequired()
	}
	return a.svc, nil
}
func (s apiServer) connectionView(c sqlc.SsoConnection) api.SsoConnection {
	v := api.SsoConnection{Id: c.ID, OrgId: c.OrgID, Name: c.Name, Provider: api.SsoConnectionProvider(c.Provider), IssuerUrl: c.IssuerUrl, ClientId: c.ClientID, Enabled: c.Enabled, Revision: c.Revision, Verified: c.TestedRevision != nil && *c.TestedRevision == c.Revision, UpdatedAt: c.UpdatedAt, CallbackUrl: s.appBaseURL + "/api/v1/auth/sso-connections/callback", LoginUrl: s.appBaseURL + "/login?connection=" + c.ID.String()}
	if c.TestedAt.Valid {
		v.TestedAt = &c.TestedAt.Time
	}
	return v
}
func (s apiServer) ListSsoConnections(ctx context.Context, req api.ListSsoConnectionsRequestObject) (api.ListSsoConnectionsResponseObject, error) {
	if _, e := authorize(ctx, req.OrgId, rbac.PermOrgView); e != nil {
		return nil, e
	}
	if e := s.requireSSOAdmin(); e != nil {
		return nil, e
	}
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	rows, e := svc.ListConnections(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	items := []api.SsoConnection{}
	for _, c := range rows {
		items = append(items, s.connectionView(c))
	}
	return api.ListSsoConnections200JSONResponse{Items: items}, nil
}
func (s apiServer) SaveSsoConnection(ctx context.Context, req api.SaveSsoConnectionRequestObject) (api.SaveSsoConnectionResponseObject, error) {
	if _, e := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); e != nil {
		return nil, e
	}
	if e := s.requireSSOAdmin(); e != nil {
		return nil, e
	}
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	c, e := svc.SaveConnection(ctx, p.UserID, req.OrgId, req.ConnectionId, sso.ConnectionInput{Name: req.Body.Name, Provider: string(req.Body.Provider), Issuer: req.Body.IssuerUrl, ClientID: req.Body.ClientId, Secret: req.Body.ClientSecret})
	if e != nil {
		return nil, e
	}
	return api.SaveSsoConnection200JSONResponse(s.connectionView(c)), nil
}
func (s apiServer) ActivateSsoConnection(ctx context.Context, req api.ActivateSsoConnectionRequestObject) (api.ActivateSsoConnectionResponseObject, error) {
	if _, e := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); e != nil {
		return nil, e
	}
	if e := s.requireSSOAdmin(); e != nil {
		return nil, e
	}
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	c, e := svc.ActivateConnection(ctx, p.UserID, req.OrgId, req.ConnectionId, req.Body.Revision, req.Body.Enabled)
	if e != nil {
		return nil, e
	}
	return api.ActivateSsoConnection200JSONResponse(s.connectionView(c)), nil
}
func (s apiServer) TestSsoConnection(ctx context.Context, req api.TestSsoConnectionRequestObject) (api.TestSsoConnectionResponseObject, error) {
	if _, e := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); e != nil {
		return nil, e
	}
	if e := s.requireSSOAdmin(); e != nil {
		return nil, e
	}
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if p.AuthMethod != authctx.AuthSSO && p.AuthMethod != authctx.AuthLocalPassword {
		return nil, apierr.New(403, "forbidden", "use an authenticated browser session to test SSO")
	}
	binding, e := sso.RandomToken()
	if e != nil {
		return nil, e
	}
	redirect, e := svc.StartConnection(ctx, req.OrgId, req.ConnectionId, p.UserID, true, req.Body.LinkAccount, binding)
	if e != nil {
		return nil, e
	}
	return connectionStartResponse{redirect: redirect, binding: binding, secure: s.cookieSecure}, nil
}
func (s apiServer) StartSsoConnection(ctx context.Context, req api.StartSsoConnectionRequestObject) (api.StartSsoConnectionResponseObject, error) {
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	binding, e := sso.RandomToken()
	if e != nil {
		return nil, e
	}
	redirect, e := svc.StartConnection(ctx, uuid.Nil, req.ConnectionId, uuid.Nil, false, false, binding)
	if e != nil {
		return nil, e
	}
	return connectionStartResponse{redirect: redirect, binding: binding, secure: s.cookieSecure}, nil
}

type connectionCallbackResponse struct {
	location      string
	sess          session.Session
	login, secure bool
}

func (r connectionCallbackResponse) VisitSsoConnectionCallbackResponse(w http.ResponseWriter) error {
	setConnectionFlowCookie(w, "", r.secure, -1)
	if r.login {
		session.SetCookie(w, r.sess, r.secure)
	}
	w.Header().Set("Location", r.location)
	w.WriteHeader(302)
	return nil
}
func (s apiServer) SsoConnectionCallback(ctx context.Context, req api.SsoConnectionCallbackRequestObject) (api.SsoConnectionCallbackResponseObject, error) {
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	p, _ := authctx.PrincipalFrom(ctx)
	actor := uuid.Nil
	if p.AuthMethod == authctx.AuthSSO || p.AuthMethod == authctx.AuthLocalPassword {
		actor = p.UserID
	}
	code := ""
	if req.Params.Code != nil {
		code = *req.Params.Code
	}
	binding := ""
	if req.Params.TnxOidcFlow != nil {
		binding = *req.Params.TnxOidcFlow
	}
	result, e := svc.CompleteConnection(ctx, code, req.Params.State, binding, actor)
	if result.Test || result.Link {
		status := "verified"
		if result.Link {
			status = "linked"
		}
		if e != nil {
			status = connectionErrorCode(e)
		}
		query := url.Values{"section": {"authentication"}, "sso_test": {status}, "sso_org": {result.OrgID.String()}, "sso_connection": {result.ConnectionID.String()}}
		return connectionCallbackResponse{location: s.appBaseURL + "/settings?" + query.Encode(), secure: s.cookieSecure}, nil
	}
	if e != nil {
		return connectionCallbackResponse{location: connectionLoginFailureURL(s.appBaseURL, result.ConnectionID, e), secure: s.cookieSecure}, nil
	}
	sess, e := s.sessions.Create(ctx, result.UserID, authctx.AuthSSO)
	if e != nil {
		return nil, e
	}
	return connectionCallbackResponse{location: s.appBaseURL + "/", sess: sess, login: true, secure: s.cookieSecure}, nil
}

func setConnectionFlowCookie(w http.ResponseWriter, value string, secure bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "tnx_oidc_flow", Value: value, Path: "/api/v1/auth/sso-connections", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

type connectionStartResponse struct {
	redirect, binding string
	secure            bool
}

func (r connectionStartResponse) write(w http.ResponseWriter) error {
	setConnectionFlowCookie(w, r.binding, r.secure, 600)
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(api.SsoRedirect{RedirectUrl: r.redirect})
}
func (r connectionStartResponse) VisitStartSsoConnectionResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r connectionStartResponse) VisitTestSsoConnectionResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func (r connectionStartResponse) VisitLinkSsoConnectionResponse(w http.ResponseWriter) error {
	return r.write(w)
}
func connectionErrorCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		switch e.Code {
		case "invalid_state", "sso_test_stale", "sso_discovery_failed", "sso_verification_failed", "sso_link_required", "sso_consent_denied", "forbidden":
			return e.Code
		}
	}
	return "sso_failed"
}
func (s apiServer) ListAvailableSsoConnections(ctx context.Context, req api.ListAvailableSsoConnectionsRequestObject) (api.ListAvailableSsoConnectionsResponseObject, error) {
	if _, e := authorize(ctx, req.OrgId, rbac.PermOrgView); e != nil {
		return nil, e
	}
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	rows, e := svc.ListConnections(ctx, req.OrgId)
	if e != nil {
		return nil, e
	}
	items := []api.SsoConnection{}
	for _, c := range rows {
		if c.Enabled {
			items = append(items, s.connectionView(c))
		}
	}
	return api.ListAvailableSsoConnections200JSONResponse{Items: items}, nil
}
func (s apiServer) LinkSsoConnection(ctx context.Context, req api.LinkSsoConnectionRequestObject) (api.LinkSsoConnectionResponseObject, error) {
	p, e := requireVerifiedSessionUser(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = authorize(ctx, req.OrgId, rbac.PermOrgView); e != nil {
		return nil, e
	}
	svc, e := s.connectionService()
	if e != nil {
		return nil, e
	}
	binding, e := sso.RandomToken()
	if e != nil {
		return nil, e
	}
	redirect, e := svc.StartConnection(ctx, req.OrgId, req.ConnectionId, p.UserID, false, true, binding)
	if e != nil {
		return nil, e
	}
	return connectionStartResponse{redirect: redirect, binding: binding, secure: s.cookieSecure}, nil
}

func connectionLoginFailureURL(base string, id uuid.UUID, err error) string {
	query := url.Values{"sso_error": {connectionErrorCode(err)}}
	if id != uuid.Nil {
		query.Set("connection", id.String())
	}
	return base + "/login?" + query.Encode()
}
