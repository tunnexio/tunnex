package http

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/serveraccess"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// SA-UI-1: the installation-wide Server Access capability. Server administrators only (the same
// deployment authority as Application domains), from a human browser session, with recent
// re-authentication. See docs/SA-UI-1-installation-toggle.md.

// serverAccessInstallationReauthScope names this endpoint's password-failure budget.
const serverAccessInstallationReauthScope = "server_access_installation"

func requireServerAccessInstallationAdmin(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if p.UserID == uuid.Nil || p.SessionID == "" || p.IsAgent() || p.IsMachine() || p.AuthMethod == authctx.AuthBearer || p.AuthMethod == authctx.AuthMachine || p.AuthMethod == authctx.AuthAgent {
		return nil, apierr.Forbidden("human_session_required", "The Server Access installation setting requires a human browser session.")
	}
	return p, nil
}

type installationReauth struct {
	password, mfa, ssoMFA bool
	passwordHash          string
}

func (r installationReauth) available() bool { return r.password || r.mfa || r.ssoMFA }

// installationReauthFor describes what this administrator can prove. A local password is proved with
// current_password; a confirmed TOTP factor (or, for an account with neither, an IdP-asserted MFA on this
// SSO session) is proved with fresh session MFA assurance.
func (s apiServer) installationReauthFor(ctx context.Context, user uuid.UUID, parent *session.Session) (installationReauth, error) {
	var out installationReauth
	if s.system == nil {
		return out, errors.New("user store not wired")
	}
	u, err := s.system.GetUserByID(ctx, user)
	if err != nil {
		return out, err
	}
	if u.PasswordHash != nil && *u.PasswordHash != "" {
		out.password, out.passwordHash = true, *u.PasswordHash
	}
	if s.mfa != nil {
		if out.mfa, err = s.mfa.HasConfirmedTOTP(ctx, user); err != nil {
			return out, err
		}
	}
	if !out.password && !out.mfa && parent != nil && parent.MFAAssuranceSource == session.MFAAssuranceSSO {
		out.ssoMFA = true
	}
	return out, nil
}

// requireServerAccessInstallationStepUp is the ONE place decision 2's re-authentication is enforced for
// this setting; the rules live in requireRecentReauthentication.
func (s apiServer) requireServerAccessInstallationStepUp(ctx context.Context, p *authctx.Principal, currentPassword *string) error {
	return s.requireRecentReauthentication(ctx, p, currentPassword, serverAccessInstallationReauthScope, "change Server Access for this installation")
}

func serverAccessInstallationView(v serveraccess.InstallationView, r installationReauth) api.ServerAccessInstallation {
	out := api.ServerAccessInstallation{Enabled: v.Enabled, Effective: v.Effective, Locked: v.Locked, Source: api.ServerAccessInstallationSource(v.Source), Version: v.Version, UpdatedAt: v.UpdatedAt}
	out.Reauthentication.Password, out.Reauthentication.Mfa, out.Reauthentication.Available = r.password, r.mfa || r.ssoMFA, r.available()
	return out
}

func serverAccessInstallationError(err error) error {
	var known *apierr.Error
	if errors.As(err, &known) {
		return err
	}
	return apierr.New(http.StatusServiceUnavailable, "server_access_installation_unavailable", "The Server Access setting is unavailable.")
}

// currentParent reads the caller's session for display-only requirements; failures degrade to "unknown".
func (s apiServer) currentParent(ctx context.Context, p *authctx.Principal) *session.Session {
	if s.sessions == nil || p.SessionID == "" {
		return nil
	}
	parent, _, err := s.sessions.GetNoTouch(ctx, p.SessionID)
	if err != nil || parent.UserID != p.UserID {
		return nil
	}
	return &parent
}

func (s apiServer) GetServerAccessInstallation(ctx context.Context, _ api.GetServerAccessInstallationRequestObject) (api.GetServerAccessInstallationResponseObject, error) {
	p, err := requireServerAccessInstallationAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.serverAccess == nil {
		return nil, serverAccessInstallationError(errors.New("not wired"))
	}
	v, err := s.serverAccess.Installation(ctx)
	if err != nil {
		return nil, serverAccessInstallationError(err)
	}
	r, err := s.installationReauthFor(ctx, p.UserID, s.currentParent(ctx, p))
	if err != nil {
		return nil, serverAccessInstallationError(err)
	}
	return api.GetServerAccessInstallation200JSONResponse{Body: serverAccessInstallationView(v, r), Headers: api.GetServerAccessInstallation200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) UpdateServerAccessInstallation(ctx context.Context, req api.UpdateServerAccessInstallationRequestObject) (api.UpdateServerAccessInstallationResponseObject, error) {
	p, err := requireServerAccessInstallationAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.serverAccess == nil {
		return nil, serverAccessInstallationError(errors.New("not wired"))
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("server_access_installation_invalid", "The Server Access setting is required.")
	}
	if err = s.requireServerAccessInstallationStepUp(ctx, p, req.Body.CurrentPassword); err != nil {
		return nil, err
	}
	v, ended, err := s.serverAccess.SaveInstallation(ctx, p.UserID, serveraccess.InstallationUpdate{Enabled: req.Body.Enabled, ExpectedVersion: req.Body.ExpectedVersion})
	if err != nil {
		return nil, serverAccessInstallationError(err)
	}
	r, err := s.installationReauthFor(ctx, p.UserID, s.currentParent(ctx, p))
	if err != nil {
		return nil, serverAccessInstallationError(err)
	}
	out := serverAccessInstallationView(v, r)
	if !v.Effective {
		out.EndedSessions = &ended
	}
	return api.UpdateServerAccessInstallation200JSONResponse{Body: out, Headers: api.UpdateServerAccessInstallation200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
