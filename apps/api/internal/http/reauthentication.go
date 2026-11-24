package http

import (
	"context"
	"net/http"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// recentReauthMFAWindow is the Local Sharing step-up window, reused (SA-UI-1).
const recentReauthMFAWindow = 5 * time.Minute

// requireRecentReauthentication enforces SA-UI-1's re-authentication rules for a
// server-administrator host action: a local password is re-entered (its own
// failure-only budget, named by scope), a confirmed TOTP factor or a fresh IdP
// MFA must be verified in this session within five minutes, and an account with
// neither is refused. action completes "Verify MFA to ...".
func (s apiServer) requireRecentReauthentication(ctx context.Context, p *authctx.Principal, currentPassword *string, scope, action string) error {
	parent, err := s.mfaParent(ctx)
	if err != nil {
		return err
	}
	r, err := s.installationReauthFor(ctx, p.UserID, &parent)
	if err != nil {
		return apierr.New(http.StatusServiceUnavailable, "reauthentication_unavailable", "Re-authentication could not be checked. Try again.")
	}
	if !r.available() {
		return apierr.Forbidden("reauthentication_unavailable", "Your account has no password or authenticator on this server to confirm it is you. Set up an authenticator app (two-factor authentication) in your account settings, then "+action+".")
	}
	if r.mfa || r.ssoMFA {
		now := time.Now()
		if !session.ValidMFAAssurance(parent.MFAVerifiedAt, parent.MFAAssuranceSource, now) || parent.MFAVerifiedAt.Before(now.Add(-recentReauthMFAWindow)) {
			return apierr.Forbidden("mfa_step_up_required", "Verify MFA to "+action+".")
		}
	}
	if r.password {
		if currentPassword == nil || *currentPassword == "" {
			return apierr.BadRequest("current_password_required", "Enter your current password to "+action+".")
		}
		// Own budget, charged only by failures: correct re-entries never lock an administrator out.
		allowed, err := s.sessions.ReauthPasswordAllowed(ctx, scope, p.UserID)
		if err != nil {
			return apierr.New(http.StatusServiceUnavailable, "reauthentication_unavailable", "Re-authentication could not be checked. Try again.")
		}
		if !allowed {
			return apierr.New(http.StatusTooManyRequests, "reauthentication_rate_limited", "Too many incorrect passwords. Try again in five minutes.")
		}
		if _, err := password.Verify(*currentPassword, r.passwordHash); err != nil {
			if err := s.sessions.RecordReauthPasswordFailure(ctx, scope, p.UserID); err != nil {
				return apierr.New(http.StatusServiceUnavailable, "reauthentication_unavailable", "Re-authentication could not be checked. Try again.")
			}
			return apierr.Forbidden("invalid_credentials", "The current password is incorrect.")
		}
	}
	return s.validateMFAParent(ctx, parent)
}

// requireHumanSession refuses machine, agent and bearer principals for a host action.
func requireHumanSession(p *authctx.Principal, what string) error {
	if p.SessionID == "" || p.IsAgent() || p.IsMachine() || p.AuthMethod == authctx.AuthBearer || p.AuthMethod == authctx.AuthMachine || p.AuthMethod == authctx.AuthAgent {
		return apierr.Forbidden("human_session_required", what+" requires a human browser session.")
	}
	return nil
}
