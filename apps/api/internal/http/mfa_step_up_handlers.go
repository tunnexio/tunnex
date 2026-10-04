package http

import (
	"context"
	"crypto/sha256"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

func mfaSessionInvalid() error {
	return apierr.New(http.StatusUnauthorized, "mfa_session_invalid", "sign in again before verifying a second factor")
}

// mfaParent requires the actual verified native cookie. A bearer principal or
// body-selected session cannot be promoted, even when it belongs to this user.
func (s apiServer) mfaParent(ctx context.Context) (session.Session, error) {
	p, err := requireVerifiedSessionUser(ctx)
	if err != nil {
		return session.Session{}, err
	}
	state, ok := ctx.Value(requestTransportKey{}).(requestTransportState)
	if !ok || state.ambiguousSession || state.sessionToken == "" || state.sessionToken != p.SessionID ||
		(p.IsMachine() || p.AuthMethod == "agent" || p.AuthMethod == "machine" || p.AuthMethod == "bearer") || s.sessions == nil || s.system == nil {
		return session.Session{}, mfaSessionInvalid()
	}
	parent, _, err := s.sessions.GetNoTouch(ctx, p.SessionID)
	if err != nil {
		return session.Session{}, mfaSessionInvalid()
	}
	if parent.UserID != p.UserID || parent.AppAuthEpoch <= 0 {
		return session.Session{}, mfaSessionInvalid()
	}
	if err = s.validateMFAParent(ctx, parent); err != nil {
		return session.Session{}, err
	}
	return parent, nil
}

// Re-check durable authority around the cross-store promotion. Reset or logout
// can win at any point; no MFA stamp overrides either epoch or logout tombstone.
func (s apiServer) validateMFAParent(ctx context.Context, parent session.Session) error {
	if s.system == nil || s.sessions == nil {
		return mfaSessionInvalid()
	}
	current, _, err := s.sessions.GetNoTouch(ctx, parent.ID)
	if err != nil || current.UserID != parent.UserID || current.AppAuthEpoch != parent.AppAuthEpoch ||
		!current.CreatedAt.Equal(parent.CreatedAt) || !current.ExpiresAt.Equal(parent.ExpiresAt) || current.AuthMethod != parent.AuthMethod {
		return mfaSessionInvalid()
	}
	user, err := s.system.GetUserByID(ctx, parent.UserID)
	if err != nil {
		return err
	}
	if user.Status != "active" || !user.EmailVerifiedAt.Valid || user.AppAuthEpoch != parent.AppAuthEpoch {
		return mfaSessionInvalid()
	}
	hash := sha256.Sum256([]byte(parent.ID))
	revoked, err := s.system.IsAppParentLogoutRevoked(ctx, hash[:])
	if err != nil {
		return err
	}
	if revoked {
		return mfaSessionInvalid()
	}
	return nil
}

func (s apiServer) mfaAttempt(ctx context.Context, parent session.Session) error {
	allowed, err := s.sessions.AllowMFAStepUp(ctx, parent.UserID, parent.ID)
	if err != nil {
		return err
	}
	if !allowed {
		return apierr.New(http.StatusTooManyRequests, "mfa_rate_limited", "too many verification attempts; try again in five minutes")
	}
	return nil
}

// MfaStepUp verifies a second factor for the current session; it never issues a
// login challenge, a new cookie, a new parent ID, or a longer session lifetime.
func (s apiServer) MfaStepUp(ctx context.Context, req api.MfaStepUpRequestObject) (api.MfaStepUpResponseObject, error) {
	parent, err := s.mfaParent(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil || req.Body.Code == "" {
		return nil, apierr.BadRequest("invalid_request", "a verification code is required")
	}
	if err = s.mfaAttempt(ctx, parent); err != nil {
		return nil, err
	}
	if s.mfa == nil {
		return nil, apierr.New(503, "mfa_unavailable", "verification is unavailable")
	}
	at, recovery, err := s.mfa.VerifyStepUp(ctx, parent.UserID, parent.AppAuthEpoch, req.Body.Code)
	if err != nil {
		return nil, err
	}
	if err = s.validateMFAParent(ctx, parent); err != nil {
		return nil, err
	}
	source := session.MFAAssuranceLocalTOTP
	if recovery {
		source = session.MFAAssuranceLocalRecovery
	}
	if _, err = s.sessions.PromoteMFA(ctx, parent, at, source); err != nil {
		return nil, mfaSessionInvalid()
	}
	if err = s.validateMFAParent(ctx, parent); err != nil {
		return nil, err
	}
	return api.MfaStepUp200JSONResponse{VerifiedAt: at}, nil
}
