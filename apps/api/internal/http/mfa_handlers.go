package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// MfaEnrollStart POST /auth/mfa/enroll — begin TOTP enrollment (OPEN; verified session).
func (s apiServer) MfaEnrollStart(ctx context.Context, req api.MfaEnrollStartRequestObject) (api.MfaEnrollStartResponseObject, error) {
	p, err := requireVerifiedSessionUser(ctx)
	if err != nil {
		return nil, err
	}
	uri, key, err := s.mfa.StartEnrollment(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	return api.MfaEnrollStart200JSONResponse{
		Body:    api.MfaEnrollResult{OtpauthUri: uri, Secret: key},
		Headers: api.MfaEnrollStart200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// MfaEnrollConfirm POST /auth/mfa/enroll/confirm — arm MFA with a valid code; returns recovery codes once.
func (s apiServer) MfaEnrollConfirm(ctx context.Context, req api.MfaEnrollConfirmRequestObject) (api.MfaEnrollConfirmResponseObject, error) {
	p, err := requireVerifiedSessionUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	codes, err := s.mfa.ConfirmEnrollment(ctx, p.UserID, req.Body.Code)
	if err != nil {
		return nil, err
	}
	return api.MfaEnrollConfirm200JSONResponse{
		Body:    api.MfaRecoveryCodes{RecoveryCodes: codes},
		Headers: api.MfaEnrollConfirm200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

// MfaDisenroll DELETE /auth/mfa — remove the current user's MFA (OPEN; verified session).
func (s apiServer) MfaDisenroll(ctx context.Context, req api.MfaDisenrollRequestObject) (api.MfaDisenrollResponseObject, error) {
	p, err := requireVerifiedSessionUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.mfa.Disenroll(ctx, p.UserID, p.UserID, "mfa.disenrolled"); err != nil {
		return nil, err
	}
	return api.MfaDisenroll204Response{}, nil
}

// mfaVerifyResponse sets the session cookie once the login challenge is passed (mirrors loginResponse).
type mfaVerifyResponse struct {
	body      api.AuthUser
	sess      session.Session
	secure    bool
	requestID string
}

func (r mfaVerifyResponse) VisitMfaVerifyResponse(w http.ResponseWriter) error {
	session.SetCookie(w, r.sess, r.secure)
	w.Header().Set("X-Request-Id", r.requestID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(r.body)
}

// MfaVerify POST /auth/mfa/verify — complete the login second step (public; challenge-bound). The
// pending state was a challenge token, never a session (D6): only here is a session minted.
func (s apiServer) MfaVerify(ctx context.Context, req api.MfaVerifyRequestObject) (api.MfaVerifyResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	user, _, err := s.mfa.VerifyChallenge(ctx, req.Body.Challenge, req.Body.Code)
	if err != nil {
		return nil, err
	}
	sess, err := s.sessions.Create(ctx, user.ID, authctx.AuthLocalPassword)
	if err != nil {
		return nil, err
	}
	au := authUser(user)
	// D11: surface the remaining recovery-code count at the verify moment — the user who just burned
	// a code (viaRecovery) is exactly who needs the low-remaining / last-code warning. Count only.
	if n, e := s.mfa.CountRecoveryRemaining(ctx, user.ID); e == nil {
		au.RecoveryCodesRemaining = &n
	}
	return mfaVerifyResponse{body: au, sess: sess, secure: s.cookieSecure, requestID: reqID(ctx)}, nil
}
