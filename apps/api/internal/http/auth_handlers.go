package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// Signup implements POST /api/v1/auth/signup. The response is deliberately
// generic (same for new and existing emails) to avoid account enumeration.
func (s apiServer) Signup(ctx context.Context, req api.SignupRequestObject) (api.SignupResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	name := ""
	if req.Body.Name != nil {
		name = *req.Body.Name
	}
	// ⛔ THE PUBLIC SIGNUP DOOR CLOSES ONCE THE DEPLOYMENT IS SET UP (founder-ruled).
	//
	// A self-hosted deployment is ONE COMPANY. Everyone inside arrives by invitation or SSO domain capture
	// — both acts by someone already here. An open form after setup produces only ORPHAN ACCOUNTS on a
	// private control plane, which is what it did on the first attempt.
	//
	// ⚠ THE GATE IS ON THE HANDLER, NOT THE SERVICE, AND THAT IS DELIBERATE. This endpoint is `Signup`'s
	// ONLY caller, so handler-gating is complete coverage of the PUBLIC door — while `auth.Service.Signup`
	// stays a usable domain operation. Pushing it into the service instead broke every test that mints a
	// user against a seeded database, which was the signal that the check was sitting at the wrong layer:
	// "is this deployment open to public registration" is a policy question about the ENDPOINT, not about
	// what it means to create an account.
	//
	// ⭐ NEITHER ADMISSION PATH TOUCHES THIS, measured: `/auth/invitations/accept` is `security: []` and
	// calls CreateUser itself (invites.go:158); SSO domain capture mints on the callback. Both are proven
	// independent by TestAdmissionPathsDoNotDependOnSignup.
	//
	// ⛔ KEYED ON USERS, NOT ORGANIZATIONS — AND THAT CLOSES A RACE THAT WAS REAL.
	//
	// This used to ask SetupComplete ("has this deployment ever had an ORGANIZATION"), which is zero on a
	// fresh install — so signup stayed open from `docker compose up` until the operator created the first
	// org. On a public address that window belongs to whoever finds it first: sign up, create the first
	// organization, own the deployment. bootstrap.EnsureAdmin exists to make the first administrator a
	// DELIBERATE act, and an open form running beside it gave the same power away for free.
	//
	// ⚠ THE ONE-CLICK INSTALLER IS WHY THIS HAD TO CHANGE BEFORE IT SHIPPED. `curl … | sh` ends with a
	// running, publicly-reachable, unclaimed control plane, and the gap between "up" and "the operator
	// reads the credential" is exactly the attacker's window.
	//
	// ⚠ AND IT FAILS CLOSED. PublicSignupOpen returns false on a read error: an unknown must not be read as
	// "nobody is here yet", which is the one answer that opens the door.
	if s.orgs != nil {
		open, e := s.orgs.PublicSignupOpen(ctx)
		if e != nil {
			return nil, e
		}
		if !open {
			return nil, apierr.Forbidden("signup_closed",
				"This deployment is already set up. Sign in as the administrator with the credential "+
					"printed at first run, or ask an administrator to invite you — the invitation link "+
					"will set up your account.")
		}
	}
	if err := s.auth.Signup(ctx, string(req.Body.Email), name, req.Body.Password); err != nil {
		return nil, err
	}
	return api.Signup202JSONResponse{
		Body:    api.GenericMessage{Message: "If that email can be registered, a verification link has been sent."},
		Headers: api.Signup202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// loginResponse is a custom oapi response object: its Visit sets the session cookie
// ONLY when the login fully authenticated (setCookie). On an MFA challenge (D6) no
// cookie is set — the pending state is a challenge token, never a session.
type loginResponse struct {
	body      api.LoginResult
	sess      session.Session
	setCookie bool
	secure    bool
	requestID string
}

func (r loginResponse) VisitLoginResponse(w http.ResponseWriter) error {
	if r.setCookie {
		session.SetCookie(w, r.sess, r.secure)
	}
	w.Header().Set("X-Request-Id", r.requestID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(r.body)
}

// Login verifies credentials. If the user has an armed TOTP (self-enrolled — S7.5.5 D1), NO
// session is minted; a challenge token is returned and the client completes at /auth/mfa/verify.
// Otherwise a fresh session is established (fixation-safe).
func (s apiServer) Login(ctx context.Context, req api.LoginRequestObject) (api.LoginResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	user, err := s.auth.Authenticate(ctx, string(req.Body.Email), req.Body.Password)
	if err != nil {
		return nil, err
	}
	reqID := middleware.GetReqID(ctx)

	if s.mfa != nil {
		challenged, cerr := s.mfa.HasConfirmedTOTP(ctx, user.ID)
		if cerr != nil {
			return nil, cerr
		}
		if challenged {
			token, ttl, e := s.mfa.CreateChallenge(ctx, user.ID)
			if e != nil {
				return nil, e
			}
			return loginResponse{body: api.LoginResult{MfaRequired: true, Challenge: &token, ChallengeExpiresIn: &ttl}, requestID: reqID}, nil
		}
	}

	// D8 grandfather: unenrolled user in an enforcing org gets a GATED session (enterprise only) —
	// authenticated, but the middleware restricts it to enrollment until a confirmed TOTP exists.
	// Resolve the gate state BEFORE minting the session so a resolution error fails the login
	// cleanly (no dangling session, no guessed flag — finding #4).
	enrollmentRequired := false
	if s.mfaEnforceEnabled && s.mfa != nil {
		gated, gerr := s.mfa.IsEnrollmentGated(ctx, user.ID)
		if gerr != nil {
			return nil, gerr
		}
		enrollmentRequired = gated
	}
	sess, err := s.sessions.Create(ctx, user.ID, authctx.AuthLocalPassword)
	if err != nil {
		return nil, err
	}
	au := authUser(user)
	result := api.LoginResult{MfaRequired: false, User: &au}
	if enrollmentRequired {
		tr := true
		au.MfaEnrollmentRequired = &tr
		result.User = &au
		result.EnrollmentRequired = &tr
	}
	return loginResponse{body: result, sess: sess, setCookie: true, secure: s.cookieSecure, requestID: reqID}, nil
}

func authUser(user sqlc.User) api.AuthUser {
	// ⚠ `cp_admin` RIDES ON THE USER ROW, and it is the only deployment-scoped authority this
	// product has. The UI uses it to decide whether to OFFER creating an organization; the server refuses
	// regardless (tenancy.checkMayCreateOrg), so a client that lies about it gains nothing — this is an
	// affordance hint, never the boundary.
	may := user.CpAdmin
	mustChange := user.MustChangePassword
	return api.AuthUser{
		Id: user.ID, Email: openapi_types.Email(user.Email),
		EmailVerified: user.EmailVerifiedAt.Valid, CpAdmin: &may,
		MustChangePassword: &mustChange,
	}
}

// logoutResponse clears the session cookie in its Visit.
type logoutResponse struct {
	secure    bool
	requestID string
}

func (r logoutResponse) VisitLogoutResponse(w http.ResponseWriter) error {
	session.ClearCookie(w, r.secure)
	w.Header().Set("X-Request-Id", r.requestID)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ResendVerification re-sends the current user's email-verification link. Session
// gated; idempotent (202 even if already verified — reveals nothing).
func (s apiServer) ResendVerification(ctx context.Context, _ api.ResendVerificationRequestObject) (api.ResendVerificationResponseObject, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	if err := s.auth.ResendVerification(ctx, p.UserID); err != nil {
		return nil, err
	}
	return api.ResendVerification202JSONResponse{
		Body:    api.GenericMessage{Message: "If your email is unverified, a verification link has been sent."},
		Headers: api.ResendVerification202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CurrentUser returns the session's user (for SPA auth rehydration on load), or
// 401 if there is no valid session. The principal is attached by SessionAuth.
func (s apiServer) CurrentUser(ctx context.Context, _ api.CurrentUserRequestObject) (api.CurrentUserResponseObject, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	// ⛔ THIS PROJECTION IS BUILT BY HAND AND authUser() EXISTS — one truth, written twice, and the copies
	// drifted. `cp_admin` and `must_change_password` were added to authUser() (used by LOGIN) and
	// never reached here (used by every page load), so both worked once and vanished on refresh: the
	// switcher's "+ New" disappeared, and the forced-password redirect never fired at all because the SPA
	// rehydrates from THIS response.
	//
	// ⚠ Not collapsed into authUser() here because that takes a sqlc.User and this has only a Principal —
	// the real fix is one projection over one type, and it is registered rather than done mid-hotfix.
	mustChange := p.MustChangePassword
	mayCreate := p.CPAdmin
	au := api.AuthUser{
		Id:                 p.UserID,
		Email:              openapi_types.Email(p.Email),
		EmailVerified:      p.EmailVerified,
		MustChangePassword: &mustChange,
		CpAdmin:            &mayCreate,
	}
	// Carry the gate state so a gated client (session minted, enrollment-restricted) can route to
	// the enrollment ceremony rather than hit dead 403s. Enterprise only. The gate-state error is
	// NEVER swallowed (finding #4): guessing false would route a gated user into the app (where the
	// middleware still 403s) and guessing true would gate a healthy one — so on a resolution error
	// we SURFACE it (loadOne applied server-side), not invent an answer in either direction.
	if s.mfaEnforceEnabled && s.mfa != nil {
		gated, gerr := s.mfa.IsEnrollmentGated(ctx, p.UserID)
		if gerr != nil {
			return nil, gerr
		}
		if gated {
			tr := true
			au.MfaEnrollmentRequired = &tr
		}
	}
	if s.mfa != nil {
		if enrolled, _ := s.mfa.HasConfirmedTOTP(ctx, p.UserID); enrolled {
			if n, e := s.mfa.CountRecoveryRemaining(ctx, p.UserID); e == nil {
				nn := n
				au.RecoveryCodesRemaining = &nn
			}
		}
	}
	return api.CurrentUser200JSONResponse{
		Body:    au,
		Headers: api.CurrentUser200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// Logout revokes the current session and clears the cookie.
func (s apiServer) Logout(ctx context.Context, _ api.LogoutRequestObject) (api.LogoutResponseObject, error) {
	if p, ok := authctx.PrincipalFrom(ctx); ok && p.SessionID != "" {
		_ = s.sessions.Delete(ctx, p.SessionID)
	}
	return logoutResponse{secure: s.cookieSecure, requestID: middleware.GetReqID(ctx)}, nil
}

// VerifyEmail implements POST /api/v1/auth/verify-email.
func (s apiServer) VerifyEmail(ctx context.Context, req api.VerifyEmailRequestObject) (api.VerifyEmailResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.auth.VerifyEmail(ctx, req.Body.Token); err != nil {
		return nil, err
	}
	return api.VerifyEmail200JSONResponse{
		Body:    api.GenericMessage{Message: "Email verified."},
		Headers: api.VerifyEmail200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RequestPasswordReset implements POST /api/v1/auth/password-reset. Always
// returns the same generic result to avoid enumeration.
func (s apiServer) RequestPasswordReset(ctx context.Context, req api.RequestPasswordResetRequestObject) (api.RequestPasswordResetResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.auth.RequestPasswordReset(ctx, string(req.Body.Email)); err != nil {
		return nil, err
	}
	return api.RequestPasswordReset202JSONResponse{
		Body:    api.GenericMessage{Message: "If that email is registered, a reset link has been sent."},
		Headers: api.RequestPasswordReset202ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ConfirmPasswordReset implements POST /api/v1/auth/password-reset/confirm.
func (s apiServer) ConfirmPasswordReset(ctx context.Context, req api.ConfirmPasswordResetRequestObject) (api.ConfirmPasswordResetResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.auth.ResetPassword(ctx, req.Body.Token, req.Body.Password); err != nil {
		return nil, err
	}
	return api.ConfirmPasswordReset200JSONResponse{
		Body:    api.GenericMessage{Message: "Password updated."},
		Headers: api.ConfirmPasswordReset200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ChangePassword implements POST /api/v1/auth/password.
//
// ⛔ THE ONLY WAY OUT OF A FORCED PASSWORD CHANGE, AND THEREFORE THE ONE AUTHENTICATED ROUTE THAT MUST NOT
// BE BLOCKED BY ONE. It deliberately does not go through `authorize()` — that is org-scoped and carries the
// `password_change_required` wall, so routing this through it would make the forced change a LOCKOUT with
// no recovery: the bootstrap admin belongs to no organization and there is no signup to replace them.
//
// ⚠ THE CURRENT PASSWORD IS REQUIRED EVEN THOUGH THE CALLER IS AUTHENTICATED. A live session is not proof
// of knowing the credential — a borrowed browser is enough — and this is the act that makes a printed,
// log-visible password permanent.
func (s apiServer) ChangePassword(ctx context.Context, req api.ChangePasswordRequestObject) (api.ChangePasswordResponseObject, error) {
	p, err := requireVerifiedUserAllowingPasswordChange(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if err := s.auth.ChangePassword(ctx, p.UserID, req.Body.CurrentPassword, req.Body.NewPassword); err != nil {
		return nil, err
	}
	return api.ChangePassword204Response{
		Headers: api.ChangePassword204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}
