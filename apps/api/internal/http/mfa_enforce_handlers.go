package http

import (
	"context"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func mfaEnforceEditionRequired() error {
	return apierr.New(http.StatusForbidden, "edition_required", "Organization MFA enforcement is a Tunnex Enterprise feature")
}

// GetMfaEnforce GET .../mfa-enforce — read the org's MFA enforce flag (enterprise; PermMfaManage).
func (s apiServer) GetMfaEnforce(ctx context.Context, req api.GetMfaEnforceRequestObject) (api.GetMfaEnforceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMfaManage); err != nil {
		return nil, err
	}
	if !s.mfaEnforceEnabled {
		return nil, mfaEnforceEditionRequired()
	}
	on, err := s.mfa.OrgEnforces(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetMfaEnforce200JSONResponse{Body: api.MfaEnforce{Enforce: on}, Headers: api.GetMfaEnforce200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// SetMfaEnforce PUT .../mfa-enforce — toggle org MFA enforcement (enterprise; PermMfaManage;
// unlock-then-opt-in, default OFF).
func (s apiServer) SetMfaEnforce(ctx context.Context, req api.SetMfaEnforceRequestObject) (api.SetMfaEnforceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMfaManage); err != nil {
		return nil, err
	}
	if !s.mfaEnforceEnabled {
		return nil, mfaEnforceEditionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.mfa.SetOrgEnforce(ctx, req.OrgId, p.UserID, req.Body.Enforce); err != nil {
		return nil, err
	}
	return api.SetMfaEnforce200JSONResponse{Body: api.MfaEnforce{Enforce: req.Body.Enforce}, Headers: api.SetMfaEnforce200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// AdminResetMfa POST .../members/{userId}/mfa-reset — disenroll a member's MFA (enterprise;
// PermMfaManage). Disenroll-only (never authenticates as them), audited + target-notified.
func (s apiServer) AdminResetMfa(ctx context.Context, req api.AdminResetMfaRequestObject) (api.AdminResetMfaResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermMfaManage); err != nil {
		return nil, err
	}
	if !s.mfaEnforceEnabled {
		return nil, mfaEnforceEditionRequired()
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if err := s.mfa.AdminReset(ctx, req.OrgId, p.UserID, req.UserId); err != nil {
		return nil, err
	}
	return api.AdminResetMfa204Response{}, nil
}

// enrollmentGateAllow is the EXACT, minimal allowlist of operationIds a MFA-enforcement-gated user
// (org enforces + no confirmed TOTP — D8) may reach: enroll (start/confirm), sign out, and read
// their own state (me carries enrollment_required so the client can route). Everything else — incl.
// disenroll (nothing to disenroll; self-cycling) and cliAuthorize (must not birth a credential that
// outlives the gate) — is DENIED. Keyed by operationId (route identity), not path-string.
// The allowlist admits EXACTLY what a gated user needs to become UN-gated. Enrollment requires a
// verified email, so email verification is UPSTREAM of enrollment — same class as the enroll ops
// themselves (finding #5: the happy-path allowlist dead-ended the unverified+enforced intersection).
//
// CASING (S7.5.5 walk defect): keys are the operationIds AS api.GetSwagger() carries them — oapi-codegen
// normalizes them to EXPORTED (PascalCase) Go identifiers, NOT the source-yaml casing. The gate resolves
// via that embedded spec, so the keys must match it. This was camelCase and silently bricked every gated
// user (zero matches). If oapi-codegen's identifier normalization ever changes, the semantic (method,path)
// pins in TestEnrollmentGateSelfArming fail LOUDLY and the fix is a key update here — a red build, never
// a silent re-brick.
var enrollmentGateAllow = map[string]bool{
	"MfaEnrollStart":     true,
	"MfaEnrollConfirm":   true,
	"VerifyEmail":        true,
	"ResendVerification": true,
	"Logout":             true,
	"CurrentUser":        true,
}

// mfaEnrollmentGate is the DEFAULT-DENY authorization overlay for the D8 grandfather path (Option A):
// an authenticated user whose org enforces MFA but has no confirmed TOTP gets a gated session — full
// authentication, but authorization restricted to enrollment until they confirm. The gate is the
// entire security property, so it fails CLOSED: an operation whose identity can't be resolved is
// DENIED for a gated user, never passed through (an unregistered/renamed route can't become a bypass).
// Enterprise-only (s.mfaEnforceEnabled); the open build never engages it (D2 downgrade-release).
func (s apiServer) mfaEnrollmentGate(swagger *openapi3.T) (func(http.Handler) http.Handler, error) {
	// The spec's OWN request→operation matcher — resolves operationId directly from the request, so
	// a path rename that regenerates the spec keeps the operationId allowlist correct by construction.
	oapiRouter, err := gorillamux.NewRouter(swagger)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.mfaEnforceEnabled || s.mfa == nil {
				next.ServeHTTP(w, r) // open build / no MFA service: no gate (D2)
				return
			}
			p, ok := authctx.PrincipalFrom(r.Context())
			if !ok || p == nil {
				next.ServeHTTP(w, r) // unauthenticated → the auth layer owns the 401
				return
			}
			// D5 (LOCKED): org MFA enforcement applies to LOCAL-PASSWORD logins only. SSO sessions
			// (the IdP owns the second factor) and bearer credentials (CLI/automation, minted downstream
			// of a browser session that already passed MFA) are EXEMPT — by construction, via the
			// principal's immutable mint-time method, NOT a route/header sniff. This is the middleware
			// half of the exemption the login seam alone couldn't guarantee.
			if p.AuthMethod != authctx.AuthLocalPassword {
				next.ServeHTTP(w, r)
				return
			}
			gated, err := s.mfa.IsEnrollmentGated(r.Context(), p.UserID)
			if err != nil {
				apierr.Write(w, r, err) // determination failed → surface, never silently pass a gated user
				return
			}
			if !gated {
				next.ServeHTTP(w, r)
				return
			}
			// GATED: fail CLOSED on anything unresolvable or not allowlisted.
			if !gateAllows(oapiRouter, r) {
				apierr.Write(w, r, apierr.New(http.StatusForbidden, "mfa_enrollment_required",
					"Set up two-factor authentication to continue."))
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// gateAllows resolves the request's operation identity via the spec's own matcher and returns whether
// a gated user may reach it. FAIL-CLOSED: an unresolvable route (no match / renamed / no operationId)
// returns false — it can never become a bypass. Extracted so the self-arming walk can drive it over
// every spec operation without a live server.
func gateAllows(oapiRouter routers.Router, r *http.Request) bool {
	route, _, err := oapiRouter.FindRoute(r)
	if err != nil || route == nil || route.Operation == nil {
		return false
	}
	return enrollmentGateAllow[route.Operation.OperationID]
}
