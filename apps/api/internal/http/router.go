// Package http wires the API's HTTP routes and middleware. Routes are mounted
// from the generated OpenAPI server (internal/api) so the wire contract is the
// spec, not hand-written handlers.
package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	oapimw "github.com/oapi-codegen/nethttp-middleware"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/hostupgrade"
	"github.com/tunnexio/tunnex/apps/api/internal/invites"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	applog "github.com/tunnexio/tunnex/apps/api/internal/log"
	"github.com/tunnexio/tunnex/apps/api/internal/machineauth"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpn"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sites"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// AuthFunc resolves the authenticated principal for a request, or nil if the
// request is unauthenticated. SessionAuth is the session-backed implementation.
type AuthFunc func(r *http.Request) *authctx.Principal

// Deps are the router's dependencies.
type Deps struct {
	System             *sqlc.Queries // deployment-wide settings (gateway control endpoint, licence, etc.)
	Orgs               *tenancy.Service
	CliAuth            *cliauth.Service
	Auth               *auth.Service
	Members            *tenancy.MembershipService
	Invites            *invites.Service
	Nodes              *nodes.Service
	AgentRuntimeOptIn  agentruntime.OptInFunc
	AgentRuntimeNotify agentruntime.Notifier
	AlertPublisher     alerts.Publisher
	AlertConfig        *alerts.ConfigService
	Devices            *devices.Service
	Ovpn               *ovpn.Service // OPEN (D-S9.1-6): OpenVPN PKI + export. CA loads lazily (D-S9.5-OPTIN a)
	Sites              *sites.Service
	K8s                *k8s.Service         // OPEN (all editions, S10.3): K8s cluster/Service connectivity
	Machine            *machineauth.Service // OPEN (S10.2): machine credentials (GitOps operator identity)
	// Licence is the entitlement source. ⚠ Never nil in production; a nil manager would mean Community,
	// which is the fail-open default rather than a failure.
	Licence        *licence.Manager
	Sessions       *session.Store
	Mfa            *mfa.Service      // OPEN (all editions): TOTP enrollment + login challenge (S7.5.5)
	SSO            ssoPort           // nil => open build (SSO endpoints return edition_required)
	Policy         policyPort        // nil => open build (policy endpoints return edition_required)
	AgentTemplates agentTemplatePort // nil => open build (F09 endpoints return edition_required)
	AgentAccess    agentAccessPort   // licence-gated (F10 endpoints return edition_required when unentitled)
	AccessLog      accessLogPort     // nil => open build (access-log endpoints return edition_required)
	IdpSync        idpSyncPort       // nil => open build (idp-sync endpoints return edition_required)
	// DeviceApprovalEnabled => false in the open build (S7.3 device posture endpoints
	// return edition_required). Named per-feature (NewDeviceApprovalEdition).
	DeviceApprovalEnabled bool
	// DeviceHealthEnabled => false in the open build (S7.5.3 device health/posture-check
	// endpoints return edition_required). Named per-feature (NewDeviceHealthEdition).
	DeviceHealthEnabled bool
	// MfaEnforceEnabled => false in the open build (S7.5.5 org enforce + admin-reset endpoints
	// return edition_required, and the enrollment gate never engages). NewMfaEnforceEdition().
	MfaEnforceEnabled bool
	CookieSecure      bool
	AppBaseURL        string
	GatewayControlURL string
	NodeAgentImage    string
	ReleaseStatus     *release.Status
	ReleaseBootstrap  *release.BootstrapRelease
	// ReleaseStatusProvider supplies an atomically refreshed, verified online
	// release status. Host mutation remains isolated in HostUpgrade's local runner.
	ReleaseStatusProvider func() *release.Status
	HostUpgrade           *hostupgrade.Service
	// ⛔ SMTPConfigured — whether this deployment can send mail. Served by /meta so a screen can warn
	// BEFORE the operator acts rather than after a recipient never receives a link.
	SMTPConfigured bool
	// CORSAllowedOrigins are exact origins allowed cross-origin bearer access
	// (S6.2 desktop; app://tunnex). Empty = no CORS (pure same-origin).
	CORSAllowedOrigins []string
	AuthFn             AuthFunc
	// BearerFn resolves a CLI bearer credential (S5.1). Tried BEFORE the cookie
	// session; any invalid bearer (unknown/revoked/expired) is one generic 401
	// (no oracle) — the CLI recognizes expiry from its local expires_at.
	BearerFn BearerAuthFunc
	// MachineFn resolves a MACHINE credential (S10.2, `tnxm_`). Tried before the CLI bearer + cookie; a
	// distinct prefix means no collision. Same no-oracle refusal. A machine principal has no UserID and
	// attributes downstream mutations to a system actor.
	MachineFn BearerAuthFunc
}

// NewRouter builds the API router with the standard middleware chain and mounts
// the generated OpenAPI handlers.
//
// Middleware order matters: RequestID runs before the structured logger so the
// correlation ID is available when the access log is written; the OpenAPI
// validator runs before handlers so malformed requests never reach them.
func NewRouter(logger *slog.Logger, d Deps) (http.Handler, error) {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	// S13.1 (review #1 + #4): the RE-KEY throttle is registered BEFORE middleware.RealIP, and the order is the
	// whole fix.
	//
	// RealIP OVERWRITES r.RemoteAddr from client-supplied True-Client-IP / X-Real-IP / leftmost X-Forwarded-For.
	// Registered after it, the throttle keyed on a value the CALLER chooses — so varying one header gave every
	// request a fresh bucket and the cap never engaged, on an unauthenticated route that performs RSA
	// verification. chi's own RealIP is deprecated upstream as IP-spoofable for exactly this reason.
	//
	// Running before RealIP means the throttle sees the raw peer address, which the caller cannot forge. It also
	// puts it ahead of the OpenAPI request validator, so a refused request no longer pays a full body decode
	// first — the amplification the throttle exists to prevent was being spent before the throttle was consulted.
	r.Use(rekeyOnly(newRekeyThrottle(rekeyAttemptsPerMinute)))

	r.Use(middleware.RealIP)
	// CORS runs early: it answers cross-origin preflights (OPTIONS) for the
	// allowlisted desktop origin before auth/validation, and never sends
	// Allow-Credentials (bearer only, cookies never cross) so the same-origin
	// cookie/CSRF posture is untouched. No-op when the allowlist is empty.
	if len(d.CORSAllowedOrigins) > 0 {
		r.Use(corsBearer(d.CORSAllowedOrigins))
	}
	r.Use(applog.Requests(logger))
	r.Use(middleware.Recoverer)
	r.Use(requestTimeout(30*time.Second, 65*time.Second))
	// API responses are never cacheable: some carry one-time secrets (a device's
	// server-generated private key / .conf), and none should be stored by an
	// intermediary proxy or the browser.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, req)
		})
	})

	// Attach the authenticated principal (if any) so downstream authorization can
	// fail closed. The org used for scoping is derived from this principal's
	// memberships, never from client input. A CLI bearer credential (S5.1) is
	// tried FIRST: bearer ≡ cookie for authorization. Any invalid bearer
	// (unknown/revoked/expired) is one generic 401 (no oracle); the CLI knows
	// its own expiry from the locally-stored expires_at.
	//
	// PRECEDENCE (intended): a request carries EITHER a bearer OR a cookie in
	// practice — the CLI sends no cookie and a browser never attaches an
	// Authorization header cross-site. An invalid bearer resolves to (nil,nil)
	// and falls through to the cookie path; a VALID bearer wins outright. A stale
	// bearer is therefore never a way to assume a cookie identity. The error
	// return of BearerFn is retained for a future path that needs a distinct
	// refusal; today it is always nil.
	if d.AuthFn != nil || d.BearerFn != nil || d.MachineFn != nil {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				// A MACHINE credential (`tnxm_`) is tried first; its prefix can't collide with the CLI's
				// `tnx_`, and an invalid one is (nil,nil) → falls through, never assumes a cookie identity.
				if d.MachineFn != nil {
					p, err := d.MachineFn(req)
					if err != nil {
						apierr.Write(w, req, err)
						return
					}
					if p != nil {
						next.ServeHTTP(w, req.WithContext(authctx.WithPrincipal(req.Context(), p)))
						return
					}
				}
				if d.BearerFn != nil {
					p, err := d.BearerFn(req)
					if err != nil {
						apierr.Write(w, req, err)
						return
					}
					if p != nil {
						next.ServeHTTP(w, req.WithContext(authctx.WithPrincipal(req.Context(), p)))
						return
					}
				}
				if d.AuthFn != nil {
					if p := d.AuthFn(req); p != nil {
						req = req.WithContext(authctx.WithPrincipal(req.Context(), p))
					}
				}
				next.ServeHTTP(w, req)
			})
		})
	}

	// CSRF protection for cookie-authenticated state changes.
	r.Use(csrfGuard)

	// S8.6 #6 compat shim: oapi-codegen's strict server decodes a JSON body UNCONDITIONALLY even
	// when the spec marks it optional (required: false) — a BODYLESS DELETE …/sites/{id}/bind (the
	// legacy caller shape #6 exists for) died on an EOF decode error BEFORE auth: sessionless
	// requests got 500 instead of 401 (the no-oracle posture broken) and the bodyless
	// sole-gateway path was unreachable over real HTTP (the unit tests constructed RequestObjects
	// directly — the fixture-fidelity trap; the spec-driven wire walk caught it). Rewrite the
	// empty body to the empty JSON object so the optional body is ACTUALLY optional on the wire.
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodDelete && req.ContentLength == 0 &&
				strings.Contains(req.URL.Path, "/sites/") && strings.HasSuffix(req.URL.Path, "/bind") {
				req.Body = io.NopCloser(strings.NewReader("{}"))
				req.ContentLength = 2
				req.Header.Set("Content-Type", "application/json")
			}
			next.ServeHTTP(w, req)
		})
	})

	// Runtime authentication must run before OpenAPI validation. Otherwise a
	// sessionless runtime request with a missing required query/body is answered
	// 400 by the validator before the machine bearer can be refused uniformly.
	// The same early boundary is needed for the human quota mutation; valid
	// sessions still proceed to strict validation and receive 400 for malformed
	// bodies.
	agentRuntime := agentruntime.New(d.System, d.AgentRuntimeOptIn)
	agentRuntime.SetNotifier(d.AgentRuntimeNotify)
	agentRuntime.SetAlertPublisher(d.AlertPublisher)
	r.Use(runtimeAuthMiddleware(agentRuntime))
	r.Use(authBeforeAgentValidation)

	// Validate every request against the spec; render failures as the envelope.
	swagger, err := api.GetSwagger()
	if err != nil {
		return nil, err
	}
	swagger.Servers = nil // don't enforce a server URL (we run behind nginx)
	r.Use(oapimw.OapiRequestValidatorWithOptions(swagger, &oapimw.Options{
		ErrorHandler: validationErrorHandler,
		Options: openapi3filter.Options{
			// The validator must NOT enforce security itself — authentication and
			// authorization are done in our handlers (authorize/requireVerifiedUser),
			// which produce the typed envelope. A noop here means "auth handled
			// elsewhere"; without it the validator would 401 even valid sessions.
			AuthenticationFunc: func(context.Context, *openapi3filter.AuthenticationInput) error { return nil },
		},
	}))

	srv := apiServer{system: d.System, orgs: d.Orgs, licence: licenceOrCommunity(d.Licence), cliAuth: d.CliAuth, auth: d.Auth, members: d.Members, invites: d.Invites, nodes: d.Nodes, agentRuntime: agentRuntime, alertConfig: d.AlertConfig, devices: d.Devices, ovpn: d.Ovpn, sites: d.Sites, k8s: d.K8s, machine: d.Machine, sessions: d.Sessions, mfa: d.Mfa, sso: d.SSO, policy: d.Policy, agentTemplates: d.AgentTemplates, agentAccess: d.AgentAccess, accessLog: d.AccessLog, idpSync: d.IdpSync, deviceApprovalEnabled: d.DeviceApprovalEnabled, deviceHealthEnabled: d.DeviceHealthEnabled, mfaEnforceEnabled: d.MfaEnforceEnabled, cookieSecure: d.CookieSecure, appBaseURL: d.AppBaseURL, gatewayControlURL: d.GatewayControlURL, nodeAgentImage: d.NodeAgentImage, smtpConfigured: d.SMTPConfigured, releaseStatus: d.ReleaseStatus, releaseStatusProvider: d.ReleaseStatusProvider, releaseBootstrap: d.ReleaseBootstrap, hostUpgrade: d.HostUpgrade}
	// Default-deny MFA-enrollment gate (S7.5.5 D8, enterprise): runs after auth attaches the
	// principal; a gated user is restricted to enrollment. Registered before the routes so it
	// wraps every operation (self-arming — a new endpoint is gated by construction).
	gate, err := srv.mfaEnrollmentGate(swagger)
	if err != nil {
		return nil, err
	}
	r.Use(gate)

	strict := api.NewStrictHandlerWithOptions(srv, nil, api.StrictHTTPServerOptions{
		// Both hooks render typed *apierr.Error (and anything else) as the envelope.
		RequestErrorHandlerFunc:  apierr.Write,
		ResponseErrorHandlerFunc: apierr.Write,
	})
	api.HandlerFromMux(strict, r)

	return r, nil
}

// requestTimeout preserves the API-wide deadline while leaving the managed
// runtime poll to its own OpenAPI-bounded wait_seconds timer. The poll contract
// permits a 60-second hold (the shipped client uses 30 seconds), so wrapping it
// in the generic 30-second deadline creates a race at the default and makes the
// upper half of the documented range impossible. Client cancellation and
// server shutdown still cancel the request context. A separate 65-second route
// deadline bounds the complete handler, including database reads around the
// maximum 60-second hold, while skipping only the shorter generic deadline.
func requestTimeout(timeout, runtimePollTimeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		timed := middleware.Timeout(timeout)(next)
		pollTimed := middleware.Timeout(runtimePollTimeout)(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/agent/runtime/poll" {
				pollTimed.ServeHTTP(w, r)
				return
			}
			timed.ServeHTTP(w, r)
		})
	}
}

// validationErrorHandler renders spec-validation failures as the error envelope.
// The middleware callback lacks the request, so request_id is omitted here.
func validationErrorHandler(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    "validation_failed",
			"message": message,
		},
	})
}

func authBeforeAgentValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		orgPath := strings.HasPrefix(req.URL.Path, "/api/v1/organizations/")
		protectedAgentMutation := req.Method == http.MethodPut &&
			(strings.HasSuffix(req.URL.Path, "/agent-quota") || strings.HasSuffix(req.URL.Path, "/agent-runtime-settings"))
		// Alerting carries write-only destination credentials. Authenticate before
		// schema validation so an anonymous caller cannot use malformed bodies or
		// a guessed destination identifier to probe the surface.
		protectedAlerting := strings.Contains(req.URL.Path, "/alerting-settings") || strings.Contains(req.URL.Path, "/alert-destinations")
		if orgPath && (protectedAgentMutation || protectedAlerting) {
			if _, ok := authctx.PrincipalFrom(req.Context()); !ok {
				apierr.Write(w, req, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required"))
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

// licenceOrCommunity guarantees a usable manager.
//
// ⛔ THE FAIL-OPEN DEFAULT, AND IT IS HERE SO THERE IS NO WINDOW WHERE A CAPABILITY ASKS AND NOTHING
// ANSWERS. A nil *Manager would panic on the first entitlement question; an empty one answers "Community",
// which is exactly what a deployment with no licence is entitled to.
func licenceOrCommunity(m *licence.Manager) *licence.Manager {
	if m == nil {
		return &licence.Manager{}
	}
	return m
}
