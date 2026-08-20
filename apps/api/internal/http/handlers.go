package http

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/alerts"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/auth"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/cliauth"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/invites"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/machineauth"
	"github.com/tunnexio/tunnex/apps/api/internal/mfa"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/ovpn"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
	"github.com/tunnexio/tunnex/apps/api/internal/sites"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// authorize fails closed and permission-gates a request against orgID:
//   - no principal            -> 401 unauthenticated
//   - principal not a member  -> 404 (not 403): no cross-tenant existence leak
//   - member lacking the perm -> 403 forbidden
//
// On success it returns the org-scoped context. Call sites pass a Permission,
// never a role, so the policy stays in package rbac.
// machineID returns the caller's machine-credential id (S10.2) when the principal is a MACHINE, else
// uuid.Nil (a human → the ownership marker is NULL/inert). Used by the create handlers to record who
// operator-created an object.
func machineID(ctx context.Context) uuid.UUID {
	p, _ := authctx.PrincipalFrom(ctx)
	if p == nil {
		return uuid.Nil
	}
	return p.MachineID
}

// auditActor returns the (actorUserID, actorSystem, cause) attribution for the caller — machine → SYSTEM
// actor + cause (the CR, via X-Tunnex-Cause), human → user id. The ONE seam create + delete audits share so
// an operator-driven mutation never masquerades as a human (D3). Nil-safe (unauthenticated → zero human).
func auditActor(ctx context.Context) (uuid.UUID, string, string) {
	p, _ := authctx.PrincipalFrom(ctx)
	if p == nil {
		return uuid.Nil, "", ""
	}
	return p.AuditActor()
}

func authorize(ctx context.Context, orgID uuid.UUID, perm rbac.Permission) (context.Context, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return ctx, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	// ⛔ A FORCED PASSWORD CHANGE IS A WALL, NOT A SUGGESTION. The bootstrap credential was printed to the
	// logs — shipped, aggregated, searchable — so it is compromised the moment it is useful. Until it is
	// replaced the principal may authenticate and may do NOTHING ELSE.
	//
	// ⚠ THE GATE IS HERE, IN authorize(), WHICH EVERY ORG-SCOPED ROUTE PASSES THROUGH. A screen the client
	// could skip, or a check on a handful of handlers, would leave the API open to a credential that is
	// public by construction — and "not by API, not by skipping the screen" was the ruling.
	if p.MustChangePassword {
		return ctx, apierr.New(http.StatusForbidden, "password_change_required",
			"This account is still using its one-time bootstrap password. Set a new password before "+
				"doing anything else.")
	}
	role, member := p.RoleIn(orgID)
	if !member {
		return ctx, apierr.NotFound("org_not_found", "organization not found")
	}
	if !rbac.Can(role, perm) {
		return ctx, apierr.New(http.StatusForbidden, "forbidden", "you do not have permission to perform this action")
	}
	// Mutating actions require a verified email (S2.1 decision, enforced here) — EXCEPT a machine principal
	// (S10.2), which has no email to verify. Without this exemption every operator mutation 403s
	// email_not_verified (a machine's EmailVerified is false by construction), bricking the operator on its
	// first real call. Mirrors the MFA-enrollment gate, which already exempts AuthMachine by construction.
	if rbac.IsMutating(perm) && !p.EmailVerified && !p.IsMachine() {
		return ctx, apierr.New(http.StatusForbidden, "email_not_verified", "verify your email to perform this action")
	}
	return authctx.WithOrg(ctx, orgID), nil
}

// requireVerifiedUser requires an authenticated, verified principal (for actions
// not scoped to an existing org, e.g. creating one). Returns the principal.
// ⛔ THE FORCED CHANGE COVERS THIS PATH TOO, AND A LIVE WALK IS WHY.
//
// The gate went into authorize() first — which is ORG-SCOPED. Creating an organization has no orgId, so it
// runs through requireVerifiedUser and sailed straight past the wall: the bootstrap admin created the
// first org while still holding the password that had been printed to the logs. "No path around it — not
// by API, not by skipping the screen" was the ruling, and one route around it is all it takes.
//
// ⚠ ChangePassword is the deliberate exception and calls requireVerifiedUserAllowingPasswordChange —
// without it the wall would be a lockout with no recovery.
func requireVerifiedUser(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireVerifiedUserAllowingPasswordChange(ctx)
	if err != nil {
		return nil, err
	}
	if p.MustChangePassword {
		return nil, apierr.New(http.StatusForbidden, "password_change_required",
			"This account is still using its one-time bootstrap password. Set a new password before "+
				"doing anything else.")
	}
	return p, nil
}

// requireCPAdmin is the DEPLOYMENT-level gate: the caller holds `users.cp_admin` (S12.11).
//
// ⛔ IT WRAPS requireVerifiedUser RATHER THAN STANDING BESIDE IT, and that is the whole reason it is one
// function instead of four checks. The bootstrap admin holds `cp_admin` AND the one-time password that was
// printed to `docker compose logs` — so a hand-rolled gate that asked only "is this a holder" would let the
// public credential grant itself ownership of every organization on the deployment BEFORE the forced change.
// That is the same route-around-the-wall that create-org already shipped once (see requireVerifiedUser).
//
// ⭐ AND IT IS ASKED BESIDE RoleIn, NEVER INSIDE IT. `authorize()` is deliberately untouched by this
// feature: a `p.CPAdmin` bypass in there has exactly the blast radius of synthesising owner roles into
// Principal.Roles — every org-scoped check in the product starts returning true for tenants the caller is
// not in — it just looks smaller.
func requireCPAdmin(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return nil, err
	}
	if !p.CPAdmin {
		return nil, apierr.New(http.StatusForbidden, "cp_admin_required",
			"This action is reserved for deployment administrators.")
	}
	return p, nil
}

func requireVerifiedUserAllowingPasswordChange(ctx context.Context) (*authctx.Principal, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	if !p.EmailVerified {
		return nil, apierr.New(http.StatusForbidden, "email_not_verified", "verify your email to perform this action")
	}
	return p, nil
}

// requireVerifiedSessionUser is requireVerifiedUser PLUS a proof that the
// principal is backed by a browser SESSION, not a CLI bearer credential. It
// ENFORCES the cookie-only exception argued in the spec for CLI credential
// minting (cliAuthorize / cliDeviceApprove): a bearer-built principal has no
// SessionID (only SessionAuth sets it), so minting a NEW credential from an
// existing bearer credential — self-replication that would let a stolen token
// outlive its expiry and survive revocation of the original — is refused. The
// browser session is the human checkpoint; without this the spec's
// "cookie-session only" would be documentation, not behavior.
func requireVerifiedSessionUser(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return nil, err
	}
	if p.SessionID == "" {
		return nil, apierr.New(http.StatusForbidden, "session_required",
			"a browser session is required to authorize a CLI credential; a CLI credential cannot mint another")
	}
	return p, nil
}

// apiServer implements the generated api.StrictServerInterface. Handlers return
// typed responses on success and plain errors on failure; the strict handler's
// ResponseErrorHandlerFunc renders those errors as the standard envelope.
type apiServer struct {
	system *sqlc.Queries
	orgs   *tenancy.Service
	// licence is the entitlement source, read on every gated question. ⚠ nil => Community (fail-open).
	licence        *licence.Manager
	cliAuth        *cliauth.Service
	auth           *auth.Service
	members        *tenancy.MembershipService
	invites        *invites.Service
	nodes          *nodes.Service
	agentRuntime   *agentruntime.Service
	alertConfig    *alerts.ConfigService
	devices        *devices.Service
	ovpn           *ovpn.Service // OPEN (D-S9.1-6): OpenVPN PKI + export; nil in a stripped build
	sites          *sites.Service
	k8s            *k8s.Service         // OPEN (all editions, S10.3): K8s cluster/Service connectivity; governance is enterprise
	machine        *machineauth.Service // OPEN (S10.2): machine credentials — the GitOps operator's org identity
	sessions       *session.Store
	mfa            *mfa.Service      // OPEN (all editions): TOTP enrollment + login challenge (S7.5.5)
	sso            ssoPort           // nil in the open build
	policy         policyPort        // nil in the open build (Zero Trust, S7.1)
	agentTemplates agentTemplatePort // nil in the open build (F09)
	agentAccess    agentAccessPort   // nil in the open build (F10)
	accessLog      accessLogPort     // nil in the open build (Zero Trust visibility, S7.5.1)
	idpSync        idpSyncPort       // nil in the open build (IdP-group sync, S7.5.2)
	// ⛔ smtpConfigured — whether this deployment can send mail AT ALL. Served by /meta so the screens that
	// send mail can say so BEFORE the operator acts. Invitations are the only way anyone joins, so a
	// deployment without it is unusable while every screen reports success.
	smtpConfigured bool
	// deviceApprovalEnabled gates device posture (S7.3). NAMED per-feature (its own
	// wire files), not a proxy behind s.policy — device posture and Zero Trust policy
	// are distinct enterprise features (F2 / ledgered S12.1 refactor).
	deviceApprovalEnabled bool
	// deviceHealthEnabled gates device health / posture checks (S7.5.3) — its own
	// named per-feature edition bool (approval ≠ health: orthogonal capabilities).
	deviceHealthEnabled bool
	// mfaEnforceEnabled gates org-level MFA ENFORCE (S7.5.5) — enterprise only. Enrollment is
	// OPEN (s.mfa, all editions); only the enforce toggle + admin-reset + the enrollment gate
	// are enterprise. In the open build this is false → enforcement releases (D2 downgrade).
	mfaEnforceEnabled     bool
	cookieSecure          bool
	appBaseURL            string
	nodeAgentImage        string
	releaseStatus         *release.Status
	releaseStatusProvider func() *release.Status
	releaseBootstrap      *release.BootstrapRelease
	gatewayControlURL     string
}

const gatewayControlSettingKey = "gateway_control_url"

func (s apiServer) gatewayURL(ctx context.Context) (string, error) {
	if s.system != nil {
		value, err := s.system.GetSystemSetting(ctx, gatewayControlSettingKey)
		if err == nil && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value), nil
		}
	}
	return strings.TrimSpace(s.gatewayControlURL), nil
}

func validGatewayURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return true
}

func requireGatewayEndpointAdmin(ctx context.Context) (*authctx.Principal, error) {
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return nil, err
	}
	if p.CPAdmin {
		return p, nil
	}
	for _, role := range p.Roles {
		if rbac.Can(role, rbac.PermOrgUpdate) {
			return p, nil
		}
	}
	return nil, apierr.New(http.StatusForbidden, "gateway_endpoint_admin_required", "gateway endpoint settings require an owner or administrator")
}

func (s apiServer) GetGatewayEndpoint(ctx context.Context, _ api.GetGatewayEndpointRequestObject) (api.GetGatewayEndpointResponseObject, error) {
	if _, err := requireGatewayEndpointAdmin(ctx); err != nil {
		return nil, err
	}
	value, err := s.gatewayURL(ctx)
	if err != nil {
		return nil, err
	}
	return api.GetGatewayEndpoint200JSONResponse{Body: api.GatewayEndpoint{Url: value, Configured: value != ""}, Headers: api.GetGatewayEndpoint200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func (s apiServer) UpdateGatewayEndpoint(ctx context.Context, req api.UpdateGatewayEndpointRequestObject) (api.UpdateGatewayEndpointResponseObject, error) {
	if _, err := requireGatewayEndpointAdmin(ctx); err != nil {
		return nil, err
	}
	if req.Body == nil || !validGatewayURL(req.Body.Url) {
		return nil, apierr.BadRequest("invalid_gateway_endpoint", "use an absolute https URL with no path, query or fragment")
	}
	value := strings.TrimSpace(req.Body.Url)
	if s.system == nil {
		return nil, apierr.New(http.StatusInternalServerError, "settings_unavailable", "deployment settings are unavailable")
	}
	if err := s.system.UpsertSystemSetting(ctx, sqlc.UpsertSystemSettingParams{Key: gatewayControlSettingKey, Value: value}); err != nil {
		return nil, err
	}
	return api.UpdateGatewayEndpoint200JSONResponse{Body: api.GatewayEndpoint{Url: value, Configured: true}, Headers: api.UpdateGatewayEndpoint200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

// GetHealth implements GET /healthz.
func (apiServer) GetHealth(ctx context.Context, _ api.GetHealthRequestObject) (api.GetHealthResponseObject, error) {
	reqID := middleware.GetReqID(ctx)
	return api.GetHealth200JSONResponse{
		Body: api.HealthResponse{
			Status:    api.Ok,
			Service:   "tunnex-api",
			RequestId: &reqID,
		},
		Headers: api.GetHealth200ResponseHeaders{XRequestId: reqID},
	}, nil
}

// ListOrganizations implements GET /api/v1/organizations — scoped to the
// caller's memberships (never all orgs).
func (s apiServer) ListOrganizations(ctx context.Context, _ api.ListOrganizationsRequestObject) (api.ListOrganizationsResponseObject, error) {
	p, ok := authctx.PrincipalFrom(ctx)
	if !ok {
		return nil, apierr.New(http.StatusUnauthorized, "unauthenticated", "authentication required")
	}
	orgs, err := s.orgs.ListOrganizationsForUser(ctx, p.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]api.Organization, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, toAPIOrg(o))
	}
	return api.ListOrganizations200JSONResponse{
		Body:    out,
		Headers: api.ListOrganizations200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CreateOrganization implements POST /api/v1/organizations.
func (s apiServer) CreateOrganization(ctx context.Context, req api.CreateOrganizationRequestObject) (api.CreateOrganizationResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, err := requireVerifiedUser(ctx)
	if err != nil {
		return nil, err
	}
	org, err := s.orgs.CreateOrganization(ctx, p.UserID, req.Body.Name, req.Body.Slug)
	if err != nil {
		return nil, err // rendered as the envelope by the strict error handler
	}
	return api.CreateOrganization201JSONResponse{
		Body:    toAPIOrg(org),
		Headers: api.CreateOrganization201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// GetOrganization implements GET /api/v1/organizations/{orgId}.
func (s apiServer) GetOrganization(ctx context.Context, req api.GetOrganizationRequestObject) (api.GetOrganizationResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgView)
	if err != nil {
		return nil, err
	}
	org, err := s.orgs.GetOrganization(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	return api.GetOrganization200JSONResponse{
		Body:    toAPIOrg(org),
		Headers: api.GetOrganization200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// UpdateOrganization implements PATCH /api/v1/organizations/{orgId}.
func (s apiServer) UpdateOrganization(ctx context.Context, req api.UpdateOrganizationRequestObject) (api.UpdateOrganizationResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate)
	if err != nil {
		return nil, err
	}
	org, err := s.orgs.UpdateOrganization(ctx, req.OrgId, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return api.UpdateOrganization200JSONResponse{
		Body:    toAPIOrg(org),
		Headers: api.UpdateOrganization200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// OrgDeletionPreflight implements GET /api/v1/organizations/{orgId}/deletion-preflight.
//
// ⛔ THE SCREEN MUST BE ABLE TO SAY WHY BEFORE THE OPERATOR COMMITS. Delete refuses while the org owns
// anything, and a refusal that arrives only AFTER someone has typed the organization's name to confirm is
// a refusal they met at the most dangerous possible moment — with their attention on getting past it.
//
// ⚠ SAME PERMISSION AS THE DELETE. A preflight is only actionable to someone who could act on it, and a
// read-only permission for "what would block a delete" would need its own answer to who may see it.
func (s apiServer) OrgDeletionPreflight(ctx context.Context, req api.OrgDeletionPreflightRequestObject) (api.OrgDeletionPreflightResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgDelete); err != nil {
		return nil, err
	}
	r, err := s.orgs.OrgResourceCount(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	// ⚠ THE BLOCKER STRINGS COME FROM THE SERVICE, not from the handler and not from the client — the same
	// function the refusal message uses. Two renderings of one state is how a screen ends up saying
	// "nothing left" beside an error saying "2 gateways".
	blockers := r.Blockers()
	if blockers == nil {
		blockers = []string{}
	}
	return api.OrgDeletionPreflight200JSONResponse{
		Body: api.OrgDeletionPreflight{
			Deletable: r.Empty(), Blockers: blockers,
			Gateways: int(r.Gateways), Devices: int(r.Devices), Sites: int(r.Sites),
			Clusters: int(r.Clusters), MachineCredentials: int(r.MachineCredentials),
		},
		Headers: api.OrgDeletionPreflight200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// DeleteOrganization implements DELETE /api/v1/organizations/{orgId}.
func (s apiServer) DeleteOrganization(ctx context.Context, req api.DeleteOrganizationRequestObject) (api.DeleteOrganizationResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermOrgDelete)
	if err != nil {
		return nil, err
	}
	if err := s.orgs.SoftDeleteOrganization(ctx, req.OrgId); err != nil {
		return nil, err
	}
	return api.DeleteOrganization204Response{
		Headers: api.DeleteOrganization204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAPIOrg(o sqlc.Organization) api.Organization {
	ovpn := o.OvpnEnabled
	return api.Organization{
		Id:                          o.ID,
		Name:                        o.Name,
		Slug:                        o.Slug,
		PoolCidr:                    o.PoolCidr,
		MaxAgentIdentities:          o.MaxAgentIdentities,
		OvpnEnabled:                 &ovpn, // D-S9.5-OPTIN: the UI hides the OpenVPN device type unless this is true
		ManagedAgentRuntimeEnabled:  o.ManagedAgentRuntimeEnabled,
		AgentPolicyTemplatesEnabled: o.AgentPolicyTemplatesEnabled,
		CreatedAt:                   o.CreatedAt,
		UpdatedAt:                   o.UpdatedAt,
	}
}
