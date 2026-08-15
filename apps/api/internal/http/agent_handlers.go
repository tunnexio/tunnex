package http

import (
	"context"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func (s apiServer) IssueAgentBootstrapToken(ctx context.Context, req api.IssueAgentBootstrapTokenRequestObject) (api.IssueAgentBootstrapTokenResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, apierr.New(http.StatusForbidden, "edition_required", "managed agent enrollment is a Tunnex Enterprise feature")
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if s.releaseBootstrap == nil {
		return nil, apierr.New(http.StatusServiceUnavailable, "bootstrap_unavailable", "managed agent enrollment is temporarily unavailable")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	tok, err := s.devices.IssueAgentBootstrapToken(ctx, p.UserID, req.OrgId, req.Body.GatewayId, req.Body.Name)
	if err != nil {
		return nil, err
	}
	return api.IssueAgentBootstrapToken201JSONResponse{Body: api.AgentBootstrapTokenResponse{BootstrapToken: tok, Release: toAPIBootstrapRelease(*s.releaseBootstrap)}, Headers: api.IssueAgentBootstrapToken201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

func toAPIBootstrapRelease(r release.BootstrapRelease) api.AgentBootstrapRelease {
	return api.AgentBootstrapRelease{
		Tag: r.Tag, SourceSha: r.SourceSHA, ManifestUrl: r.ManifestURL, VerifierKeyId: r.VerifierKeyID,
		Runtime: api.AgentBootstrapRuntimeRelease{
			Binary: api.TunnexAgentRuntime, Version: r.Runtime.Version,
			LinuxAmd64: toAPIBootstrapAsset(r.Runtime.LinuxAMD64),
			LinuxArm64: toAPIBootstrapAsset(r.Runtime.LinuxARM64),
			Unit:       toAPIBootstrapAsset(r.Runtime.Unit),
		},
	}
}

func toAPIBootstrapAsset(a release.RuntimeAsset) api.AgentBootstrapRuntimeAsset {
	return api.AgentBootstrapRuntimeAsset{Name: a.Name, Sha256: a.SHA256, SourceSha: a.SourceSHA}
}

// SetOrganizationAgentQuota updates the explicit nullable enterprise quota.
// Permission is checked before the edition gate to preserve no-oracle policy.
func (s apiServer) SetOrganizationAgentQuota(ctx context.Context, req api.SetOrganizationAgentQuotaRequestObject) (api.SetOrganizationAgentQuotaResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	org, err := s.orgs.SetAgentQuota(ctx, req.OrgId, req.Body.MaxAgentIdentities)
	if err != nil {
		return nil, err
	}
	return api.SetOrganizationAgentQuota200JSONResponse{Body: toAPIOrg(org), Headers: api.SetOrganizationAgentQuota200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// SetOrganizationAgentRuntimeEnabled is the explicit F04 organization
// on-switch. Permission is checked before edition so unauthorized callers
// cannot use this endpoint as an entitlement oracle.
func (s apiServer) SetOrganizationAgentRuntimeEnabled(ctx context.Context, req api.SetOrganizationAgentRuntimeEnabledRequestObject) (api.SetOrganizationAgentRuntimeEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentRuntimeManage)
	if err != nil {
		return nil, err
	}
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	org, err := s.orgs.SetAgentRuntimeEnabled(ctx, req.OrgId, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return api.SetOrganizationAgentRuntimeEnabled200JSONResponse{
		Body:    api.AgentRuntimeSetting{Enabled: org.ManagedAgentRuntimeEnabled},
		Headers: api.SetOrganizationAgentRuntimeEnabled200ResponseHeaders{XRequestId: reqID(ctx)},
	}, nil
}

func (s apiServer) BootstrapAgent(ctx context.Context, req api.BootstrapAgentRequestObject) (api.BootstrapAgentResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if req.Body.PublicKey == "" {
		return nil, apierr.BadRequest("invalid_wg_key", "public_key is required")
	}
	res, err := s.devices.Create(ctx, devices.CreateInput{PublicKey: req.Body.PublicKey, BootstrapToken: req.Body.BootstrapToken})
	if err != nil {
		return nil, err
	}
	return api.BootstrapAgent200JSONResponse{Body: api.AgentBootstrapResponse{Device: toAPIDevice(res.Device), Config: res.Config, RuntimeCredential: res.RuntimeCredential}, Headers: api.BootstrapAgent200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

// ListAgents GET /api/v1/organizations/{orgId}/agents — S15.3.
//
// ⛔ PERMISSION BEFORE EDITION, and the order is enforced by `TestEditionGateNeverPrecedesPermissionGate`
// (which harvests gate-helper names from source, so a new helper cannot slip past). Checking the edition
// first would tell an unauthorized caller which editions a feature belongs to — an edition oracle, answered
// to someone who was never entitled to ask.
//
// ⚠ AND `403 edition_required` IS A SUCCESSFUL REFUSAL, NOT A FAILURE. The open edition must render ABSENCE
// — no section, no styled-away control, no error. Folding this into the failed state would show "could not
// load" for a server that answered correctly, which is the load-failed/none confusion under a new name.
func (s apiServer) ListAgents(ctx context.Context, req api.ListAgentsRequestObject) (api.ListAgentsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	role, _ := principal.RoleIn(req.OrgId)
	canViewOwners := rbac.Can(role, rbac.PermMemberManage)
	if s.policy == nil || (s.licence != nil && s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity) {
		return nil, policyEditionRequired()
	}
	rows, err := s.nodes.ListAgents(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Agent, 0, len(rows))
	for _, r := range rows {
		a := api.Agent{
			DeviceId:       r.DeviceID,
			Name:           r.Name,
			NodeId:         &r.NodeID,
			GatewayName:    r.GatewayName,
			Status:         r.Status,
			Unattributable: r.OwnerEmail == nil,
		}
		if canViewOwners || (r.OwnerUserID != uuid.Nil && r.OwnerUserID == principal.UserID) {
			a.OwnerEmail = r.OwnerEmail
		}
		a.Address = r.Address

		// ⛔ `config_issued` IS NOT LIVENESS AND NO LONGER PRETENDS TO BE. It was named `connected` and
		// computed exactly this way, so an agent that had never once handshaked reported connected: the
		// field described the row's shape and was read as a statement about the network.
		configIssued := r.PublicKey != ""
		a.ConfigIssued = &configIssued

		if r.LastHandshakeAt.Valid {
			hs := r.LastHandshakeAt.Time
			a.LastHandshakeAt = &hs
		}
		a.RxBytes = r.RxBytes
		a.TxBytes = r.TxBytes

		// ⛔ THE SAME HELPER AND THEREFORE THE SAME WINDOW AS A HUMAN DEVICE. An agent is a peer; if its
		// online-ness were derived here against a locally-chosen threshold, the two surfaces would disagree
		// about the same handshake and neither would be wrong on its own terms.
		online := deviceOnline(a.LastHandshakeAt)
		a.Online = &online

		// ⛔ AND WHETHER THE REPORTER ITSELF IS ALIVE, because a silent gateway and a dead agent produce an
		// IDENTICAL absence of handshakes. The agent has no control-plane channel of its own — it runs
		// wg-quick — so the gateway's status push is the only thing that can ever say an agent is up.
		// Without this field the UI would render a confident "offline" about an agent it has no information
		// on, which is the three-states-one-appearance failure the EPIC 15 walk was nearly ruined by.
		//
		// ⛔ AND IT WATCHES THE STATUS CHANNEL, NOT THE REPORT CHANNEL. The gateway runs two independent
		// loops at the same 30s cadence: `/agent/report` bumps `nodes.last_seen_at`, `/agent/status` carries
		// the peer handshakes. Reading `last_seen_at` would be watching the wrong loop — if the status push
		// alone failed, the gateway would look perfectly healthy while no handshake data arrived, and every
		// agent on it would read a confident "never connected". `device_status.updated_at` is stamped BY the
		// status upsert, so it is the freshness of the channel the evidence actually travels on.
		//
		// The `last_seen_at` fallback covers exactly one case the status clock cannot: an agent created so
		// recently that no push has mentioned it yet has no `device_status` row at all, and treating that as
		// a dead reporter would hide the actionable "never connected" behind an unknown for the first 30s.
		gwReporting := agentGatewayReporting(r.StatusReportedAt, r.GatewayLastSeenAt)
		a.GatewayReporting = &gwReporting

		out = append(out, a)
	}
	return api.ListAgents200JSONResponse{Body: out, Headers: api.ListAgents200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// agentGatewayReporting — extracted so it can be pinned in BOTH directions without a database.
//
// ⚠ A DERIVATION THAT ONLY EVER RUNS BEHIND A QUERY IS A DERIVATION NOTHING TESTS. Inverted, this function
// would still satisfy every TypeScript test on the consuming screen, because those tests supply the field
// rather than compute it.
func agentGatewayReporting(statusReportedAt, gatewayLastSeenAt pgtype.Timestamptz) bool {
	if statusReportedAt.Valid {
		return deviceOnline(&statusReportedAt.Time)
	}
	return gatewayLastSeenAt.Valid && deviceOnline(&gatewayLastSeenAt.Time)
}
