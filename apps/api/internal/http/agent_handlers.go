package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/release"
)

func (s apiServer) IssueAgentBootstrapToken(ctx context.Context, req api.IssueAgentBootstrapTokenRequestObject) (api.IssueAgentBootstrapTokenResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermAgentEnroll); err != nil {
		return nil, err
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
		Tag: r.Tag, SourceSha: r.SourceSHA, ManifestUrl: r.ManifestURL, VerifierKeyId: r.VerifierKeyID, VerifierPublicKey: r.VerifierPublicKey,
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

// SetOrganizationAgentQuota updates the explicit nullable managed-agent quota.
func (s apiServer) SetOrganizationAgentQuota(ctx context.Context, req api.SetOrganizationAgentQuotaRequestObject) (api.SetOrganizationAgentQuotaResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
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
// on-switch. It is an organization setting and never enables itself.
func (s apiServer) SetOrganizationAgentRuntimeEnabled(ctx context.Context, req api.SetOrganizationAgentRuntimeEnabledRequestObject) (api.SetOrganizationAgentRuntimeEnabledResponseObject, error) {
	ctx, err := authorize(ctx, req.OrgId, rbac.PermAgentRuntimeManage)
	if err != nil {
		return nil, err
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
func (s apiServer) ListAgents(ctx context.Context, req api.ListAgentsRequestObject) (api.ListAgentsResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if req.Params.Access != nil && (s.licence == nil || !s.licence.Has(licence.FeatAgentJITAccess, time.Now())) {
		return nil, agentAccessFeatureRequired()
	}
	principal, _ := authctx.PrincipalFrom(ctx)
	role, _ := principal.RoleIn(req.OrgId)
	canViewOwners := rbac.Can(role, rbac.PermMemberManage)
	rows, err := s.nodes.ListAgents(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	rows, err = s.filterAgentRows(ctx, req, rows)
	if err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool {
		left, right := strings.ToLower(rows[i].Name), strings.ToLower(rows[j].Name)
		if left == right {
			return rows[i].DeviceID.String() < rows[j].DeviceID.String()
		}
		return left < right
	})
	desc := req.Params.Dir != nil && *req.Params.Dir == api.Desc
	if desc {
		slices.Reverse(rows)
	}
	if req.Params.Cursor != nil {
		cursor, err := decodeAgentListCursor(*req.Params.Cursor, desc, agentListCursorFingerprint(req))
		if err != nil {
			return nil, err
		}
		rows = agentRowsAfterCursor(rows, cursor, desc)
	}
	limit := 50
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	nextCursor := (*string)(nil)
	if len(rows) > limit {
		cursor := encodeAgentListCursor(rows[limit-1], desc, agentListCursorFingerprint(req))
		nextCursor = &cursor
		rows = rows[:limit]
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
	return api.ListAgents200JSONResponse{Body: api.AgentListPage{Items: out, NextCursor: nextCursor}, Headers: api.ListAgents200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

type agentListCursor struct {
	Name   string `json:"n"`
	ID     string `json:"i"`
	Desc   bool   `json:"d"`
	Filter string `json:"f"`
}

func agentListCursorFingerprint(req api.ListAgentsRequestObject) string {
	q := ""
	if req.Params.Q != nil {
		q = strings.ToLower(strings.TrimSpace(*req.Params.Q))
	}
	data := fmt.Sprintf("%q|%v|%v|%v|%v|%v|%v", q, req.Params.Lifecycle, req.Params.Runtime, req.Params.Mcp, req.Params.Access, req.Params.GatewayId, req.Params.Sort)
	sum := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func encodeAgentListCursor(row sqlc.ListAgentsForOrgRow, desc bool, filter string) string {
	b, _ := json.Marshal(agentListCursor{Name: strings.ToLower(row.Name), ID: row.DeviceID.String(), Desc: desc, Filter: filter})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeAgentListCursor(raw string, desc bool, filter string) (agentListCursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return agentListCursor{}, apierr.BadRequest("invalid_cursor", "cursor is invalid")
	}
	var cursor agentListCursor
	if err := json.Unmarshal(b, &cursor); err != nil || cursor.Name == "" || cursor.ID == "" || cursor.Desc != desc || cursor.Filter != filter {
		return agentListCursor{}, apierr.BadRequest("invalid_cursor", "cursor is invalid")
	}
	if _, err := uuid.Parse(cursor.ID); err != nil {
		return agentListCursor{}, apierr.BadRequest("invalid_cursor", "cursor is invalid")
	}
	return cursor, nil
}

func agentRowsAfterCursor(rows []sqlc.ListAgentsForOrgRow, cursor agentListCursor, desc bool) []sqlc.ListAgentsForOrgRow {
	for i, row := range rows {
		name, id := strings.ToLower(row.Name), row.DeviceID.String()
		after := name > cursor.Name || (name == cursor.Name && id > cursor.ID)
		if desc {
			after = name < cursor.Name || (name == cursor.Name && id < cursor.ID)
		}
		if after {
			return rows[i:]
		}
	}
	return nil
}

func (s apiServer) filterAgentRows(ctx context.Context, req api.ListAgentsRequestObject, rows []sqlc.ListAgentsForOrgRow) ([]sqlc.ListAgentsForOrgRow, error) {
	q := ""
	if req.Params.Q != nil {
		q = strings.ToLower(strings.TrimSpace(*req.Params.Q))
	}
	result := make([]sqlc.ListAgentsForOrgRow, 0, len(rows))
	for _, row := range rows {
		if q != "" && !strings.Contains(strings.ToLower(row.Name), q) && !strings.Contains(strings.ToLower(row.GatewayName), q) && (row.OwnerEmail == nil || !strings.Contains(strings.ToLower(*row.OwnerEmail), q)) {
			continue
		}
		if req.Params.Lifecycle != nil && !agentStringFilterContains(*req.Params.Lifecycle, row.Status) {
			continue
		}
		if req.Params.GatewayId != nil && !slices.Contains(*req.Params.GatewayId, row.NodeID) {
			continue
		}
		if req.Params.Runtime != nil {
			state := s.agentRuntimeListState(ctx, req.OrgId, row.DeviceID)
			if !agentStringFilterContains(*req.Params.Runtime, state) {
				continue
			}
		}
		if req.Params.Mcp != nil {
			assigned, err := s.agentMCPProfileAssigned(ctx, req.OrgId, row.DeviceID)
			if err != nil {
				return nil, err
			}
			state := "unassigned"
			if assigned {
				state = "assigned"
			}
			if !agentStringFilterContains(*req.Params.Mcp, state) {
				continue
			}
		}
		if req.Params.Access != nil {
			state, err := s.agentAccessListState(ctx, req.OrgId, row.DeviceID)
			if err != nil {
				return nil, err
			}
			if !agentStringFilterContains(*req.Params.Access, state) {
				continue
			}
		}
		result = append(result, row)
	}
	return result, nil
}

func agentStringFilterContains[T ~string](values []T, want string) bool {
	for _, value := range values {
		if string(value) == want {
			return true
		}
	}
	return false
}

func (s apiServer) agentRuntimeListState(ctx context.Context, orgID, deviceID uuid.UUID) string {
	if s.agentRuntime == nil {
		return "not_configured"
	}
	state, err := s.agentRuntime.Status(ctx, orgID, deviceID)
	if err != nil || state.LastSeenAt == nil {
		return "not_configured"
	}
	if state.Health == "healthy" && !state.Stale && state.AppliedRevision == state.DesiredRevision {
		return "healthy"
	}
	if state.AppliedRevision < state.DesiredRevision && state.LastErrorCode == nil {
		return "pending"
	}
	return "degraded"
}

func (s apiServer) agentMCPProfileAssigned(ctx context.Context, orgID, deviceID uuid.UUID) (bool, error) {
	if s.system == nil {
		return false, apierr.Internal()
	}
	profiles, err := s.system.ListAgentMCPProfilesForDevice(ctx, sqlc.ListAgentMCPProfilesForDeviceParams{OrgID: orgID, DeviceID: deviceID})
	if err != nil {
		return false, err
	}
	return len(profiles) > 0, nil
}

func (s apiServer) agentAccessListState(ctx context.Context, orgID, deviceID uuid.UUID) (string, error) {
	if s.agentAccess == nil {
		return "none", nil
	}
	for _, state := range []string{"approved", "pending"} {
		rows, err := s.agentAccess.List(ctx, orgID, &state, &deviceID, nil, nil, 1)
		if err != nil {
			return "", err
		}
		if len(rows) > 0 {
			if state == "approved" {
				return "active", nil
			}
			return "pending", nil
		}
	}
	return "none", nil
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
