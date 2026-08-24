package http

import (
	"context"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
	"github.com/tunnexio/tunnex/apps/api/internal/tenancy"
)

// ListDevices GET /api/v1/organizations/{orgId}/devices. Members see their own
// devices; admins (member:manage) see all of the org's devices.
func (s apiServer) ListDevices(ctx context.Context, req api.ListDevicesRequestObject) (api.ListDevicesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)

	var devs []devices.DeviceWithStatus
	var err error
	if rbac.Can(role, rbac.PermMemberManage) {
		devs, err = s.devices.ListForOrg(ctx, req.OrgId)
	} else {
		devs, err = s.devices.ListForUser(ctx, req.OrgId, p.UserID)
	}
	if err != nil {
		return nil, err
	}
	// Stale-profile surface: an issued config that no longer matches reality needs re-import. TWO causes
	// (devices.ProfileStale) — baked site ranges for STATIC exports, and the tunnel ADDRESS for every mode.
	// The address half is Slice 6: it was missing entirely, so a re-addressed device (cascade restore onto a
	// fresh address, Slice 5) rendered exactly as clean as one that kept its address, and its user would have
	// found out by failing to connect. Fetch the current ranges ONCE (best-effort — a fault leaves ranges
	// uncompared, never fails the list; the surface is advisory, not enforcement).
	var current []string
	if s.sites != nil {
		current, _ = s.sites.ListRoutedRanges(ctx, req.OrgId)
	}
	// S12.12 D7 — the THIRD cause's managed half needs to know which gateways a managed device follows itself
	// onto. Read ONCE per request, like the ranges, and best-effort for the same reason: a topology fault
	// leaves the gateway cause uncompared for managed devices rather than failing the list.
	//
	// ⚠ AND THE FAILURE DIRECTION IS THE OPPOSITE OF THE TRANSFER'S, deliberately. The transfer reports a
	// one-shot consequence, where an unknown must overstate the work. This is a STANDING surface, where an
	// unknown that reports stale is a permanent false positive on a healthy fleet — the exact thing the
	// unknown-is-not-stale rule was written for. So a fault here reads as self-homing (no gateway staleness),
	// and the transfer's own report is what caught the case at the moment it was created.
	selfHoming := map[uuid.UUID]bool{}
	if s.nodes != nil {
		if m, err := s.nodes.SelfHomingNodes(ctx, req.OrgId); err == nil {
			selfHoming = m
		}
	}
	out := make([]api.Device, 0, len(devs))
	for _, d := range devs {
		ad := toAPIDeviceWithStatus(d)
		// Computed for EVERY mode now, not just static — the mode discrimination lives inside ProfileStale,
		// where the ranges half stays static-only and the address half does not. Gating out here is what hid
		// managed devices from the signal.
		stale := devices.ProfileStale(d.Device.ProvisioningMode, d.Device.ProvisionedRanges, current,
			d.Device.ProvisionedIp, d.Device.AssignedIp, d.Device.ProvisionedNodeID, d.Device.NodeID,
			selfHoming[d.Device.NodeID])
		ad.NeedsReexport = &stale
		out = append(out, ad)
	}
	return api.ListDevices200JSONResponse{
		Body:    out,
		Headers: api.ListDevices200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// CreateDevice POST /api/v1/organizations/{orgId}/devices. The owner is the
// session user; an admin may create on behalf of a named member. Minting a
// credential is a mutating action, so it requires a verified email.
func (s apiServer) CreateDevice(ctx context.Context, req api.CreateDeviceRequestObject) (api.CreateDeviceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	if !p.EmailVerified {
		return nil, apierr.New(403, "email_not_verified", "verify your email to create a device")
	}

	owner := p.UserID
	if req.Body.UserId != nil && *req.Body.UserId != p.UserID {
		// Creating a device for someone else is an admin action.
		role, _ := p.RoleIn(req.OrgId)
		if !rbac.Can(role, rbac.PermMemberManage) {
			return nil, apierr.New(403, "forbidden", "you may not create a device for another user")
		}
		owner = *req.Body.UserId
	}

	in := devices.CreateInput{OrgID: req.OrgId, ActorID: p.UserID, OwnerID: owner, NodeID: req.Body.NodeId, Name: req.Body.Name}
	if req.Body.Platform != nil {
		in.Platform = *req.Body.Platform
	}
	// S15.3 — an AI agent is enrolled as a peer on a gateway. The only difference from a laptop is the
	// kind, which carries the cap exemption and makes the agent grantable as a policy source.
	if req.Body.Kind != nil {
		in.Kind = string(*req.Body.Kind)
	}
	if req.Body.PublicKey != nil {
		in.PublicKey = *req.Body.PublicKey
	}
	if req.Body.FullTunnel != nil {
		in.FullTunnel = *req.Body.FullTunnel
	}
	if req.Body.Provisioning != nil {
		in.Provisioning = string(*req.Body.Provisioning)
	}
	res, err := s.devices.Create(ctx, in)
	if err != nil {
		return nil, err
	}
	body := api.CreateDeviceResult{Device: toAPIDevice(res.Device)}
	if res.PrivateKeyOneTime != "" {
		body.PrivateKey = &res.PrivateKeyOneTime
	}
	if res.Config != "" {
		body.Config = &res.Config
	}
	if res.PendingApproval { // S7.3: signal the client to show a stable "awaiting approval" state
		pa := true
		body.PendingApproval = &pa
	}
	return api.CreateDevice201JSONResponse{
		Body:    body,
		Headers: api.CreateDevice201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// UpdateDeviceMode PATCH .../devices/{deviceId}/mode. This changes the issued
// routing mode in-place; it never mints or revokes a device identity.
func (s apiServer) UpdateDeviceMode(ctx context.Context, req api.UpdateDeviceModeRequestObject) (api.UpdateDeviceModeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)
	dev, err := s.devices.Get(ctx, req.OrgId, req.DeviceId)
	if err != nil {
		return nil, err
	}
	if dev.UserID != p.UserID && !rbac.Can(role, rbac.PermMemberManage) {
		return nil, apierr.New(403, "forbidden", "you may not change this device")
	}
	if req.Params.FullTunnel == nil {
		return nil, apierr.BadRequest("invalid_request", "full_tunnel is required")
	}
	res, err := s.devices.UpdateMode(ctx, p.UserID, req.OrgId, req.DeviceId, *req.Params.FullTunnel)
	if err != nil {
		return nil, err
	}
	body := api.UpdateDeviceModeResult{Device: toAPIDevice(res.Device)}
	body.Config.Address = res.Config.Address
	body.Config.Endpoint = res.Config.Endpoint
	body.Config.PeerPublicKey = res.Config.PeerPublicKey
	body.Config.AllowedIps = res.Config.AllowedIPs
	body.Config.Mtu = &res.Config.MTU
	body.Config.PersistentKeepalive = &res.Config.PersistentKeepalive
	if len(res.Config.Addresses) > 0 {
		v := append([]string(nil), res.Config.Addresses...)
		body.Config.Addresses = &v
	}
	if len(res.Config.DNS) > 0 {
		v := append([]string(nil), res.Config.DNS...)
		body.Config.Dns = &v
	}
	return api.UpdateDeviceMode200JSONResponse{Body: body, Headers: api.UpdateDeviceMode200ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

// RevokeDevice POST /api/v1/organizations/{orgId}/devices/{deviceId}/revoke. A
// user may revoke their own device; an admin may revoke any.
// RemoveDevice DELETE /organizations/{orgId}/devices/{deviceId} — take a REVOKED device off the roster.
//
// ⛔ SOFT, AND THE `ovpn_client_certs` CASCADE IS THE REASON. The OpenVPN CRL is built from that table, and
// every FK into `devices` is ON DELETE CASCADE — so a hard delete would drop the device's serial out of the
// CRL and UN-REVOKE the credential on the wire. A tidy-up that silently restores access.
//
// > **A DELETE THAT CASCADES INTO A REVOCATION LIST IS AN UN-REVOKE WEARING A HOUSEKEEPING VERB.**
//
// ⚠ THE SAME OWNERSHIP GATE AS REVOKE, deliberately: removing is strictly less powerful (the credential is
// already dead), so anyone who could revoke this device may tidy it away, and nobody else.
func (s apiServer) RemoveDevice(ctx context.Context, req api.RemoveDeviceRequestObject) (api.RemoveDeviceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)

	if _, err := s.authorizeDeviceLifecycleTarget(ctx, req.OrgId, req.DeviceId, p.UserID, role, "remove"); err != nil {
		return nil, err
	}
	if err := s.devices.RemoveRevoked(ctx, req.OrgId, p.UserID, req.DeviceId); err != nil {
		return nil, err
	}
	return api.RemoveDevice204Response{Headers: api.RemoveDevice204ResponseHeaders{XRequestId: reqID(ctx)}}, nil
}

func (s apiServer) RevokeDevice(ctx context.Context, req api.RevokeDeviceRequestObject) (api.RevokeDeviceResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	role, _ := p.RoleIn(req.OrgId)

	if _, err := s.authorizeDeviceLifecycleTarget(ctx, req.OrgId, req.DeviceId, p.UserID, role, "revoke"); err != nil {
		return nil, err
	}
	if err := s.devices.Revoke(ctx, req.OrgId, p.UserID, req.DeviceId); err != nil {
		return nil, err
	}
	return api.RevokeDevice204Response{
		Headers: api.RevokeDevice204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// authorizeDeviceLifecycleTarget preserves the shared human-device endpoint
// without turning agent existence into an oracle. A caller without global
// agent:revoke first proves relational agent authority. If that fails, the
// target may still be their human device; a missing/foreign row returns the
// same forbidden envelope as an existing unauthorized agent.
func (s apiServer) authorizeDeviceLifecycleTarget(ctx context.Context, orgID, deviceID, userID uuid.UUID, role, verb string) (sqlc.Device, error) {
	if rbac.Can(role, rbac.PermAgentRevoke) {
		return s.devices.Get(ctx, orgID, deviceID)
	}
	agentErr := s.requireAgentPermission(ctx, orgID, deviceID, rbac.PermAgentRevoke)
	if agentErr == nil {
		return s.devices.Get(ctx, orgID, deviceID)
	}
	dev, err := s.devices.Get(ctx, orgID, deviceID)
	if err != nil {
		return sqlc.Device{}, agentErr
	}
	if dev.Kind == "agent" {
		return sqlc.Device{}, agentErr
	}
	if dev.UserID != userID && !rbac.Can(role, rbac.PermMemberManage) {
		return sqlc.Device{}, apierr.New(403, "forbidden", "you may not "+verb+" this device")
	}
	return dev, nil
}

// onlineThreshold: a device is treated as "online" if its last WireGuard
// handshake is within this window. WireGuard has no connection state — this is an
// APPROXIMATION derived from handshake recency (~2.5-3min matches WG's rekey
// cadence); the UI shows "last seen" for honest precision. It aliases
// tenancy.OnlineWindow (the single source of truth) so the per-device dot and
// the dashboard "seen in last N min" tile can never drift apart.
const onlineThreshold = tenancy.OnlineWindow

func toAPIDevice(d sqlc.Device) api.Device {
	out := api.Device{
		Id:         d.ID,
		UserId:     d.UserID,
		NodeId:     d.NodeID,
		Name:       d.Name,
		PublicKey:  d.PublicKey,
		Status:     api.DeviceStatus(d.Status),
		CreatedAt:  d.CreatedAt,
		FullTunnel: d.FullTunnel,
	}
	if d.Platform != "" {
		out.Platform = &d.Platform
	}
	// ⛔ SERVED (S15.3). `kind` was persisted by S15.2 and read by NOBODY — the second instance in two
	// stories, after `owner_email` in S15.1. A device list could not tell an agent from a laptop.
	// ⚠ Always set, never conditional: an absent field would make 'human' and "this build predates kind"
	// indistinguishable, which is the reassuring-empty class in a DTO.
	k := api.DeviceKind(d.Kind)
	out.Kind = &k
	if d.AssignedIp != nil {
		out.AssignedIp = d.AssignedIp
	}
	if d.ApprovedBy.Valid { // S7.3: null = grandfathered/auto; set = explicitly approved
		u := uuid.UUID(d.ApprovedBy.Bytes)
		out.ApprovedBy = &u
	}
	return out
}

func toAPIDeviceWithStatus(d devices.DeviceWithStatus) api.Device {
	out := toAPIDevice(d.Device)
	if d.OwnerEmail != nil {
		email := openapi_types.Email(*d.OwnerEmail)
		out.OwnerEmail = &email
	}
	out.LastHandshakeAt = d.LastHandshakeAt
	out.RxBytes = d.RxBytes
	out.TxBytes = d.TxBytes
	online := deviceOnline(d.LastHandshakeAt)
	out.Online = &online
	// S7.5.3: the posture projection — present only when the service surfaced it
	// (org has >= 1 configured check). "unknown" is a first-class state the UI
	// must render distinctly: absence is not compliance.
	if h := d.Health; h != nil {
		state := api.DeviceHealthState(h.State)
		out.HealthState = &state
		blocked := h.Blocked
		out.HealthBlocked = &blocked
		out.HealthDiskEncrypted = h.DiskEncrypted
		out.HealthReportedAt = h.ReportedAt
		if h.OSVersion != "" {
			v := h.OSVersion
			out.HealthOsVersion = &v
		}
		fcs := make([]struct {
			Kind api.DeviceHealthFailedChecksKind `json:"kind"`
			Mode api.DeviceHealthFailedChecksMode `json:"mode"`
		}, 0, len(h.FailedChecks))
		for _, f := range h.FailedChecks {
			fcs = append(fcs, struct {
				Kind api.DeviceHealthFailedChecksKind `json:"kind"`
				Mode api.DeviceHealthFailedChecksMode `json:"mode"`
			}{Kind: api.DeviceHealthFailedChecksKind(f.Kind), Mode: api.DeviceHealthFailedChecksMode(f.Mode)})
		}
		out.HealthFailedChecks = &fcs
	}
	return out
}

// deviceOnline derives online-ness from handshake recency (WireGuard has no
// connection state) — an approximation, not a live socket check.
func deviceOnline(lastHandshake *time.Time) bool {
	return lastHandshake != nil && time.Since(*lastHandshake) <= onlineThreshold
}
