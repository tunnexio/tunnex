package http

import (
	"context"
	"net"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// ovpnServerPort is the OpenVPN server's UDP port (the .ovpn `remote <host> <port>`). A constant
// for now; per-gateway configuration (which gateways terminate OVPN, on which port) is 4d.
const ovpnServerPort = 1194

// ExportOVPNProfile mints an OpenVPN-transport device (the D-S9.4-MODEL create-fork: no WireGuard
// key/peer, a pool /32, transport tagged) and returns its one-time `.ovpn` profile. The profile
// carries the client private key and is served EXACTLY ONCE (S3.4/D2) — never re-fetchable; a lost
// profile is recovered by revoke + re-issue, never re-download. Gated by D-S9.5-OPTIN: refuses
// opt_in_required when the org has not opted into OpenVPN (the UI also hides the type — this is the
// defense-in-depth server gate).
func (s apiServer) ExportOVPNProfile(ctx context.Context, req api.ExportOVPNProfileRequestObject) (api.ExportOVPNProfileResponseObject, error) {
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
	// The OVPN service is open-edition but may be unwired in a stripped build; guard defensively.
	if s.ovpn == nil {
		return nil, apierr.New(404, "not_found", "OpenVPN is not available on this server")
	}
	// D-S9.5-OPTIN gate: OpenVPN is OFF by default per org. Refuse cleanly when not opted in.
	org, err := s.orgs.GetOrganization(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	if !org.OvpnEnabled {
		return nil, apierr.New(403, "opt_in_required", "OpenVPN is not enabled for this organization")
	}

	// Owner resolution (self, or admin-on-behalf) — mirrors CreateDevice.
	owner := p.UserID
	if req.Body.UserId != nil && *req.Body.UserId != p.UserID {
		role, _ := p.RoleIn(req.OrgId)
		if !rbac.Can(role, rbac.PermMemberManage) {
			return nil, apierr.New(403, "forbidden", "you may not create a device for another user")
		}
		owner = *req.Body.UserId
	}

	// The create-fork: an OpenVPN device (no WG key/peer; pool /32; transport tagged) via the SHARED
	// path (cap, pool, audit, and the org-wide push placing the /32 into the compiled artifact).
	// WF-OVPN-3: full-tunnel is a per-device choice for OVPN too. FullTunnel rides the SHARED create path,
	// so it inherits the gateway_no_egress refusal verbatim (a gateway without egress capability refuses a
	// full-tunnel OVPN device exactly as it refuses full-tunnel WireGuard).
	res, err := s.devices.Create(ctx, devices.CreateInput{
		OrgID: req.OrgId, ActorID: p.UserID, OwnerID: owner, NodeID: req.Body.NodeId,
		Name: req.Body.Name, Transport: "openvpn",
		FullTunnel: req.Body.FullTunnel != nil && *req.Body.FullTunnel,
	})
	if err != nil {
		return nil, err
	}

	// Resolve the gateway remote(s). WF-OVPN-9: for a device homed on a HUB-SET member, the profile lists
	// EVERY member as a `remote` in priority order (native client-side failover, same hub-set authority the
	// widened roster reads). A non-hub-set device gets a single remote — its own gateway's endpoint.
	remotes, err := s.nodes.OVPNRemotes(ctx, req.OrgId, req.Body.NodeId)
	if err != nil {
		return nil, err
	}
	if len(remotes) == 0 {
		endpoint, _, _, dErr := s.nodes.NodeDial(ctx, req.OrgId, req.Body.NodeId)
		if dErr != nil {
			return nil, dErr
		}
		host := endpoint
		if h, _, e := net.SplitHostPort(endpoint); e == nil {
			host = h
		}
		remotes = []string{host}
	}

	// Mint the cert, assemble the one-time profile, audit the KEYED FINGERPRINT (never the material).
	profile, fingerprint, err := s.ovpn.ExportProfile(ctx, req.OrgId, p.UserID, res.Device.ID, remotes, ovpnServerPort)
	if err != nil {
		return nil, err
	}

	return api.ExportOVPNProfile201JSONResponse{
		Body: api.ExportOVPNProfileResult{
			Device:      toAPIDevice(res.Device),
			Profile:     profile,
			Fingerprint: fingerprint,
		},
		Headers: api.ExportOVPNProfile201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// SetOVPNEnabled flips the org's OpenVPN opt-in (S9.1 D-S9.5-OPTIN). org:update perm (an org setting).
// Unlock-then-opt-in: OFF by default; disabling is NOT revocation (issued certs survive, re-enable
// restores). The agent runs the OVPN server on a gateway iff this is true (DesiredState.OVPNEnabled).
func (s apiServer) SetOVPNEnabled(ctx context.Context, req api.SetOVPNEnabledRequestObject) (api.SetOVPNEnabledResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	org, err := s.orgs.SetOVPNEnabled(ctx, req.OrgId, req.Body.Enabled)
	if err != nil {
		return nil, err
	}
	return api.SetOVPNEnabled200JSONResponse{
		Body:    api.OVPNSetting{Enabled: org.OvpnEnabled},
		Headers: api.SetOVPNEnabled200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}
