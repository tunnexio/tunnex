package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/devices"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

// EnrollAgent POST /api/v1/agent/enroll (public — the join token is the credential).
func (s apiServer) EnrollAgent(ctx context.Context, req api.EnrollAgentRequestObject) (api.EnrollAgentResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	if req.Body.ProtocolVersion > nodes.ProtocolVersion {
		return nil, apierr.BadRequest("unsupported_protocol", "the control plane does not support this agent protocol version")
	}
	res, err := s.nodes.Enroll(ctx, req.Body.JoinToken, req.Body.Csr, req.Body.NodeName, req.Body.AgentVersion)
	if err != nil {
		return nil, err
	}
	id, _ := uuid.Parse(res.NodeID)
	return api.EnrollAgent200JSONResponse{
		Body: api.EnrollResponse{
			NodeId:        id,
			Certificate:   res.CertPEM,
			CaCertificate: res.CAPEM,
		},
		Headers: api.EnrollAgent200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// ListNodes GET /api/v1/organizations/{orgId}/nodes.
func (s apiServer) ListNodes(ctx context.Context, req api.ListNodesRequestObject) (api.ListNodesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgView); err != nil {
		return nil, err
	}
	ns, err := s.nodes.ListNodes(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	// Zero Trust policy health: the authoritative bool + the advisory kind from ONE org
	// compile (S7.4b fold [0] — a single snapshot so bool and kind can't disagree).
	// Load the site topology + elect the hub ONCE, shared by both passes (review #3: no double load).
	batch := s.nodes.LoadSiteTopoBatch(ctx, req.OrgId, ns)
	health := s.nodes.PolicyHealthForNodes(ctx, req.OrgId, ns, batch)
	// S8.3: the hub designation (projection of the ONE election) + the reported max policy version (CW).
	extras := s.nodes.NodeDisplayExtrasForNodes(ctx, req.OrgId, ns, batch)
	// ⛔ D25(C) — DEGRADE, DO NOT REFUSE. An agent with no owner KEEPS RUNNING and the surface says so.
	// ⚠ AN ERROR HERE IS NOT "NOBODY IS ATTRIBUTABLE". If the resolver fails, every node would silently
	// render as unattributable — a false alarm across the whole fleet, which is the reassuring-empty class
	// inverted. Fail the request instead: the operator gets an error they can retry, not a fleet-wide lie.
	owners, err := s.nodes.OwnerEmails(ctx, req.OrgId)
	if err != nil {
		return nil, err
	}
	out := make([]api.Node, 0, len(ns))
	for _, n := range ns {
		an := toAPINode(n)
		if n.OwnerUserID.Valid {
			ow := uuid.UUID(n.OwnerUserID.Bytes)
			an.OwnerUserId = &ow
			if em, ok := owners[n.ID]; ok {
				an.OwnerEmail = &em
			}
		}
		// The flag is derived from the COLUMN, never from the email lookup — an owner who exists but cannot
		// be resolved is still attributable, and saying otherwise would blame the join for the fact.
		un := !n.OwnerUserID.Valid
		an.Unattributable = &un
		h := health[n.ID]
		an.PolicyDegraded = &h.Degraded
		k := api.NodePolicyDegradedKind(h.Kind)
		an.PolicyDegradedKind = &k
		// WF-B: the subordinate site-link note (a demoted-dead peer while transit is healthy) — nullable,
		// set only when one is genuinely down-but-subordinate so the badge names a peer only then.
		if h.SiteLinkNotePeer != "" {
			peer := h.SiteLinkNotePeer
			an.SiteLinkNotePeer = &peer
			dem := h.SiteLinkNoteDemoted
			an.SiteLinkNoteDemoted = &dem
		}
		e := extras[n.ID]
		an.IsSiteHub = &e.IsSiteHub
		if e.MaxPolicyVersion > 0 { // nullable: 0 = never reported → leave nil (the UI reads absence as below-ceiling)
			mv := e.MaxPolicyVersion
			an.MaxPolicyVersion = &mv
		}
		if e.OVPNHealth != "" { // S9.1 4d: only present when the OVPN server is refusing loudly (surfaced, not logged)
			oh := api.NodeOvpnHealth(e.OVPNHealth)
			an.OvpnHealth = &oh
		}
		out = append(out, an)
	}
	return api.ListNodes200JSONResponse{
		Body:    out,
		Headers: api.ListNodes200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// IssueJoinToken POST /api/v1/organizations/{orgId}/nodes/join-token.
func (s apiServer) IssueJoinToken(ctx context.Context, req api.IssueJoinTokenRequestObject) (api.IssueJoinTokenResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	name := ""
	if req.Body != nil && req.Body.NodeName != nil {
		name = *req.Body.NodeName
	}
	// ⚠ ABSENCE IS THE CLOSED STATE — an omitted marker enrols a plain gateway. The zero value of a
	// missing enum pointer is "", which the query COALESCEs to 'gateway'.
	kind := ""
	if req.Body != nil && req.Body.EnrolsKind != nil {
		kind = string(*req.Body.EnrolsKind)
	}
	tok, err := s.nodes.IssueJoinToken(ctx, p.UserID, req.OrgId, name, kind)
	if err != nil {
		return nil, err
	}
	return api.IssueJoinToken201JSONResponse{
		Body:    api.JoinTokenResponse{JoinToken: tok},
		Headers: api.IssueJoinToken201ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RevokeNode POST /api/v1/organizations/{orgId}/nodes/{nodeId}/revoke.
func (s apiServer) RevokeNode(ctx context.Context, req api.RevokeNodeRequestObject) (api.RevokeNodeResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermOrgUpdate); err != nil {
		return nil, err
	}
	p, _ := authctx.PrincipalFrom(ctx)
	// Revoke re-elects the hub set internally IFF the node is a gateway (S8.6 #9 — no reconcile churn on a
	// non-gateway device revoke).
	if err := s.nodes.Revoke(ctx, p.UserID, req.OrgId, req.NodeId); err != nil {
		return nil, err
	}
	return api.RevokeNode204Response{
		Headers: api.RevokeNode204ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RestoreNodeDevices POST /api/v1/organizations/{orgId}/nodes/{nodeId}/restore-devices (S13.1 Slice 7).
//
// THE REACHABLE TRIGGER. Revoking a gateway cascade-revokes every device homed on it, and re-key REFUSES a revoked
// node (D3) — so before this endpoint the restore code existed with nothing able to reach it. A human with
// device:restore names the dead gateway and the live replacement, and the act is audited whether or not anything
// came back.
//
// device:restore rather than org:update (which revokes a node): granting the power to take access away must not
// silently grant the power to hand it back.
func (s apiServer) RestoreNodeDevices(ctx context.Context, req api.RestoreNodeDevicesRequestObject) (api.RestoreNodeDevicesResponseObject, error) {
	if _, err := authorize(ctx, req.OrgId, rbac.PermDeviceRestore); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	p, _ := authctx.PrincipalFrom(ctx)
	res, err := s.devices.RestoreCascadedDevicesByOperator(ctx, p.UserID, req.OrgId, req.NodeId, req.Body.TargetNodeId)
	switch {
	case errors.Is(err, devices.ErrRestoreSourceUnknown):
		return nil, apierr.NotFound("node_not_found", err.Error())
	case errors.Is(err, devices.ErrRestoreTargetUnusable):
		return nil, apierr.BadRequest("invalid_target_node", err.Error())
	case err != nil:
		return nil, err
	}

	// api.RestoreDevicesResult — the schema is RestoreNodeDevicesResponse but carries x-go-name, because the
	// bare name collides with the wrapper oapi-codegen derives for operationId `restoreNodeDevices` and broke
	// apps/cli's compilation (2026-08-01). Five sibling schemas carry the same escape.
	body := api.RestoreDevicesResult{Restored: len(res)}
	for _, r := range res {
		if !r.KeptAddress {
			body.Readdressed++
		}
		entry := struct {
			AssignedIp         string             `json:"assigned_ip"`
			Id                 openapi_types.UUID `json:"id"`
			KeptAddress        bool               `json:"kept_address"`
			Name               string             `json:"name"`
			PreviousAssignedIp *string            `json:"previous_assigned_ip,omitempty"`
		}{AssignedIp: r.NewIP, Id: r.DeviceID, KeptAddress: r.KeptAddress, Name: r.Name}
		if !r.KeptAddress && r.OldIP != "" {
			old := r.OldIP
			entry.PreviousAssignedIp = &old
		}
		body.Devices = append(body.Devices, entry)
	}
	return api.RestoreNodeDevices200JSONResponse{
		Body:    body,
		Headers: api.RestoreNodeDevices200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

func toAPINode(n sqlc.Node) api.Node {
	out := api.Node{
		Id:           n.ID,
		Name:         n.Name,
		Status:       api.NodeStatus(n.Status),
		AgentVersion: n.AgentVersion,
		EnrolledAt:   n.EnrolledAt,
	}
	if n.LastSeenAt.Valid {
		t := n.LastSeenAt.Time
		out.LastSeenAt = &t
	}
	// ⛔ SERVED SO A CLIENT CAN REFUSE AN UNUSABLE CONFIG (S15.3). A gateway with no endpoint cannot be
	// dialled; issuing a peer config for it produces `Endpoint = `, which wg-quick rejects. Without this on
	// the wire the picker could only show a name, and the operator got a command that could never work.
	if n.Endpoint != "" {
		e := n.Endpoint
		out.Endpoint = &e
	}
	mode := api.Checking
	var caps nodes.NodeCapabilities
	if len(n.Capabilities) > 0 {
		if err := json.Unmarshal(n.Capabilities, &caps); err == nil && caps.EgressNAT {
			mode = api.Ipv4Only
			if caps.EgressIPv6 {
				mode = api.DualStack
			}
		}
	}
	out.EgressMode = &mode
	if n.SiteID.Valid { // S8.3 D2/CH: the site binding the topology view joins on
		sid := uuid.UUID(n.SiteID.Bytes)
		out.SiteId = &sid
	}
	return out
}

// RekeyChallenge POST /api/v1/agent/rekey/challenge (public — see the paper's D8 statement).
//
// Mints a single-use nonce for an IDENTIFIER WITHOUT checking that it is known. That absence is the anti-enumeration
// property (D9): a challenge that succeeded only for real identifiers would make them probeable one request at a
// time. An unknown identifier fails at SUBMIT, with the same uniform refusal as every other failure.
//
// TWO IDENTIFIERS (D10), and a malformed or contradictory pair is refused with nodes.ErrRekeyRefused — the SAME
// answer as an unknown identifier — rather than with a 400. A caller who could tell "your fingerprint is the wrong
// shape" from "no node has that fingerprint" learns the shape, and an endpoint that answers questions gets asked.
func (s apiServer) RekeyChallenge(ctx context.Context, req api.RekeyChallengeRequestObject) (api.RekeyChallengeResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	ident, ok := nodes.ParseRekeyIdentifier(deref(req.Body.CertSerial), deref(req.Body.KeyFingerprint))
	if !ok {
		return nil, nodes.ErrRekeyRefused
	}
	nonce, err := s.nodes.IssueRekeyChallenge(ctx, ident)
	if err != nil {
		return nil, err
	}
	return api.RekeyChallenge200JSONResponse{
		Body:    api.RekeyNonce{Nonce: base64.StdEncoding.EncodeToString(nonce)},
		Headers: api.RekeyChallenge200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}

// RekeyAgent POST /api/v1/agent/rekey (public — the entire defence is the gone-gate plus the proof).
//
// UNAUTHENTICATED BY CONSTRUCTION: the caller's certificate is the thing that has failed, and Go's ClientAuth is a
// listener property with no per-route relaxation, so this cannot live beside /agent/renew on the mTLS channel. The
// gate authorizes ONLY on certificate expiry and refuses a revoked node — a proof of possession must never overturn
// a human decision, because it cannot distinguish the legitimate holder from whoever took the key.
//
// Malformed base64 returns the SAME refusal as a wrong key: decoding is the first thing an attacker can vary, and a
// distinct error for it would be a free signal about how far a probe got.
func (s apiServer) RekeyAgent(ctx context.Context, req api.RekeyAgentRequestObject) (api.RekeyAgentResponseObject, error) {
	if req.Body == nil {
		return nil, apierr.BadRequest("invalid_request", "request body is required")
	}
	nonce, nErr := base64.StdEncoding.DecodeString(req.Body.Nonce)
	sig, sErr := base64.StdEncoding.DecodeString(req.Body.Signature)
	if nErr != nil || sErr != nil {
		return nil, nodes.ErrRekeyRefused
	}
	// Same refusal for a bad identifier as for a bad signature, by the same reasoning as the decode above.
	ident, ok := nodes.ParseRekeyIdentifier(deref(req.Body.CertSerial), deref(req.Body.KeyFingerprint))
	if !ok {
		return nil, nodes.ErrRekeyRefused
	}
	certPEM, caPEM, err := s.nodes.Rekey(ctx, ident, nonce, []byte(req.Body.Csr), sig, req.Body.AgentVersion)
	if err != nil {
		return nil, err
	}
	return api.RekeyAgent200JSONResponse{
		Body:    api.RekeyResponse{CertPem: certPEM, CaPem: caPEM},
		Headers: api.RekeyAgent200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}
