// Package devices is the control-plane side of user-owned WireGuard peers.
//
// Identity<->credential binding is enforced here and structurally in the schema:
// every device has a NOT NULL owning user who must be a member of the org, and a
// device is created only for an explicit owner (the session user, or — for an
// admin — a named target member). The control plane stores ONLY the peer public
// key: client-generated keys never leave the device; a server-generated key
// (browser flow) is returned once and never persisted.
package devices

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetguard"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetsrc"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

// Service provides device/peer operations.
type Service struct {
	pool   *pgxpool.Pool
	q      *sqlc.Queries
	hub    *nodepush.Hub
	logger *slog.Logger
	// afterResizeCheck is a test-only barrier fired inside ResizePool's window
	// (after the orphan check, before commit) so TestResizeAllocationRace can drive
	// a concurrent CreateDevice into that window. Always nil in production; a
	// per-Service field (not a package global) so parallel tests can't clobber it.
	afterResizeCheck func()
	// dialResolver (WF-A D-WFA-6, optional) derives a node's ACTIVE-HUB dial (endpoint + gateway pubkey)
	// so a NEW device on a hub-set member's config dials the active hub, not its arbitrary assigned gateway.
	// Wired to nodes.NodeDial. nil (tests / open build / not wired) → the device keeps its assigned node's
	// endpoint (pre-WF-A behavior); a resolver ERROR is also a silent keep (mint must not fail on a topology
	// blip — the re-home poll fixes the endpoint shortly after).
	dialResolver func(ctx context.Context, orgID, nodeID uuid.UUID) (endpoint, pubkey string, derived bool, err error)
	// selfHomingNodes (S12.12 D7, optional) names the gateways for which dialResolver would return
	// derived=true — i.e. the ones a MANAGED device follows itself onto. Wired to nodes.SelfHomingNodes.
	// nil / an error → unknown, which the transfer resolves to "assume a re-issue is needed": overstating the
	// work is recoverable, and understating it means a user finds out by failing to connect.
	selfHomingNodes func(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]bool, error)
	// exportEnrich (S9.1 Part-2, optional) returns the org's currently-approved routed ranges + whether
	// it has cross-site DNS forwarding, for a STATIC export (a file/QR profile whose non-polling client
	// can't learn ranges from the routed-ranges poll). Wired to sites.ListRoutedRanges + the DNS-forward
	// check — the SAME one truth the Tunnex client polls, so the two renderings never diverge. nil / a
	// query error → the export is NOT enriched (pool-only, pre-Part-2 behavior; never fail the mint).
	exportEnrich func(ctx context.Context, orgID uuid.UUID) (ranges []string, hasDNS bool, err error)
	// licence answers one question and only one: may a NEW device come into existence right now.
	// ⚠ nil means allowed — the fail-open default, matching nodes.Service.
	licence *licence.Manager
	// rebuildCRL (S9.1 Slice 5) — the SHARED revocation seam: after a device's OVPN client certs are
	// marked revoked (in the revoke tx), regenerate + store the org's CRL. Wired to ovpn.Service.RebuildCRL;
	// nil (no OVPN service) → no-op. Called from the ONE device-revoke path (D-S9.5-1 iii).
	rebuildCRL func(ctx context.Context, orgID uuid.UUID) error
	// approvalEnforced (WF-OVPN-6) — whether device-approval ENFORCEMENT is active for this edition.
	// Device approval is an ENTERPRISE feature (S7.5.3 unlock-then-opt-in): the open build gates the
	// admin surface (Get/SetDeviceApproval → 403 edition_required) AND must NOT enforce approval either,
	// or the gate makes the OPEN tier LESS functional (devices trapped pending with no way to approve) —
	// the edition line inverted. Wired from apphttp.NewDeviceApprovalEdition(); default false (open):
	// devices enroll ACTIVE regardless of the org's stored approval mode (downgrade-release by construction).
	approvalEnforced bool
}

type AgentCredentialRotationStatus struct {
	DeviceID                   uuid.UUID
	CurrentRevision            int64
	State                      string
	RequestedRevision          *int64
	Deadline                   *time.Time
	WireGuardCurrentRevision   int64
	WireGuardState             string
	WireGuardRequestedRevision *int64
}

func credentialRotationStatus(row sqlc.GetAgentRuntimeCredentialRotationRow) AgentCredentialRotationStatus {
	state := "current"
	var requested *int64
	var deadline *time.Time
	if row.RotationRequestedAt.Valid && row.RotationDeadline.Valid && row.RotationDeadline.Time.After(time.Now()) {
		next := row.Revision + 1
		requested = &next
		d := row.RotationDeadline.Time
		deadline = &d
		state = "requested"
		if row.CandidatePending {
			state = "candidate"
		}
	}
	return AgentCredentialRotationStatus{DeviceID: row.DeviceID, CurrentRevision: row.Revision, State: state, RequestedRevision: requested, Deadline: deadline,
		WireGuardCurrentRevision: 1, WireGuardState: "current"}
}

func wireGuardRotationStatus(row sqlc.AgentWireguardRotation, now time.Time) (string, *int64, *time.Time) {
	if row.State == "current" || row.RequestedRevision == nil || !row.Deadline.Valid || !row.Deadline.Time.After(now) {
		return "current", nil, nil
	}
	deadline := row.Deadline.Time
	return row.State, row.RequestedRevision, &deadline
}

func (s *Service) GetAgentCredentialRotation(ctx context.Context, orgID, deviceID uuid.UUID) (AgentCredentialRotationStatus, error) {
	row, err := s.q.GetAgentRuntimeCredentialRotation(ctx, sqlc.GetAgentRuntimeCredentialRotationParams{OrgID: orgID, DeviceID: deviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentCredentialRotationStatus{}, apierr.NotFound("agent_not_found", "agent not found")
	}
	if err != nil {
		return AgentCredentialRotationStatus{}, err
	}
	status := credentialRotationStatus(row)
	if wg, wgErr := s.q.GetAgentWireGuardRotation(ctx, sqlc.GetAgentWireGuardRotationParams{OrgID: orgID, DeviceID: deviceID}); wgErr == nil {
		status.WireGuardCurrentRevision = wg.CurrentRevision
		wgState, wgRequested, wgDeadline := wireGuardRotationStatus(wg, time.Now())
		status.WireGuardState = wgState
		status.WireGuardRequestedRevision = wgRequested
		if status.Deadline == nil && wgDeadline != nil {
			status.Deadline = wgDeadline
		}
	} else if !errors.Is(wgErr, pgx.ErrNoRows) {
		return AgentCredentialRotationStatus{}, wgErr
	}
	return status, nil
}

func (s *Service) RequestAgentCredentialRotation(ctx context.Context, actorID, orgID, deviceID uuid.UUID) (AgentCredentialRotationStatus, error) {
	var result AgentCredentialRotationStatus
	if s == nil || s.pool == nil {
		return result, errors.New("agent credential rotation database unavailable")
	}
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// The same device -> credential order is used by runtime authentication,
		// preparation and device-lifecycle triggers. Expiry is a credential write
		// too, so acquire the device before touching even an expired candidate.
		dev, err := q.GetDeviceForUpdate(ctx, sqlc.GetDeviceForUpdateParams{ID: deviceID, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && (dev.Kind != "agent" || dev.Status != "active")) {
			return apierr.Conflict("agent_credential_rotation_unavailable", "credential rotation requires one active agent with no pending candidate")
		}
		if err != nil {
			return err
		}
		// ReportStatus stages the WireGuard row before its handshake commit
		// locks the device. Refuse contention without waiting while we own the
		// device; no runtime credential has been changed at this point.
		_, err = q.TryLockAgentWireGuardRotation(ctx, sqlc.TryLockAgentWireGuardRotationParams{OrgID: orgID, DeviceID: deviceID})
		var lockErr *pgconn.PgError
		if errors.As(err, &lockErr) && lockErr.Code == "55P03" {
			return apierr.Conflict("agent_credential_rotation_unavailable", "credential rotation requires one active agent with no pending candidate")
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := q.ExpireAgentRuntimeCredentialRotation(ctx, sqlc.ExpireAgentRuntimeCredentialRotationParams{OrgID: orgID, DeviceID: deviceID}); err != nil {
			return err
		}
		deadline := pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}
		actor := pgtype.UUID{Bytes: actorID, Valid: true}
		row, err := q.RequestAgentRuntimeCredentialRotation(ctx, sqlc.RequestAgentRuntimeCredentialRotationParams{
			OrgID: orgID, DeviceID: deviceID,
			RotationDeadline: deadline, RotationRequestedBy: actor,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.Conflict("agent_credential_rotation_unavailable", "credential rotation requires one active agent with no pending candidate")
		}
		if err != nil {
			return err
		}
		wg, err := q.RequestAgentWireGuardRotation(ctx, sqlc.RequestAgentWireGuardRotationParams{
			OrgID: orgID, ID: deviceID, Deadline: deadline, RequestedBy: actor,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.Conflict("agent_credential_rotation_unavailable", "credential rotation requires one active agent with no pending candidate")
		}
		if err != nil {
			return err
		}
		result = AgentCredentialRotationStatus{DeviceID: row.DeviceID, CurrentRevision: row.Revision, State: "requested",
			WireGuardCurrentRevision: wg.CurrentRevision, WireGuardState: wg.State,
			WireGuardRequestedRevision: wg.RequestedRevision}
		next := row.Revision + 1
		result.RequestedRevision = &next
		if row.RotationDeadline.Valid {
			d := row.RotationDeadline.Time
			result.Deadline = &d
		}
		return audit(ctx, q, orgID, &actorID, "agent.credential_rotation_requested", "device", deviceID.String(), map[string]any{"revision": next})
	})
	return result, err
}

// SetApprovalEnforced wires the edition's device-approval enforcement (WF-OVPN-6). Called from the server
// wiring with apphttp.NewDeviceApprovalEdition() — true only on the enterprise build. Default false (open).
func (s *Service) SetApprovalEnforced(v bool) { s.approvalEnforced = v }

// SetRebuildCRL wires the shared OVPN CRL rebuild (Slice 5) — ovpn.Service.RebuildCRL. nil → no-op.
func (s *Service) SetRebuildCRL(fn func(ctx context.Context, orgID uuid.UUID) error) {
	s.rebuildCRL = fn
}

// SetDialResolver wires the WF-A active-hub dial derivation (nodes.NodeDial). Optional — see the field doc.
func (s *Service) SetDialResolver(fn func(ctx context.Context, orgID, nodeID uuid.UUID) (string, string, bool, error)) {
	s.dialResolver = fn
}

// SetSelfHomingNodes wires nodes.SelfHomingNodes — the gateways a MANAGED device can be moved onto without
// re-issuing its config (S12.12 D7). Optional: nil means unknown, and unknown resolves to "assume a re-issue
// is needed", which overstates the work rather than hiding a broken device.
func (s *Service) SetSelfHomingNodes(fn func(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]bool, error)) {
	s.selfHomingNodes = fn
}

// SetExportEnrich wires the S9.1 Part-2 static-export enrichment source (the org's routed ranges + DNS
// presence). Optional — nil keeps exports pool-only (pre-Part-2).
func (s *Service) SetExportEnrich(fn func(ctx context.Context, orgID uuid.UUID) ([]string, bool, error)) {
	s.exportEnrich = fn
}

// NewService builds the device service. hub may be nil (no push; interval
// reconcile still converges).
func NewService(pool *pgxpool.Pool, hub *nodepush.Hub, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{pool: pool, q: sqlc.New(pool), hub: hub, logger: logger}
}

func (s *Service) withTx(ctx context.Context, fn func(*sqlc.Queries) error) error {
	if s.pool == nil {
		return fn(s.q)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(sqlc.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CreateInput describes a new device.
type CreateInput struct {
	OrgID    uuid.UUID
	ActorID  uuid.UUID // the authenticated caller (for the audit trail)
	OwnerID  uuid.UUID // the device's owning user (never inferred from the body)
	NodeID   uuid.UUID // the gateway the peer connects through
	Name     string
	Platform string
	// Kind (S15.3) — "human" (default) or "agent". An AGENT is enrolled exactly like any other peer: it is
	// homed on a gateway, holds its own /32, and its traffic is FORWARDED through that gateway, which is
	// what puts it in front of the policy chain.
	Kind string
	// PublicKey, if set, is a client-generated peer key (preferred). If empty, the
	// server generates a keypair and returns the private key ONCE (browser flow).
	PublicKey string
	// FullTunnel routes all client traffic (0.0.0.0/0); default is split-tunnel
	// (org network only) — the zero-trust posture.
	FullTunnel bool
	// Transport is the data-plane the device uses (S9.1 D-S9.4-MODEL): "" / "wireguard"
	// (default) or "openvpn". FILTER-only — it selects the roster + export path, never the
	// policy engine (an OVPN device is a device row, indistinguishable to the compiler).
	Transport string
	// Provisioning (S9.1 Part-2): "" / "managed" (default — a polling Tunnex client that learns
	// routed ranges from the poll) or "static" (a file/QR export whose non-polling client needs the
	// approved ranges + DNS BAKED into the config). Derives from the EXPORT PATH: the web
	// download/QR ceremony sets "static"; the Tunnex client leaves it managed. Recorded on the
	// device as an immutable provisioning fact (for the stale-profile surface), not a live flag.
	Provisioning string
	// BootstrapToken is accepted only by the public managed-agent redemption path.
	// It is never persisted; only its hash is looked up.
	BootstrapToken string
}

// CreateResult is the created device plus, only for the server-generated flow,
// the one-time private key and the ready-to-use .conf (never stored, never
// returned again).
type CreateResult struct {
	Device            sqlc.Device
	PrivateKeyOneTime string // non-empty only when the server generated the key
	Config            string // full .conf, only for the server-generated flow
	// PendingApproval is true when the org requires device approval (S7.3): the device
	// is enrolled but BLOCKED (no tunnel) until an admin approves. The client shows a
	// stable "awaiting approval" state — never an error loop (the spine).
	PendingApproval   bool
	RuntimeCredential string
}

// managedHumanKeyReplayEligible is deliberately narrower than "client supplied
// a public key". Static exports, agents/bootstrap redemption, and OpenVPN retain
// their existing create semantics. D14o applies only to the managed desktop
// identity whose private key is durably anchored on that client before POST.
func managedHumanKeyReplayEligible(in CreateInput) bool {
	return in.BootstrapToken == "" && in.PublicKey != "" && wgkey.Valid(in.PublicKey) &&
		(in.Kind == "" || in.Kind == "human") &&
		(in.Transport == "" || in.Transport == "wireguard") &&
		(in.Provisioning == "" || in.Provisioning == "managed")
}

// classifyManagedHumanKeyHistory refuses every shape except the ONE exact live
// managed-human identity a response-loss retry is allowed to recover. Full
// history is load-bearing: a retired key is never silently brought back, and a
// database predating D14o that already contains duplicates is never guessed
// down to the first row.
func classifyManagedHumanKeyHistory(in CreateInput, history []sqlc.Device) (sqlc.Device, bool, error) {
	if len(history) == 0 {
		return sqlc.Device{}, false, nil
	}
	conflict := func() (sqlc.Device, bool, error) {
		return sqlc.Device{}, false, apierr.Conflict(
			"device_key_recovery_conflict",
			"the submitted public key cannot be recovered safely",
		)
	}
	if len(history) != 1 {
		return conflict()
	}
	candidate := history[0]
	if candidate.OrgID != in.OrgID || candidate.UserID != in.OwnerID ||
		candidate.PublicKey != in.PublicKey || candidate.Kind != "human" ||
		candidate.Transport != "wireguard" || candidate.ProvisioningMode != "managed" ||
		candidate.DeletedAt.Valid || (candidate.Status != "active" && candidate.Status != "pending") ||
		candidate.AssignedIp == nil || *candidate.AssignedIp == "" ||
		candidate.ProvisionedIp == nil || *candidate.ProvisionedIp != *candidate.AssignedIp ||
		!candidate.ProvisionedNodeID.Valid {
		return conflict()
	}
	return candidate, true, nil
}

// findManagedHumanKeyReplay takes the same owner+org advisory locks as Create's
// mutation transaction. It is the pre-growth fast path: an existing identity
// remains recoverable even when the licence now refuses NEW principals or the
// current IPv6-pool initializer is unavailable. Create repeats the read under
// its mutation lock after this probe to close a concurrent first-create race.
func (s *Service) findManagedHumanKeyReplay(ctx context.Context, in CreateInput) (sqlc.Device, bool, error) {
	var candidate sqlc.Device
	var found bool
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		for _, key := range sortedKeys(in.OwnerID.String(), in.OrgID.String()) {
			if err := q.LockDeviceKey(ctx, key); err != nil {
				return err
			}
		}
		if _, err := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: in.OrgID, UserID: in.OwnerID}); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.NotFound("owner_not_member", "the owner is not a member of this organization")
			}
			return err
		}
		history, err := q.ListDevicePublicKeyHistoryForOrg(ctx, sqlc.ListDevicePublicKeyHistoryForOrgParams{
			OrgID: in.OrgID, PublicKey: in.PublicKey,
		})
		if err != nil {
			return err
		}
		candidate, found, err = classifyManagedHumanKeyHistory(in, history)
		return err
	})
	return candidate, found, err
}

// IssueAgentBootstrapToken creates a short-lived, single-use credential bound
// to one org gateway. The raw value is returned exactly once.
func (s *Service) IssueAgentBootstrapToken(ctx context.Context, actor, orgID, gatewayID uuid.UUID, name string) (string, error) {
	if name == "" {
		return "", apierr.BadRequest("invalid_request", "agent name is required")
	}
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return "", err
	}
	raw := "tnx_agent_" + base64.RawURLEncoding.EncodeToString(rawBytes)
	h := sha256.Sum256([]byte(raw))
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		n, err := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: gatewayID, OrgID: orgID})
		if err != nil {
			return apierr.NotFound("gateway_not_found", "no such active gateway in this organization")
		}
		if n.Status != "active" {
			return apierr.Conflict("gateway_not_ready", "the gateway is not active")
		}
		_, err = q.CreateAgentBootstrapToken(ctx, sqlc.CreateAgentBootstrapTokenParams{OrgID: orgID, GatewayNodeID: gatewayID, AgentName: name, TokenHash: h[:], ExpiresAt: time.Now().Add(time.Hour), IssuedBy: pgtype.UUID{Bytes: actor, Valid: actor != uuid.Nil}})
		return err
	})
	returnIfErr := err
	if returnIfErr != nil {
		return "", returnIfErr
	}
	return raw, nil
}

func hashBootstrapToken(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

// ModeConfig is the mutable portion of a managed device configuration. It deliberately
// excludes the private key: the API never stores or re-issues that secret.
type ModeConfig struct {
	Address             string
	Addresses           []string
	Endpoint            string
	PeerPublicKey       string
	AllowedIPs          []string
	DNS                 []string
	MTU                 int
	PersistentKeepalive int
}

// ModeResult is returned by UpdateMode. Device identity and allocation are preserved;
// Config contains only facts the client may merge into its locally-held private key.
type ModeResult struct {
	Device sqlc.Device
	Config ModeConfig
}

// UpdateMode changes split/full routing on an existing device without minting a new
// principal. The caller must authorize ownership before invoking this method. The row
// lock serializes concurrent toggles; the gateway push happens only after commit.
func (s *Service) UpdateMode(ctx context.Context, actorID, orgID, deviceID uuid.UUID, fullTunnel bool) (ModeResult, error) {
	var result ModeResult
	changed := false
	// Pool initialization uses the shared DB pool and must happen outside the device
	// row transaction; nesting a pool operation inside withTx can deadlock under load.
	ipv6Pool, err := ipalloc.EnsureOrgIPv6Pool(ctx, s.pool, orgID)
	if err != nil {
		return ModeResult{}, apierr.Conflict("invalid_ipv6_pool", err.Error())
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		prior, err := q.GetDeviceForUpdate(ctx, sqlc.GetDeviceForUpdateParams{ID: deviceID, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("device_not_found", "device not found")
		}
		if err != nil {
			return err
		}
		if prior.Status != "active" && prior.Status != "pending" {
			return apierr.Conflict("device_not_active", "only active or pending devices can change mode")
		}
		org, err := q.GetOrganizationByID(ctx, orgID)
		if err != nil {
			return err
		}
		node, err := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: prior.NodeID, OrgID: orgID})
		if err != nil {
			return apierr.Conflict("node_not_ready", "the device gateway is no longer active")
		}
		var caps struct {
			EgressNAT  bool `json:"egress_nat"`
			EgressIPv6 bool `json:"egress_ipv6"`
		}
		if len(node.Capabilities) > 0 {
			_ = json.Unmarshal(node.Capabilities, &caps)
		}
		if fullTunnel && !caps.EgressNAT {
			return apierr.Conflict("gateway_no_egress", "this gateway can't route full-tunnel internet traffic yet; use split tunnel")
		}
		dualStack := ipv6Pool != "" && (!fullTunnel || caps.EgressIPv6)
		updated := prior
		if prior.FullTunnel != fullTunnel {
			updated, err = q.UpdateDeviceMode(ctx, sqlc.UpdateDeviceModeParams{ID: deviceID, OrgID: orgID, FullTunnel: fullTunnel})
			if errors.Is(err, pgx.ErrNoRows) {
				return apierr.Conflict("device_not_active", "only active or pending devices can change mode")
			}
			if err != nil {
				return err
			}
			if err := audit(ctx, q, orgID, &actorID, "device.mode_changed", "device", deviceID.String(), map[string]any{
				"from_full_tunnel": prior.FullTunnel,
				"to_full_tunnel":   fullTunnel,
			}); err != nil {
				return err
			}
			changed = true
		}
		assigned := ""
		if updated.AssignedIp != nil {
			assigned = *updated.AssignedIp
		}
		// A mode update must retain the same high-availability dial behavior as a
		// fresh managed enrollment. The allocation/node identity remains unchanged,
		// but the active hub may differ from the stored node.
		serverPubKey, endpoint := node.WgPublicKey, node.Endpoint
		if s.dialResolver != nil {
			if ep, pk, derived, derr := s.dialResolver(ctx, orgID, node.ID); derr == nil && derived {
				endpoint, serverPubKey = ep, pk
			}
		}
		addresses := []string{}
		if assigned != "" {
			addresses = append(addresses, deviceAddressCIDR(assigned))
		}
		if dualStack && assigned != "" {
			if v6, e := ipalloc.IPv6DeviceAddr(ipv6Pool, orgID, assigned); e == nil {
				addresses = append(addresses, v6.String()+"/128")
			}
		}
		result = ModeResult{Device: updated, Config: ModeConfig{
			Address: deviceAddressCIDR(assigned), Addresses: addresses, Endpoint: endpoint, PeerPublicKey: serverPubKey,
			AllowedIPs: allowedIPsFor(fullTunnel, dualStack, org.PoolCidr),
			DNS: func() []string {
				if fullTunnel {
					return []string{fullTunnelDNS}
				}
				return []string{}
			}(),
			MTU: clientMTU, PersistentKeepalive: keepalive,
		}}
		return nil
	})
	if err != nil {
		return ModeResult{}, err
	}
	// D14o uses a same-value request as an idempotent read-through for mutable
	// helper facts after an ambiguous create response. Preserve the existing
	// mutation behavior for a real toggle, but do not manufacture an audit event
	// or gateway push when the requested value is already current.
	if changed {
		s.PushOrgNodes(ctx, orgID)
	}
	return result, nil
}

// Create issues a device/peer for OwnerID, enforcing owner membership and the
// per-user cap, then pushes the gateway so the peer applies within seconds. The
// membership check + cap check + insert + audit run in ONE transaction under a
// per-user advisory lock, so the cap cannot be raced past.
func (s *Service) Create(ctx context.Context, in CreateInput) (CreateResult, error) {
	var bootstrapHash []byte
	var runtimeCredential string
	if in.BootstrapToken != "" {
		if in.PublicKey == "" || !wgkey.Valid(in.PublicKey) {
			return CreateResult{}, apierr.BadRequest("invalid_wg_key", "public_key must be a 32-byte base64 WireGuard key")
		}
		bootstrapHash = hashBootstrapToken(in.BootstrapToken)
		tok, err := s.q.GetAgentBootstrapToken(ctx, bootstrapHash)
		if err != nil {
			return CreateResult{}, apierr.New(401, "invalid_bootstrap_token", "the bootstrap token is invalid, used, or expired")
		}
		in.OrgID, in.NodeID, in.OwnerID = tok.OrgID, tok.GatewayNodeID, uuid.UUID(tok.IssuedBy.Bytes)
		if !tok.IssuedBy.Valid {
			return CreateResult{}, apierr.New(401, "invalid_bootstrap_token", "the bootstrap token has no issuer")
		}
		in.ActorID = uuid.UUID(tok.IssuedBy.Bytes)
		in.Name, in.Kind, in.Provisioning = tok.AgentName, "agent", "static"
	}
	// Bootstrap redemption derives the name from the issuer-bound token before
	// reaching the common name validation. Ordinary creates retain the same
	// early name_required behavior.
	if in.Name == "" {
		return CreateResult{}, apierr.BadRequest("name_required", "a device name is required")
	}
	// Validate an ordinary managed-human client key before the recovery probe.
	// Otherwise malformed input would reach the full-history query (and could
	// even match malformed legacy data) instead of deterministically retaining
	// the existing invalid_wg_key contract. Static/agent/bootstrap/OpenVPN paths
	// keep their established validation and ordering below.
	if in.BootstrapToken == "" && in.PublicKey != "" &&
		(in.Kind == "" || in.Kind == "human") &&
		(in.Transport == "" || in.Transport == "wireguard") &&
		(in.Provisioning == "" || in.Provisioning == "managed") &&
		!wgkey.Valid(in.PublicKey) {
		return CreateResult{}, apierr.BadRequest("invalid_wg_key", "public_key must be a 32-byte base64 WireGuard key")
	}
	replayEligible := managedHumanKeyReplayEligible(in)
	if replayEligible {
		if recovered, found, err := s.findManagedHumanKeyReplay(ctx, in); err != nil {
			return CreateResult{}, err
		} else if found {
			return CreateResult{Device: recovered, PendingApproval: recovered.Status == "pending"}, nil
		}
	}
	// ⛔ THE GRACE LADDER (S12.1 slice 7). A device is a principal; enrolling one is GROWTH, and growth is
	// what an expired licence stops. Every device already issued keeps its tunnel, and no connected user is
	// ever disconnected — the check is here, at creation, and nowhere near the data plane.
	// D14o recovery runs immediately above this gate because replaying an already-issued
	// UUID is not growth. A zero-history request still reaches this exact gate before
	// any server key generation or create mutation.
	//
	// ⚠ BEFORE THE KEYGEN, deliberately. Minting a WireGuard private key and then refusing would spend a
	// one-time secret on a request that was never going to succeed.
	//
	// ⛔ AND NOTE WHAT IS *NOT* GATED: adding a MEMBER. A device is a principal; a person is a seat, and
	// there are no seat gates in this product by founder ruling. Grace refusing new users would be a user
	// count wearing a different name.
	if e := s.checkNewPrincipalAllowed(); e != nil {
		return CreateResult{}, e
	}
	// THE OVPN-CREATE FORK — ONE SEAM (D-S9.4-MODEL): transport determines only the CREDENTIAL here.
	// Everything address-and-identity below (cap, pool, row, audit, and the org-wide push that places
	// the /32 into the compiled artifact) is transport-agnostic. WG mints a keypair; OpenVPN mints
	// NOTHING here — its credential is a client cert issued by the export path, so public_key stays ''
	// and it materializes NO WG peer (its "peer" is the CCD entry, Slice 3/4c). Downstream WG
	// materialization (the desired-state peer list, the pubkey-unique index) keys on KEY-PRESENCE, not
	// transport — so this switch is the sole place transport is examined in Create.
	pub, oneTimePriv := in.PublicKey, ""
	if in.Transport == "openvpn" {
		if pub != "" {
			return CreateResult{}, apierr.BadRequest("wg_key_on_ovpn", "an OpenVPN device does not take a WireGuard public key")
		}
		// pub stays "" — no keygen, no WG peer, no WG config (the oneTimePriv=="" gate below skips it).
	} else if pub == "" {
		priv, generated, gerr := wgkey.Generate()
		if gerr != nil {
			return CreateResult{}, gerr
		}
		pub, oneTimePriv = generated, priv
	} else if !wgkey.Valid(pub) {
		return CreateResult{}, apierr.BadRequest("invalid_wg_key", "public_key must be a 32-byte base64 WireGuard key")
	}

	// S9.1 Part-2: for a STATIC export, snapshot the org's currently-approved routed ranges NOW — used
	// for BOTH the baked config and the recorded snapshot (one truth, one query). A nil provider or a
	// query error → no enrichment (pool-only, pre-Part-2), never a mint failure.
	// ⛔ AN AGENT IS ALWAYS A STATIC EXPORT, AND THIS IS THE LINE THAT MAKES IT REACHABLE AT ALL.
	//
	// A managed device runs the Tunnex client and LEARNS the org's routed ranges from the control plane. An
	// AI agent runs `wg-quick` and polls nothing — so if its config is not enriched at issue time, its
	// AllowedIPs is the pool alone and traffic to any destination beyond it never enters the tunnel. The
	// grant would be correct, the policy chain would never see the packet, and the operator would be told
	// access was granted while nothing worked.
	//
	// ⚠ This is the defect my own end-to-end test concealed: I added the destination route BY HAND to prove
	// the policy leg, and in doing so supplied the very thing the product was failing to supply.
	isStatic := in.Provisioning == "static" || in.Kind == "agent"
	var staticRanges []string
	var staticHasDNS bool
	if isStatic && s.exportEnrich != nil {
		if r, hd, e := s.exportEnrich(ctx, in.OrgID); e == nil {
			staticRanges, staticHasDNS = r, hd
		}
	}

	var dev sqlc.Device
	var node sqlc.Node
	var assignedIP, poolCIDR, ipv6Pool string
	replayed := false
	dualStack := false
	// Resolve the deployment IPv6 pool before opening the device transaction.
	// EnsureOrgIPv6Pool uses the pool for its query/insert; calling it while a
	// size-1 transaction is holding that same pool deadlocks concurrent creates.
	var poolErr error
	ipv6Pool, poolErr = ipalloc.EnsureOrgIPv6Pool(ctx, s.pool, in.OrgID)
	if poolErr != nil {
		return CreateResult{}, apierr.Conflict("invalid_ipv6_pool", poolErr.Error())
	}
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		if len(bootstrapHash) > 0 {
			if e := q.LockDeviceKey(ctx, "agent-bootstrap:"+fmt.Sprintf("%x", bootstrapHash)); e != nil {
				return e
			}
			if _, e := q.GetAgentBootstrapToken(ctx, bootstrapHash); e != nil {
				return apierr.New(401, "invalid_bootstrap_token", "the bootstrap token is invalid, used, or expired")
			}
		}
		// Take the user AND org advisory locks (in sorted order -> no deadlock) so
		// the per-user cap check and the org-wide IP allocation are both atomic
		// against concurrent creates.
		for _, key := range sortedKeys(in.OwnerID.String(), in.OrgID.String()) {
			if e := q.LockDeviceKey(ctx, key); e != nil {
				return e
			}
		}
		// The owner must be a member of THIS org (identity binding — no cross-tenant
		// or non-member owners, even when an admin creates on someone's behalf).
		if _, e := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: in.OrgID, UserID: in.OwnerID}); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("owner_not_member", "the owner is not a member of this organization")
			}
			return e
		}
		if replayEligible {
			history, e := q.ListDevicePublicKeyHistoryForOrg(ctx, sqlc.ListDevicePublicKeyHistoryForOrgParams{
				OrgID: in.OrgID, PublicKey: in.PublicKey,
			})
			if e != nil {
				return e
			}
			recovered, found, e := classifyManagedHumanKeyHistory(in, history)
			if e != nil {
				return e
			}
			if found {
				dev = recovered
				replayed = true
				return nil
			}
		}
		// The node must belong to this org (and be active) — no cross-org attach.
		n, e := q.GetOrgNode(ctx, sqlc.GetOrgNodeParams{ID: in.NodeID, OrgID: in.OrgID})
		if e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return apierr.NotFound("node_not_found", "no such active node in this organization")
			}
			return e
		}
		node = n
		// A device is useless without a reachable gateway endpoint (the classic
		// self-hosted first-run failure is a config with an internal container IP)
		// or the node's WG public key (the peer would dial an empty server key).
		if node.Endpoint == "" || node.WgPublicKey == "" {
			return apierr.Conflict("node_not_ready", "the node has not reported its endpoint/key yet; ensure the agent is enrolled and TUNNEX_NODE_ENDPOINT is set")
		}
		// S3.7: a full-tunnel device routes ALL traffic to the gateway, so the gateway
		// MUST be able to source-NAT it to the internet. Refuse rather than mint a
		// config that silently blackholes everything. The agent probes + reports this
		// capability every reconcile; split-tunnel is always allowed.
		if in.FullTunnel {
			var caps struct {
				EgressNAT  bool `json:"egress_nat"`
				EgressIPv6 bool `json:"egress_ipv6"`
			}
			if len(node.Capabilities) > 0 {
				_ = json.Unmarshal(node.Capabilities, &caps)
			}
			if !caps.EgressNAT {
				return apierr.Conflict("gateway_no_egress", "this gateway can't route full-tunnel internet traffic yet; use split tunnel")
			}
			if ipv6Pool != "" {
				if _, e := netip.ParsePrefix(ipv6Pool); e != nil {
					return apierr.Conflict("invalid_ipv6_pool", "the deployment IPv6 pool is not a valid IPv6 /48")
				}
				dualStack = caps.EgressIPv6
			}
		}
		if !in.FullTunnel {
			dualStack = ipv6Pool != ""
		}
		// Per-user cap (0 = unlimited, per the org setting).
		org, e := q.GetOrganizationByID(ctx, in.OrgID)
		if e != nil {
			return e
		}
		poolCIDR = org.PoolCidr
		if in.Kind == "agent" && org.MaxAgentIdentities != nil {
			count, ce := q.CountAgentIdentitiesForQuota(ctx, in.OrgID)
			if ce != nil {
				return ce
			}
			if count >= int64(*org.MaxAgentIdentities) {
				return apierr.Conflict("agent_quota_exceeded", "the organization managed-agent identity quota has been reached")
			}
		}
		// S7.3 device posture: when the org requires approval, the device enrolls as
		// PENDING (blocked — excluded from every status='active' reader, so no peer + no
		// grants) until an admin approves. Default 'off' -> 'active', zero behavior change.
		// WF-OVPN-6: only the ENTERPRISE edition (approvalEnforced) honors the org's approval mode. Open
		// edition enrolls devices ACTIVE regardless — a gate whose admin surface is edition-locked must not
		// also enforce, or it makes the open tier less functional (the edition line inverted). This is the
		// downgrade-release seam by construction: an enterprise→open org's stored device_approval='on' stops
		// trapping new devices the moment the edition can no longer manage it.
		deviceStatus := "active"
		if s.approvalEnforced && org.DeviceApproval == "on" {
			deviceStatus = "pending"
		}
		if org.MaxDevicesPerUser > 0 {
			// Counts active+pending (finding #1): a pending device reserves a pool /32 and
			// is a real enrollment, so the cap must include it — else a user creates
			// unbounded pending devices (cap bypass on approve + an org-pool DoS).
			count, ce := q.CountDevicesForUserCap(ctx, sqlc.CountDevicesForUserCapParams{OrgID: in.OrgID, UserID: in.OwnerID})
			if ce != nil {
				return ce
			}
			if count >= int64(org.MaxDevicesPerUser) {
				return apierr.Conflict("device_limit", "device limit reached for this user")
			}
		}
		// Allocate the lowest free tunnel address from the org's flat pool
		// (deterministic; safe under the org advisory lock + the org_ip unique index).
		// Uses the SAME query as resize's orphan check (ListActiveDeviceAllocations)
		// so there is one definition of "live allocation" — no two filtered reads to
		// drift apart.
		allocs, e := q.ListActiveDeviceAllocations(ctx, in.OrgID)
		if e != nil {
			return e
		}
		usedIPs := make([]string, 0, len(allocs))
		for _, r := range allocs {
			if r.AssignedIp != nil {
				usedIPs = append(usedIPs, *r.AssignedIp)
			}
		}
		ip, e := ipalloc.Allocate(org.PoolCidr, usedIPs)
		if e != nil {
			if errors.Is(e, ipalloc.ErrPoolExhausted) {
				return apierr.Conflict("pool_exhausted", "no free tunnel address in the org pool")
			}
			return e // bad/too-small CIDR is a server misconfiguration
		}
		assignedIP = ip

		transport := in.Transport
		if transport == "" {
			transport = "wireguard"
		}
		created, e := q.CreateDevice(ctx, sqlc.CreateDeviceParams{
			OrgID: in.OrgID, UserID: in.OwnerID, NodeID: in.NodeID,
			Name: in.Name, Platform: in.Platform, PublicKey: pub,
			AssignedIp: &assignedIP,
			// ⛔ EXPLICIT, NOT DEFAULTED (S15.2 slice 3). The column has a 'human' DEFAULT for the existing
			// rows, but Go's zero value for a string is "" — which the CHECK constraint rejects. Relying on
			// the DEFAULT here would mean this insert breaks the moment sqlc names the column, and it would
			// break at runtime rather than at compile time.
			// ⚠ Defaulted here rather than at the caller, and the direction is conservative: an unspecified
			// device is a HUMAN, which counts toward the per-user cap. Defaulting to 'agent' would exempt
			// rows from the cap by accident.
			Kind: func() string {
				if in.Kind == "agent" {
					return "agent"
				}
				return "human"
			}(),
			// Persisted (0019) so the S7.2 mode-enable can enumerate the full-tunnel
			// devices whose egress the enforcing flip governs.
			FullTunnel: in.FullTunnel,
			Status:     deviceStatus, // S7.3: 'pending' when the org requires approval
			// S9.1 D-S9.4-MODEL: the transport tag ('wireguard' default, 'openvpn' for a .ovpn
			// client). FILTER-only — the roster/export path reads it; the compiler never sees it.
			Transport: transport,
		})
		if e != nil {
			if c := pgerr.UniqueConstraint(e); c != "" {
				if strings.Contains(c, "_ip_") { // devices_org_ip_key
					return apierr.Conflict("ip_conflict", "tunnel address already in use in this org")
				}
				return apierr.Conflict("duplicate_key", "this public key is already registered on the node")
			}
			return e
		}
		dev = created
		if in.Kind == "agent" {
			// The profile is created in the same transaction. The device row remains
			// the lifecycle authority: pending means enrolled/awaiting approval.
			if e := q.EnsureAgentProfile(ctx, dev.ID); e != nil {
				return e
			}
		}
		// S9.1 Part-2: record the STATIC provisioning fact + the ranges snapshot baked in, so the
		// stale-profile surface can later flag "a subnet was added — re-export". Immutable record, in
		// the same tx as the create (a static device is never silently indistinguishable from managed).
		// Record what the ISSUED CONFIG baked, for EVERY mode. The ranges snapshot stays static-only (a managed
		// device polls routes, so nothing baked can go stale), but the ADDRESS is baked by every config — so
		// recording it only for static exports left managed devices silently excluded from the staleness signal
		// (S13.1 Slice 6). Same tx as the create: a device is never briefly indistinguishable from one issued
		// before this existed.
		mode := "managed"
		var rj []byte
		if isStatic {
			mode = "static"
			rj, _ = json.Marshal(staticRanges)
		}
		// provisioned_node_id joins the snapshot (F3): the issued config bakes THIS gateway's endpoint and public
		// key, so a device later re-homed onto another gateway holds a config naming one that will never serve it.
		nodeSnap := pgtype.UUID{Bytes: [16]byte(dev.NodeID), Valid: true}
		if e := q.SetDeviceProvisioning(ctx, sqlc.SetDeviceProvisioningParams{
			ID: dev.ID, ProvisioningMode: mode, ProvisionedRanges: rj, ProvisionedIp: dev.AssignedIp,
			ProvisionedNodeID: nodeSnap,
		}); e != nil {
			return e
		}
		dev.ProvisioningMode = mode
		dev.ProvisionedRanges = rj
		dev.ProvisionedIp = dev.AssignedIp
		dev.ProvisionedNodeID = nodeSnap
		if len(bootstrapHash) > 0 {
			raw := make([]byte, 32)
			if _, e := rand.Read(raw); e != nil {
				return e
			}
			runtimeCredential = "tnx_runtime_" + base64.RawURLEncoding.EncodeToString(raw)
			rh := sha256.Sum256([]byte(runtimeCredential))
			if _, e := q.CreateAgentRuntimeCredential(ctx, sqlc.CreateAgentRuntimeCredentialParams{OrgID: in.OrgID, DeviceID: dev.ID, TokenHash: rh[:]}); e != nil {
				return e
			}
			if _, e := q.ConsumeAgentBootstrapToken(ctx, sqlc.ConsumeAgentBootstrapTokenParams{TokenHash: bootstrapHash, ConsumedDeviceID: pgtype.UUID{Bytes: dev.ID, Valid: true}}); e != nil {
				return e
			}
		}
		keySource := "client"
		if oneTimePriv != "" {
			keySource = "server"
		}
		provMode := "managed"
		if isStatic {
			provMode = "static"
		}
		return audit(ctx, q, in.OrgID, &in.ActorID, "device.created", "device", dev.ID.String(),
			map[string]any{"name": in.Name, "owner": in.OwnerID.String(), "node_id": in.NodeID.String(), "key_source": keySource, "provisioning": provMode})
	})
	if err != nil {
		return CreateResult{}, err
	}
	// PUSH ORG-WIDE (F1-part-3): a new device's /32 can enter compiled allow-sets as a
	// group-resolved DESTINATION on gateways that do NOT host it (its owner in a policy
	// dst-group), so the grant must land <5s on those source gateways too — own-node push
	// would land it only on the reconcile interval. (For a pending device this is a no-op
	// nudge — it is excluded from every allow-set until approved.)
	if !replayed {
		s.PushOrgNodes(ctx, in.OrgID)
	}

	res := CreateResult{Device: dev, PrivateKeyOneTime: oneTimePriv, PendingApproval: dev.Status == "pending"}
	// Only the server-generated flow can produce a complete config (it holds the
	// one-time private key); the client-generated flow assembles its own.
	if oneTimePriv != "" || len(bootstrapHash) > 0 {
		// WF-A D-WFA-6: a NEW device on a hub-set member dials the ACTIVE HUB (the widening hosts it there),
		// not its arbitrary assigned gateway — so the config points at the re-home target from the first
		// handshake. derived=false / a resolver error → keep the assigned node's endpoint (spoke-device case,
		// or a topology blip; the re-home poll corrects it shortly after). Carries no device-identity change.
		serverPubKey, endpoint := node.WgPublicKey, node.Endpoint
		if s.dialResolver != nil {
			if ep, pk, derived, derr := s.dialResolver(ctx, in.OrgID, node.ID); derr == nil && derived {
				serverPubKey, endpoint = pk, ep
			}
		}
		allowed := allowedIPsFor(in.FullTunnel, dualStack, poolCIDR)
		dns := dnsFor(in.FullTunnel)
		ipv6Address := ""
		if ipv6Pool != "" && (!in.FullTunnel || dualStack) {
			if v6, e := ipalloc.IPv6DeviceAddr(ipv6Pool, in.OrgID, assignedIP); e == nil {
				ipv6Address = v6.String()
			}
		}
		// S9.1 Part-2: a STATIC export (non-polling client) needs the approved ranges + DNS BAKED, since
		// it can't learn them from the routed-ranges poll. Only for split-tunnel — a full-tunnel export
		// already routes everything (0.0.0.0/0), so range enrichment is moot. AllowedIPs = pool + ranges;
		// DNS points at the gateway forwarder (which does the per-domain routing) when the org has forwards.
		if isStatic && !in.FullTunnel {
			allowed = append(allowed, staticRanges...)
			if staticHasDNS {
				if gw, e := ipalloc.GatewayCIDR(poolCIDR); e == nil {
					if ip, _, ok := strings.Cut(gw, "/"); ok {
						dns = ip
					}
				}
			}
		}
		res.Config = buildConfig(configParams{
			address:      assignedIP,
			ipv6Address:  ipv6Address,
			privateKey:   oneTimePriv,
			serverPubKey: serverPubKey,
			endpoint:     endpoint,
			allowedIPs:   allowed,
			dns:          dns,
		})
		if len(bootstrapHash) > 0 {
			res.RuntimeCredential = runtimeCredential
			res.Config = strings.Replace(res.Config, "PrivateKey = \n", "PrivateKey = __TUNNEX_PRIVATE_KEY__\n", 1)
		}
	}
	return res, nil
}

// AgentLifecycleTransition is the only legal F01 lifecycle graph. In particular,
// revoked is terminal and suspension/resumption must not be smuggled through the
// generic device status helpers.
func AgentLifecycleTransition(from, to string) bool {
	switch from {
	case "active":
		return to == "suspended"
	case "suspended":
		return to == "active"
	default:
		return false
	}
}

type AgentProfile struct {
	DeviceID          uuid.UUID
	Name              string
	Environment       string
	Runtime           string
	Labels            []byte
	OwnerID           uuid.UUID
	OwnerEmail        string
	ManagingGroupID   *uuid.UUID
	ManagingGroupName *string
	Status            string
	LastHandshakeAt   *time.Time
	RxBytes           *int64
	TxBytes           *int64
}

func (s *Service) GetAgentProfile(ctx context.Context, orgID, deviceID uuid.UUID) (AgentProfile, error) {
	r, err := s.q.GetAgentProfileForOrg(ctx, sqlc.GetAgentProfileForOrgParams{DeviceID: deviceID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentProfile{}, apierr.NotFound("agent_not_found", "agent not found")
	}
	if err != nil {
		return AgentProfile{}, err
	}
	var managingGroupID *uuid.UUID
	if r.ManagingGroupID.Valid {
		v := uuid.UUID(r.ManagingGroupID.Bytes)
		managingGroupID = &v
	}
	return AgentProfile{DeviceID: r.DeviceID, Name: r.Name, Environment: r.Environment, Runtime: r.Runtime,
		Labels: r.Labels, OwnerID: r.UserID, OwnerEmail: r.OwnerEmail, Status: r.Status,
		ManagingGroupID: managingGroupID, ManagingGroupName: r.ManagingGroupName,
		LastHandshakeAt: tsPtr(r.LastHandshakeAt), RxBytes: r.RxBytes, TxBytes: r.TxBytes}, nil
}

type AgentScopedAuthority struct {
	Owner   bool
	Manager bool
}

// AgentManagingGroupCounts returns the server-owned destructive-impact count
// for every managing group in an organization. Missing groups have zero
// assignments. The web uses this only when presenting a group/member removal
// confirmation; it never derives the count from separately loaded agents.
func (s *Service) AgentManagingGroupCounts(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]int64, error) {
	rows, err := s.q.ListAgentManagingGroupCounts(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]int64, len(rows))
	for _, row := range rows {
		if row.ManagingGroupID.Valid {
			out[row.ManagingGroupID.Bytes] = row.ManagedAgentCount
		}
	}
	return out, nil
}

func (s *Service) AgentScopedAuthority(ctx context.Context, orgID, deviceID, userID uuid.UUID) (AgentScopedAuthority, error) {
	if s.pool == nil {
		p, err := s.GetAgentProfile(ctx, orgID, deviceID)
		return AgentScopedAuthority{Owner: err == nil && p.OwnerID == userID}, err
	}
	r, err := s.q.GetAgentScopedAuthority(ctx, sqlc.GetAgentScopedAuthorityParams{DeviceID: deviceID, OrgID: orgID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentScopedAuthority{}, nil
	}
	return AgentScopedAuthority{Owner: r.IsOwner, Manager: r.IsManager}, err
}

// IsAgentOwner deliberately returns only an authorization fact. Callers use it
// before loading the profile so a member cannot learn another agent's metadata.
func (s *Service) IsAgentOwner(ctx context.Context, orgID, deviceID, userID uuid.UUID) (bool, error) {
	if s.pool == nil {
		p, err := s.GetAgentProfile(ctx, orgID, deviceID)
		return err == nil && p.OwnerID == userID, err
	}
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM devices WHERE id = $1 AND org_id = $2 AND user_id = $3 AND kind = 'agent' AND deleted_at IS NULL
	)`, deviceID, orgID, userID).Scan(&exists)
	return exists, err
}

func (s *Service) UpdateAgentProfile(ctx context.Context, actorID, orgID, deviceID uuid.UUID, environment, runtime string, labels []byte) (AgentProfile, error) {
	return s.UpdateAgentProfileWithLifecycle(ctx, actorID, orgID, deviceID, environment, runtime, labels, nil)
}

// UpdateAgentProfileWithLifecycle is atomic: a rejected lifecycle transition
// rolls back the metadata update in the same transaction.
func (s *Service) UpdateAgentProfileWithLifecycle(ctx context.Context, actorID, orgID, deviceID uuid.UUID, environment, runtime string, labels []byte, status *string) (AgentProfile, error) {
	return s.UpdateAgentProfileWithLifecycleAndGovernance(ctx, actorID, orgID, deviceID, environment, runtime, labels, status, AgentGovernanceUpdate{ProfileUpdateRequested: true})
}

type AgentGovernanceUpdate struct {
	OwnerID                *uuid.UUID
	ManagingGroupSet       bool
	ManagingGroupID        *uuid.UUID
	ProfileUpdateRequested bool
}

func (s *Service) UpdateAgentProfileWithLifecycleAndGovernance(ctx context.Context, actorID, orgID, deviceID uuid.UUID, environment, runtime string, labels []byte, status *string, governance AgentGovernanceUpdate) (AgentProfile, error) {
	jitClosed := false
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		current, err := q.GetAgentProfileForOrg(ctx, sqlc.GetAgentProfileForOrgParams{DeviceID: deviceID, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("agent_not_found", "agent not found")
		}
		if err != nil {
			return err
		}
		if status != nil && !AgentLifecycleTransition(current.Status, *status) {
			return apierr.Conflict("invalid_agent_transition", "agent lifecycle transition is not allowed")
		}
		locked, err := q.GetAgentGovernanceForUpdate(ctx, sqlc.GetAgentGovernanceForUpdateParams{DeviceID: deviceID, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return apierr.NotFound("agent_not_found", "agent not found")
		}
		if err != nil {
			return err
		}
		if governance.OwnerID != nil {
			if _, err := q.GetCurrentAgentOwnerCandidate(ctx, sqlc.GetCurrentAgentOwnerCandidateParams{OrgID: orgID, UserID: *governance.OwnerID}); errors.Is(err, pgx.ErrNoRows) {
				return apierr.BadRequest("invalid_agent_owner", "agent owner must be a current organization member")
			} else if err != nil {
				return err
			}
		}
		if governance.ManagingGroupSet && governance.ManagingGroupID != nil {
			if _, err := q.GetUserGroup(ctx, sqlc.GetUserGroupParams{ID: *governance.ManagingGroupID, OrgID: orgID}); errors.Is(err, pgx.ErrNoRows) {
				return apierr.BadRequest("invalid_agent_managing_group", "managing group must belong to the organization")
			} else if err != nil {
				return err
			}
		}
		if governance.ProfileUpdateRequested {
			if _, err := q.UpdateAgentProfile(ctx, sqlc.UpdateAgentProfileParams{DeviceID: deviceID, Environment: environment, Runtime: runtime, Labels: labels, OrgID: orgID}); err != nil {
				return err
			}
		}
		if governance.ProfileUpdateRequested && status != nil {
			if _, err := q.UpdateAgentLifecycle(ctx, sqlc.UpdateAgentLifecycleParams{ID: deviceID, OrgID: orgID, Status: *status, Status_2: current.Status}); errors.Is(err, pgx.ErrNoRows) {
				return apierr.Conflict("agent_lifecycle_changed", "agent lifecycle changed; retry the update")
			} else if err != nil {
				return err
			}
			if *status == "suspended" {
				n, err := agentaccess.CloseForDeviceTx(ctx, q, orgID, deviceID, actorID, "agent_suspended")
				if err != nil {
					return err
				}
				jitClosed = n != 0
			}
		}
		assignmentChanged := false
		if governance.OwnerID != nil && *governance.OwnerID != locked.UserID {
			if _, err := q.SetAgentOwner(ctx, sqlc.SetAgentOwnerParams{ID: deviceID, OrgID: orgID, UserID: *governance.OwnerID}); err != nil {
				return err
			}
			assignmentChanged = true
		}
		oldGroup := (*uuid.UUID)(nil)
		if locked.ManagingGroupID.Valid {
			v := uuid.UUID(locked.ManagingGroupID.Bytes)
			oldGroup = &v
		}
		if governance.ManagingGroupSet && !sameOptionalUUID(oldGroup, governance.ManagingGroupID) {
			group := pgtype.UUID{}
			if governance.ManagingGroupID != nil {
				group = pgtype.UUID{Bytes: *governance.ManagingGroupID, Valid: true}
			}
			if _, err := q.SetAgentManagingGroup(ctx, sqlc.SetAgentManagingGroupParams{DeviceID: deviceID, ManagingGroupID: group, OrgID: orgID}); err != nil {
				return err
			}
			assignmentChanged = true
		}
		if governance.ProfileUpdateRequested {
			meta := map[string]any{}
			if status != nil {
				meta["from"], meta["to"] = current.Status, *status
			}
			if err := audit(ctx, q, orgID, &actorID, "agent.profile_updated", "device", deviceID.String(), meta); err != nil {
				return err
			}
		}
		if assignmentChanged {
			newOwner := locked.UserID
			if governance.OwnerID != nil {
				newOwner = *governance.OwnerID
			}
			newGroup := oldGroup
			if governance.ManagingGroupSet {
				newGroup = governance.ManagingGroupID
			}
			return audit(ctx, q, orgID, &actorID, "agent.assignment_updated", "device", deviceID.String(), map[string]any{
				"old_owner_id": locked.UserID, "new_owner_id": newOwner,
				"old_managing_group_id": oldGroup, "new_managing_group_id": newGroup,
			})
		}
		return nil
	})
	if err != nil {
		return AgentProfile{}, err
	}
	if jitClosed {
		s.PushOrgNodes(ctx, orgID)
	}
	return s.GetAgentProfile(ctx, orgID, deviceID)
}

func sameOptionalUUID(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// sortedKeys returns a and b in ascending order, so multiple advisory locks are
// always acquired in the same order across callers (deadlock-free).
func sortedKeys(a, b string) [2]string {
	if a <= b {
		return [2]string{a, b}
	}
	return [2]string{b, a}
}

// OrphanDevice is a device a resize would strand: which device, its address, and
// why (out_of_range | reserved_collision — the latter is numerically inside the
// new range and looks fine, so the reason must reach the UI).
type OrphanDevice struct {
	DeviceID   uuid.UUID
	Name       string
	AssignedIP string
	Reason     string
}

// ShrinkOrphansError is returned when a resize would strand live allocations.
// Orphans is the FULL list, ordered by assigned_ip ascending; the HTTP layer caps
// the rendered slice and reports the true total, so the 409 body is bounded but
// the count is honest.
type ShrinkOrphansError struct{ Orphans []OrphanDevice }

func (e *ShrinkOrphansError) Error() string {
	return fmt.Sprintf("resize would strand %d live allocation(s)", len(e.Orphans))
}

// ResizePool changes the org's tunnel pool CIDR, atomically with an
// org.cidr_resized audit row, under the SAME per-org lock the allocator takes
// (LockDeviceKey) — so a concurrent device-create cannot slip a new allocation
// past the orphan check during the resize window. (Lock ordering: resize takes
// only the org key; allocation takes {owner,org} sorted; resize never waits on
// the owner key, so no inversion/deadlock.)
//
// Legal shapes are grow-superset or shrink-subset only; an identical CIDR is an
// idempotent no-op. The orphan check runs UNCONDITIONALLY (not shrink-only): on
// a valid grow it is provably empty for Allocate-produced IPs — every reserved
// address of the new range is outside the usable interval [O_net+2, O_bcast-1]
// that any allocation occupies — so it fires only if that INVARIANT is broken.
// PREMISE: this assumes every assigned_ip was produced by ipalloc.Allocate (∈ the
// usable interval); UNIQUE(org_id,assigned_ip) enforces uniqueness, NOT range
// membership. Any future path that writes assigned_ip directly (a Pritunl-style
// import that preserves IPs; EPIC 9 OpenVPN if it doesn't allocate through
// ipalloc) MUST use Allocate or re-validate this — otherwise a grow could strand
// such an address on a new reserved slot, and the check firing here is the
// backstop that turns silent corruption into a refused resize.
func (s *Service) ResizePool(ctx context.Context, actor, orgID uuid.UUID, newCIDR string) (sqlc.Organization, error) {
	newP, err := netip.ParsePrefix(newCIDR)
	if err != nil || !newP.Addr().Is4() {
		return sqlc.Organization{}, apierr.BadRequest("invalid_cidr", "pool_cidr must be a valid IPv4 CIDR")
	}
	newP = newP.Masked()
	if 32-newP.Bits() < 2 { // need network + gateway + >=1 host + broadcast
		return sqlc.Organization{}, apierr.BadRequest("cidr_too_small", "the pool is too small to hold the gateway and at least one device (need /30 or larger)")
	}
	// Persist the CANONICAL (masked) form, not the raw input — so a host-bits-dirty
	// but valid input (e.g. "10.0.1.5/23") is stored/audited/echoed as "10.0.0.0/23",
	// matching what the pool actually is.
	masked := newP.String()
	var result sqlc.Organization
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		if e := q.LockDeviceKey(ctx, orgID.String()); e != nil {
			return e
		}
		org, e := q.GetOrganizationByID(ctx, orgID)
		if e != nil {
			return e
		}
		oldP, e := netip.ParsePrefix(org.PoolCidr)
		if e != nil {
			return e // a stored CIDR should always be valid
		}
		oldP = oldP.Masked()
		if oldP == newP {
			result = org // idempotent: identical CIDR is a successful no-op (no update, no audit)
			return nil
		}
		grow := newP.Bits() <= oldP.Bits() && newP.Contains(oldP.Addr())
		shrink := oldP.Bits() <= newP.Bits() && oldP.Contains(newP.Addr())
		if !grow && !shrink {
			return apierr.BadRequest("illegal_resize", "the new range must contain, or be contained by, the current range")
		}
		// S8.1 (S4.5b touch, D5/D7): the resized pool must stay DISJOINT from APPROVED site subnets —
		// growing the pool into a site's LAN would route device-/32s toward a site link (the
		// silent-ambiguity class). The SAME disjointness validator as advertisement-approval, the other
		// direction (typed illegal_resize). Pool is invalid here (we ARE the pool being resized).
		// S10.3 F2: the shared collector assembles EVERY class (approved subnets, pool, cluster VIP ranges);
		// WithoutPool excludes the OLD pool we are replacing. Growing into a site subnet OR a VIP range is
		// the silent-ambiguity class the validator exists to prevent.
		ranges, e := subnetguard.Collect(ctx, subnetsrc.Source{Q: q}, orgID)
		if e != nil {
			return e
		}
		if ov, ok := subnetguard.Check(newP, ranges.WithoutPool()); !ok {
			return apierr.BadRequest("illegal_resize", "the new pool overlaps "+string(ov.Class)+" "+ov.With.String()+"; resize refused")
		}
		// SINGLE read: the same device rows feed both the orphan check and the 409
		// objects, so the check and the build can't drift (no phantom orphan, no
		// count mismatch) under this org lock.
		rows, e := q.ListActiveDeviceAllocations(ctx, orgID)
		if e != nil {
			return e
		}
		ips := make([]string, 0, len(rows))
		byIP := make(map[string]sqlc.ListActiveDeviceAllocationsRow, len(rows))
		for _, r := range rows {
			if r.AssignedIp == nil { // query filters NOT NULL; defensive
				continue
			}
			ips = append(ips, *r.AssignedIp)
			byIP[*r.AssignedIp] = r
		}
		orphans, e := ipalloc.Orphans(masked, ips)
		if e != nil {
			return apierr.BadRequest("invalid_cidr", "pool_cidr must be a valid IPv4 CIDR")
		}
		// Test seam (per-Service, nil in prod): a barrier fired AFTER the orphan
		// check, BEFORE the commit — lets TestResizeAllocationRace drive a real
		// concurrent CreateDevice into this window to prove the LockDeviceKey above
		// actually excludes it.
		if s.afterResizeCheck != nil {
			s.afterResizeCheck()
		}
		// See this function's doc-comment PREMISE: on a valid grow this is provably
		// empty for Allocate-produced IPs; if it fires on a grow, that invariant was
		// violated (a direct assigned_ip writer). Do NOT drop this as "shrink-only"
		// without re-reading that proof.
		if len(orphans) > 0 {
			objs := make([]OrphanDevice, len(orphans))
			for i, o := range orphans {
				r := byIP[o.Addr] // present by construction: built from the same rows
				objs[i] = OrphanDevice{DeviceID: r.ID, Name: r.Name, AssignedIP: o.Addr, Reason: o.Reason}
			}
			return &ShrinkOrphansError{Orphans: objs}
		}
		updated, e := q.UpdateOrgPoolCidr(ctx, sqlc.UpdateOrgPoolCidrParams{ID: orgID, PoolCidr: masked})
		if e != nil {
			return e
		}
		result = updated // return the row we committed, in-tx — no post-commit re-fetch to race a concurrent delete
		return audit(ctx, q, orgID, &actor, "org.cidr_resized", "organization", orgID.String(),
			map[string]any{"from": org.PoolCidr, "to": masked})
	})
	if err != nil {
		return sqlc.Organization{}, err
	}
	return result, nil
}

// DeviceWithStatus is a device plus its live telemetry (nil when never reported).
type DeviceWithStatus struct {
	Device sqlc.Device
	// OwnerEmail is resolved by the pending-device query for approval attribution.
	// It is nil only when the owner record is unavailable; callers must not infer it.
	OwnerEmail      *string
	LastHandshakeAt *time.Time
	RxBytes         *int64
	TxBytes         *int64
	// Health is the posture projection (S7.5.3) — nil unless the org has opted
	// into >= 1 posture check (healthSurfaceActive), so an org that never opted
	// in gets no posture fields at all.
	Health *HealthInfo
}

// ListForUser returns a user's devices in an org (self-service view) with status.
func (s *Service) ListForUser(ctx context.Context, orgID, userID uuid.UUID) ([]DeviceWithStatus, error) {
	rows, err := s.q.ListDevicesByUser(ctx, sqlc.ListDevicesByUserParams{OrgID: orgID, UserID: userID})
	if err != nil {
		return nil, err
	}
	surfaceHealth, err := s.healthSurfaceActive(ctx, orgID) // [3]: a config-read error fails the list (retriable), never hides a live block
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]DeviceWithStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, DeviceWithStatus{
			Device: r.Device, LastHandshakeAt: tsPtr(r.LastHandshakeAt), RxBytes: r.RxBytes, TxBytes: r.TxBytes,
			Health: s.deviceHealthProjection(surfaceHealth, r.Device.HealthBlocked, r.EvaluatedState, r.FailedChecks, r.OsVersion, r.DiskEncrypted, r.ReportedAt, now),
		})
	}
	return out, nil
}

// ListForOrg returns all devices in an org (admin view) with status.
func (s *Service) ListForOrg(ctx context.Context, orgID uuid.UUID) ([]DeviceWithStatus, error) {
	rows, err := s.q.ListDevicesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	surfaceHealth, err := s.healthSurfaceActive(ctx, orgID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]DeviceWithStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, DeviceWithStatus{
			Device: r.Device, LastHandshakeAt: tsPtr(r.LastHandshakeAt), RxBytes: r.RxBytes, TxBytes: r.TxBytes,
			Health: s.deviceHealthProjection(surfaceHealth, r.Device.HealthBlocked, r.EvaluatedState, r.FailedChecks, r.OsVersion, r.DiskEncrypted, r.ReportedAt, now),
		})
	}
	return out, nil
}

// tsPtr converts a nullable timestamptz to *time.Time.
func tsPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time
	return &u
}

// Get returns a device scoped to its org (not-found otherwise — no cross-tenant leak).
func (s *Service) Get(ctx context.Context, orgID, deviceID uuid.UUID) (sqlc.Device, error) {
	dev, err := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
	if err != nil {
		return sqlc.Device{}, apierr.NotFound("device_not_found", "device not found")
	}
	return dev, nil
}

// Revoke marks a device revoked and pushes its gateway so the peer is removed
// from the device within the <5s bound. A no-op (already revoked) is a conflict.
// RemoveRevoked takes an already-REVOKED device off the roster. Soft: `deleted_at` is set and nothing is
// destroyed.
//
// ⛔ THE CASCADE IS WHY IT IS SOFT. Every FK into `devices` is ON DELETE CASCADE, and `ovpn_client_certs` is
// one of them — the OpenVPN CRL is `SELECT serial FROM ovpn_client_certs WHERE revoked_at IS NOT NULL`. A
// hard delete would drop this device's serial out of the CRL and UN-REVOKE its credential on the wire, so
// the housekeeping verb would silently restore the access the operator revoked. It would also take the
// device's posture history, its telemetry, and any policy rule naming it as an agent source.
//
// ⚠ REVOKED ONLY, ENFORCED IN THE STATEMENT rather than by a read-then-write: the WHERE clause carries
// `status = 'revoked'`, so a device that is active — or that becomes active between the check and the write
// — is not removed. Removing an ACTIVE device would leave a live credential with no surface to revoke it
// from: invisible and still working, the worst state this product can produce.
//
// ⚠ AND ROWS-AFFECTED IS READ, so "not found" and "not revoked" are different answers. Reporting success for
// a no-op is how an operator concludes a device is gone when it is still on the roster.
func (s *Service) RemoveRevoked(ctx context.Context, orgID, actorID, deviceID uuid.UUID) error {
	return s.withTx(ctx, func(q *sqlc.Queries) error {
		if _, err := agentaccess.CloseForDeviceTx(ctx, q, orgID, deviceID, actorID, "agent_removed"); err != nil {
			return err
		}
		n, err := q.SoftDeleteRevokedDevice(ctx, sqlc.SoftDeleteRevokedDeviceParams{ID: deviceID, OrgID: orgID})
		if err != nil {
			return err
		}
		if n == 0 {
			// Distinguish the two zero-row causes for the caller, from inside the same transaction.
			if _, e := q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID}); e != nil {
				return apierr.NotFound("device_not_found", "device not found")
			}
			return apierr.Conflict("device_not_revoked",
				"only a revoked device can be removed from the roster — revoke it first")
		}
		return audit(ctx, q, orgID, &actorID, "device.removed", "device", deviceID.String(),
			map[string]any{"cause": "operator_removed_revoked"})
	})
}

func (s *Service) Revoke(ctx context.Context, orgID, actorID, deviceID uuid.UUID) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// Read the PRIOR status (in-tx, ROW-LOCKED) so the audit distinguishes an owner
		// CANCELLING their own pending enrollment (device.cancelled) from a revocation of an
		// active device (device.revoked) — the queue history separates user-withdrew from
		// admin-refused (finding #3). FOR UPDATE serializes against a concurrent Approve so
		// the label can't be stale (finding #6; audit_logs is append-only). This in-tx locked
		// read is DISTINCT from the handler's pre-tx ownership read (a different layer —
		// authorization vs the atomic label); do not couple them (finding #7 accepted).
		prior, ge := q.GetDeviceForUpdate(ctx, sqlc.GetDeviceForUpdateParams{ID: deviceID, OrgID: orgID})
		if errors.Is(ge, pgx.ErrNoRows) {
			return apierr.Conflict("already_revoked", "device is not active")
		} else if ge != nil {
			return ge
		}
		if _, e := q.RevokeDevice(ctx, sqlc.RevokeDeviceParams{ID: deviceID, OrgID: orgID}); errors.Is(e, pgx.ErrNoRows) {
			return apierr.Conflict("already_revoked", "device is not active")
		} else if e != nil {
			return e
		}
		if _, e := agentaccess.CloseForDeviceTx(ctx, q, orgID, deviceID, actorID, "agent_revoked"); e != nil {
			return e
		}
		// Release the device's live status so a revoked device can't report stale
		// online/handshake via the API.
		if e := q.DeleteDeviceStatus(ctx, deviceID); e != nil {
			return e
		}
		// S9.1 Slice 5 (B2 full-sweep): mark the device's OVPN client certs revoked IN THE SAME TX (atomic
		// with the device revoke). A no-op for a WireGuard device (no cert rows). The CRL is regenerated
		// after commit (the shared seam); ccd-exclusive already blocks reconnect via the roster sweep.
		if _, e := q.RevokeOVPNClientCertsForDevice(ctx, deviceID); e != nil {
			return e
		}
		removedAgentGroups, e := q.RemoveAgentGroupMembershipsForDevice(ctx, sqlc.RemoveAgentGroupMembershipsForDeviceParams{
			OrgID: orgID, DeviceID: deviceID,
		})
		if e != nil {
			return e
		}
		action := "device.revoked"
		if prior.Status == "pending" {
			action = "device.cancelled" // owner withdrew a pending enrollment
		}
		return audit(ctx, q, orgID, &actorID, action, "device", deviceID.String(), map[string]any{
			"removed_agent_group_memberships": removedAgentGroups,
		})
	})
	if err != nil {
		return err
	}
	// S9.1 Slice 5: regenerate the org's CRL from the full revoked set (the shared seam), AFTER commit so
	// the expensive signing is off the tx. Best-effort: the device is already revoked (can't reconnect); a
	// failed rebuild leaves the live session until the scheduled rebuild backstops it — logged loudly.
	if s.rebuildCRL != nil {
		if e := s.rebuildCRL(ctx, orgID); e != nil {
			s.logger.Error("ovpn_crl_rebuild_failed_after_revoke", "org_id", orgID.String(), "error", e.Error())
		}
	}
	// PUSH ORG-WIDE (F1-part-3, a CORRECTNESS/SECURITY fix — not mere consistency): a
	// revoked device's /32 may be a group-resolved DESTINATION in compiled allow-sets on
	// gateways that do NOT host it. Own-node push would leave that stale allow rule on the
	// OTHER gateways for up to the reconcile interval — and revoke FREES the IP (S3.5/D1b),
	// so a reallocation inside that window would hand the new holder the old device's
	// group-dst grants on the unreconciled gateways: the address-reuse privilege leak
	// (F1-part-2's fail-OPEN sibling at the push layer). Org-wide strips it everywhere <5s.
	s.PushOrgNodes(ctx, orgID)
	return nil
}

// Approve flips a pending device to active (S7.3), recording the approver. A newly-trusted
// device enters the compiled allow-sets, so it PUSHES ORG-WIDE (pin 3): the device's /32
// appears as a source grant on its own gateway AND, if its owner is in a group that is a
// policy DESTINATION, as a /32 dst on OTHER gateways — an own-node push would land that
// grant only on the interval, not <5s (the F1-part-2 shape in reverse). Self-approval
// (actor == owner) is ALLOWED but distinctly audited (device.self_approved) — the
// designed-against case is approving your OWN device without a second-party vouch; four-eyes
// is advanced posture (D3).
func (s *Service) Approve(ctx context.Context, orgID, actorID, deviceID uuid.UUID) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		owner, e := q.ApproveDevice(ctx, sqlc.ApproveDeviceParams{
			ID: deviceID, OrgID: orgID, ApprovedBy: pgtype.UUID{Bytes: actorID, Valid: true},
		})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.Conflict("not_pending", "device is not awaiting approval")
		}
		if e != nil {
			return e
		}
		action := "device.approved"
		if owner == actorID {
			action = "device.self_approved"
		}
		return audit(ctx, q, orgID, &actorID, action, "device", deviceID.String(),
			map[string]any{"owner": owner.String()})
	})
	if err != nil {
		return err
	}
	s.PushOrgNodes(ctx, orgID)
	return nil
}

// Reject flips a pending device to revoked (S7.3), FREEING its held pool IP for reuse
// (D1b — the same release Revoke does). Only a pending device can be rejected. A pending
// device was never a peer / never in any allow-set (status-filtered out), so reject is
// data-plane-INERT — the own-node push is for convergence consistency, not a live change.
func (s *Service) Reject(ctx context.Context, orgID, actorID, deviceID uuid.UUID) error {
	var nodeID uuid.UUID
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		n, e := q.RejectDevice(ctx, sqlc.RejectDeviceParams{ID: deviceID, OrgID: orgID})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.Conflict("not_pending", "device is not awaiting approval")
		}
		if e != nil {
			return e
		}
		nodeID = n
		return audit(ctx, q, orgID, &actorID, "device.rejected", "device", deviceID.String(), map[string]any{})
	})
	if err != nil {
		return err
	}
	s.push(nodeID)
	return nil
}

// ListPending returns the org's device-approval queue (S7.3). Health rides along
// (S7.5.3): a pending device may already be reporting posture — both facts show
// independently (the D7 orthogonality), excluded from desired state once.
func (s *Service) ListPending(ctx context.Context, orgID uuid.UUID) ([]DeviceWithStatus, error) {
	rows, err := s.q.ListPendingDevicesByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	surfaceHealth, err := s.healthSurfaceActive(ctx, orgID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]DeviceWithStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, DeviceWithStatus{
			Device: r.Device, OwnerEmail: r.OwnerEmail, LastHandshakeAt: tsPtr(r.LastHandshakeAt), RxBytes: r.RxBytes, TxBytes: r.TxBytes,
			Health: s.deviceHealthProjection(surfaceHealth, r.Device.HealthBlocked, r.EvaluatedState, r.FailedChecks, r.OsVersion, r.DiskEncrypted, r.ReportedAt, now),
		})
	}
	return out, nil
}

// GetDeviceApproval reads the org's device-approval mode ('off' | 'on').
func (s *Service) GetDeviceApproval(ctx context.Context, orgID uuid.UUID) (string, error) {
	org, err := s.q.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return "", err
	}
	return org.DeviceApproval, nil
}

// SetDeviceApproval flips the org device-approval gate (S7.3), mirroring the
// zero_trust_mode SetMode ceremony EXACTLY: audited both directions, actor-attributed,
// in ONE transaction. Existing active devices are GRANDFATHERED (D4 — never retro-pended;
// a flip must not mass-blackhole a fleet, the S7.2 cold-start lesson). The grandfathered
// COUNT is BEST-EFFORT AFTER commit (the pass-4 #A lesson: never fail a committed setting
// flip because the count query blipped) and is meaningful only when turning ON.
func (s *Service) SetDeviceApproval(ctx context.Context, actor, orgID uuid.UUID, mode string) (grandfathered int64, err error) {
	if mode != "off" && mode != "on" {
		return 0, apierr.BadRequest("invalid_request", "device_approval must be off or on")
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		org, e := q.SetOrgDeviceApproval(ctx, sqlc.SetOrgDeviceApprovalParams{ID: orgID, DeviceApproval: mode})
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.NotFound("org_not_found", "organization not found")
		}
		if e != nil {
			return e
		}
		action := "org.device_approval_disabled"
		if org.DeviceApproval == "on" {
			action = "org.device_approval_enabled"
		}
		return audit(ctx, q, orgID, &actor, action, "organization", orgID.String(),
			map[string]any{"device_approval": mode})
	})
	if err != nil {
		return 0, err
	}
	if mode == "on" {
		if n, e := s.q.CountActiveDevicesForOrg(ctx, orgID); e != nil {
			s.logger.Warn("grandfathered_count_failed_after_device_approval_commit",
				slog.String("org_id", orgID.String()), slog.String("error", e.Error()))
		} else {
			grandfathered = n
		}
	}
	return grandfathered, nil
}

// PushUserNodes nudges every node carrying one of a user's active devices to
// reconcile now. Used by the offboarding cascade: after a user is deactivated
// (or reactivated) their peers drop from / return to desired state.
func (s *Service) PushUserNodes(ctx context.Context, userID uuid.UUID) {
	if s.hub == nil {
		return
	}
	ids, err := s.q.ListNodeIDsForUserActiveDevices(ctx, userID)
	if err != nil {
		// The interval reconcile still converges; surface the missed fast path.
		s.logger.Warn("device_push_lookup_failed", slog.String("user_id", userID.String()), slog.String("error", err.Error()))
		return
	}
	s.hub.NotifyMany(ids)
}

// PushOrgNodes signals EVERY active gateway in the org to re-fetch (S7.2). Used for
// org-wide policy changes — notably org-membership REMOVAL (the F1 4th trigger): a
// removed member's /32 must drop from every node's compiled ruleset that referenced
// it, not just the nodes hosting the removed user's own devices. Best-effort.
func (s *Service) PushOrgNodes(ctx context.Context, orgID uuid.UUID) {
	if s.hub == nil {
		return
	}
	ids, err := s.q.ListActiveNodeIDsForOrg(ctx, orgID)
	if err != nil {
		s.logger.Warn("device_push_org_lookup_failed", slog.String("org_id", orgID.String()), slog.String("error", err.Error()))
		return
	}
	s.hub.NotifyMany(ids)
}

func (s *Service) push(nodeID uuid.UUID) {
	if s.hub != nil {
		s.hub.Notify(nodeID)
	}
}

// audit writes an audit_logs row (same shape as the other services), in the
// caller's transaction so a mutation and its record commit atomically.
func audit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor *uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	b := []byte("{}")
	if meta != nil {
		b, _ = json.Marshal(meta)
	}
	actorID := pgtype.UUID{}
	if actor != nil {
		actorID = pgtype.UUID{Bytes: [16]byte(*actor), Valid: true}
	}
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID: pgtype.UUID{Bytes: [16]byte(orgID), Valid: true}, ActorUserID: actorID,
		Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}

// checkNewPrincipalAllowed is the grace gate, extracted so it is provable without a database — the
// wording and the status code are the parts an operator meets.
func (s *Service) checkNewPrincipalAllowed() error {
	if s.licence == nil || s.licence.AllowsNewPrincipals(time.Now()) {
		return nil
	}
	return apierr.New(403, "licence_expired", s.licence.NewPrincipalRefusal(time.Now()))
}

// WithLicence wires the entitlement manager. Chainable, and optional: without it, device creation is never
// refused for a licence reason.
func (s *Service) WithLicence(m *licence.Manager) *Service {
	s.licence = m
	return s
}
