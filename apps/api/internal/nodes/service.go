// Package nodes is the control-plane side of the tunnex-node agent: join-token
// enrollment, cert-identity authorization, short-lived-cert renewal (the
// revocation mechanism), and the desired-state the agent reconciles toward.
package nodes

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/ipalloc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
)

// enrolKindAgent / enrolKindGateway — the OPERATOR'S DECLARATION of what a join token enrols (S15.3).
//
// ⛔ ABSENCE IS THE CLOSED STATE. `node_join_tokens.enrols_kind` is NOT NULL DEFAULT 'gateway', so a token
// minted by a caller that has never heard of agents enrols a plain gateway. A nullable marker read as
// "agent" would be the same fail-open one column over.
const (
	enrolKindGateway = "gateway"
	enrolKindAgent   = "agent"
)

// ProtocolVersion is the control-plane protocol version, kept in lockstep with
// policyspec.ProtocolVersion (TestProtocolVersionConstantsAgree). v2 (S7.5.1): rule_id.
// v3 (S7.5.4): src_device_id — both additive + hash-invisible. v4 (S8.1 Slice 3): sites as a
// destination kind — Option A, no new wire field, but Version IS in-hash so v4 is a real hash change,
// and S8.1 D1's agent gate makes an agent at maxSupported<4 REFUSE it rather than mis-enforce (the
// v4 bump is no longer "safe to safe-ignore" — it is the enforcement boundary the gate protects).
// v6 (A3b, S8.6): pool_cidr on the site-gateway artifact (device-pool Docker accepts) — an old agent
// would silently strand device transit on Docker hosts, so the gate refuses (lockstep with policyspec).
const ProtocolVersion = policyspec.ProtocolVersion

const joinTokenTTL = time.Hour

// defaultGatewayCIDR is the interface address used when an org's pool can't be
// read (soft-deleted org / invalid CIDR) — matches the default pool's gateway so
// desired-state fetches degrade gracefully instead of failing.
const defaultGatewayCIDR = "10.99.0.1/24"

// Peer is one WireGuard peer in a node's desired state. S3.2 populates these;
// S3.1 carries the shape so the reconcile protocol is complete.
type Peer struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
	// SiteLink (S8.2) marks a gateway-DIALED site-link peer whose Endpoint is control-plane-managed
	// (static), NOT a roaming client. The agent's peer dirty-check compares Endpoint only for these (B4),
	// and reports their handshake staleness for the site-link health surface (H5). Device peers roam →
	// SiteLink=false → endpoint-blind.
	SiteLink bool `json:"site_link,omitempty"`
	// PersistentKeepalive (S8.3 CK, seconds) keeps a site-link tunnel warm through NAT: a NAT'd spoke
	// must dial the hub, and an idle link would otherwise false-stale (H5 site_link_down from mere
	// idleness). Set only on SITE-LINK peers (CP intent); 0 (omitted) on roaming device peers, which
	// re-handshake on demand. The agent compares it for SiteLink peers so a change re-syncs (Slice 0).
	PersistentKeepalive int `json:"persistent_keepalive,omitempty"`
}

// DesiredState is what an agent should converge its interface to. Version lets
// the agent detect changes cheaply; ProtocolVersion gates compatibility.
type DesiredState struct {
	ProtocolVersion  int    `json:"protocol_version"`
	NodeID           string `json:"node_id"`
	InterfaceAddress string `json:"interface_address"` // TODO(S3.5): from the org pool allocator
	MTU              int    `json:"mtu"`               // explicit, never inherited from ambient
	ListenPort       int    `json:"listen_port"`
	// Version is the node's push change-version at fetch time; the agent echoes it
	// on the next watch so a change during the fetch gap is not missed.
	Version uint64 `json:"version"`
	Peers   []Peer `json:"peers"`
	// Policy is the compiled Zero Trust policy (S7.2). Omitted in the open build
	// (nil provider) and when no provider is wired -> the agent decodes nil and
	// keeps the legacy blanket mesh (its asserted absent=mesh default).
	Policy *policyspec.Compiled `json:"policy,omitempty"`
	// OVPNClients is the OpenVPN roster homed to this gateway (S9.1 Slice 4c): each client's cert
	// CommonName (= device id) + its CP-assigned /32. Out-of-hash PLUMBING (like Routes) — the agent
	// renders these into CCD ifconfig-push entries; the ranges + DNS to PUSH ride the compiled Policy
	// (Routes/DNSForwards) the agent already holds. Omitted when the node has no OpenVPN devices. An
	// OVPN device is NOT a WireGuard Peer (it has no WG key, so DesiredState's peer loop skips it) —
	// but its /32 IS in the compiled Policy exactly as a WG device's (B1 data half on the wire).
	OVPNClients []OVPNClient `json:"ovpn_clients,omitempty"`
	// OVPNEnabled tells the agent whether to RUN the OpenVPN server on this gateway (S9.1 D-S9.5-OPTIN):
	// the org opted in AND this gateway is enabled. false → the agent keeps the OVPN server DOWN (idle,
	// no tun, zero egress rules — byte-identical to a WireGuard-only deployment). Per-gateway
	// granularity is org-level for now (every gateway in an opted-in org); a node-level enable is the
	// registered refinement.
	OVPNEnabled bool `json:"ovpn_enabled,omitempty"`
	// OVPNServer (D-S9.6-CERT-DELIVERY): the gateway's OpenVPN server MATERIAL — CA + server cert +
	// server KEY — delivered as desired state when OVPNEnabled, so the agent writes ca.crt/server.crt/
	// server.key at cfgDir (the zero-touch precondition the guards protect). The key crosses the SAME
	// mTLS control channel as policy + pool (no new trust). nil when OVPN is off → the agent SWEEPS the
	// files. NEVER logged / audited (fingerprint-only convention).
	OVPNServer *OVPNServerMaterial `json:"ovpn_server,omitempty"`
}

// OVPNServerMaterial is the gateway's OpenVPN server PKI, delivered for the agent to write to disk.
type OVPNServerMaterial struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
	CRL  string `json:"crl,omitempty"` // S9.1 Slice 5: the org's signed CRL (real-or-empty); crl-verify always-on
}

// OVPNClient is one OpenVPN client's wire binding: its cert CommonName (= device id, the CCD filename)
// and its CP-assigned /32. The allocator stays authoritative; the agent renders, never allocates.
type OVPNClient struct {
	CommonName string `json:"cn"`
	IP         string `json:"ip"`
	FullTunnel bool   `json:"ft,omitempty"` // WF-OVPN-3: per-device full-tunnel (redirect-gateway via CCD)
}

// PolicyProvider compiles the Zero Trust policy artifact for one node (S7.2).
// nil in the open build (no policy field is ever sent -> agents keep the legacy
// mesh); the enterprise build wires the policy engine via SetPolicyProvider.
type PolicyProvider interface {
	// activeHub (S8.6 REDUCE #1) is the DERIVED active transit hub for this compile pass, computed ONCE by
	// the caller (electSiteHub over the same loaded topology that feeds the data-plane graph) and threaded
	// in so the policy transit grant lands on the SAME hub the routing cites. uuid.Nil = no hub.
	CompiledForNode(ctx context.Context, orgID, nodeID, activeHub uuid.UUID) (*policyspec.Compiled, error)
	// CompiledArtifactsForNodes returns each node's ROUTE-LESS compiled artifact with a SINGLE org
	// snapshot build — the batch counterpart to CompiledForNode. Route-less by design: the CORE
	// finalizeArtifact/pushedHash attach the site routes + derive the version, so the pushed-hash
	// baseline is computed the SAME way the served artifact is (the #1 single-source fix). nil for a node
	// with no enforcement artifact (off / device-less-off). Avoids an N+1 recompile per node (finding #5).
	// activeHub threaded as above (org-wide — one hub for the batch).
	CompiledArtifactsForNodes(ctx context.Context, orgID uuid.UUID, nodeIDs []uuid.UUID, activeHub uuid.UUID) (map[uuid.UUID]*policyspec.Compiled, error)
}

// Service provides node control-plane operations.
type Service struct {
	// licence answers the entitlement questions. ⚠ nil means Community — the fail-open default.
	licence *licence.Manager
	pool    *pgxpool.Pool
	q       *sqlc.Queries
	ca      *agentca.CA
	policy  PolicyProvider // nil => open build / not wired
	// sealer supplies the keyed proof-of-secret fingerprint (S4.5 convention)
	// written to the join-token audit rows, so issuance and redemption correlate
	// without the raw token ever entering the audit stream.
	sealer *crypto.Sealer
	// siteTopoLoad loads the S8.2 site topology. Defaults to loadSiteTopology; a test overrides it to
	// inject a fault, proving the DesiredState-ATOMIC contract (a topology error fails the whole fetch).
	siteTopoLoad func(context.Context, uuid.UUID) (siteTopology, error)
	// failovers holds the per-org in-memory hysteresis state for the S8.6 failover tick — rebuilt from
	// stored freshness on a CP restart (no persistence for state the substrate re-derives). Guarded by
	// failoverMu (the tick runs on a background goroutine).
	failovers  map[uuid.UUID]*FailoverController
	failoverMu sync.Mutex
	// ovpnServerCert (D-S9.6, optional) mints-once + returns the gateway's OpenVPN server material for
	// delivery as desired state. Wired to ovpn.Service.EnsureServerCert. nil (WG-only / open build) →
	// no server material delivered.
	ovpnServerCert func(ctx context.Context, orgID, nodeID uuid.UUID) (ca, cert, key string, err error)
	// rebuildCRL (S9.1 Slice 5, optional) — the SHARED OVPN CRL rebuild seam, called from node-revoke (the
	// second revocation path) after the sweep marks the node's devices' OVPN certs revoked. ovpn.Service.RebuildCRL.
	rebuildCRL func(ctx context.Context, orgID uuid.UUID) error
	// ovpnCRL (S9.1 Slice 5, optional) — the org's signed CRL PEM for delivery (crl-verify always-on).
	// Wired to ovpn.Service.GetCRL (lazy-inits an empty CRL once). nil → no CRL delivered (pre-Slice-5).
	ovpnCRL func(ctx context.Context, orgID uuid.UUID) (string, error)
	// pushOrg (S13.1) fans a change out to every ACTIVE gateway in an org — the full-sweep reconciliation
	// signal, wired to the nodepush hub exactly as devices.PushOrgNodes is. Called AFTER a re-key transaction
	// commits, never inside it: a database transaction must not depend on a network call to a fleet, or a slow
	// gateway holds a write lock on the node row and a failed push rolls back a re-key that already succeeded
	// cryptographically. nil → no push (open build / tests); the recovering agent's own next reconcile still
	// converges it.
	pushOrg func(ctx context.Context, orgID uuid.UUID)
	// restoreDevices (S13.1 D5, Wall 6) brings back the devices that were cascade-revoked when this gateway was
	// revoked. Wired to devices.Service.RestoreCascadeRevokedDevices. nil → not wired (open build / tests), and a
	// recovered gateway then simply comes back with no users, which is the behaviour this closes.
	restoreDevices func(ctx context.Context, orgID, nodeID uuid.UUID) (int, int, error)
}

// NewService builds the node service.
func NewService(pool *pgxpool.Pool, ca *agentca.CA, sealer *crypto.Sealer) *Service {
	s := &Service{pool: pool, q: sqlc.New(pool), ca: ca, sealer: sealer, failovers: map[uuid.UUID]*FailoverController{}}
	s.siteTopoLoad = s.loadSiteTopology
	return s
}

// SetPolicyProvider wires the enterprise policy engine (S7.2). Call before serving.
// CountLiveGateways is the number the licence ceiling is checked against — every live gateway on the
// DEPLOYMENT, across all organizations.
//
// ⛔ EXPOSED SO THE UI CAN SHOW THE SAME NUMBER THE SERVER ENFORCES. The nav badge paired an ORG-scoped
// numerator with a DEPLOYMENT-scoped ceiling, so a fresh organization read "0 / 5" on a deployment that
// was already full and would refuse the very next enrolment. Two different questions, one fraction.
func (s *Service) CountLiveGateways(ctx context.Context) (int64, error) {
	return s.q.CountLiveNodes(ctx)
}

func (s *Service) SetPolicyProvider(p PolicyProvider) { s.policy = p }

// SetOVPNServerCertProvider wires the D-S9.6 server-cert delivery (ovpn.Service.EnsureServerCert).
func (s *Service) SetOVPNServerCertProvider(fn func(ctx context.Context, orgID, nodeID uuid.UUID) (ca, cert, key string, err error)) {
	s.ovpnServerCert = fn
}

// SetRebuildCRL wires the shared OVPN CRL rebuild (Slice 5) for the node-revoke path — ovpn.Service.RebuildCRL.
func (s *Service) SetRebuildCRL(fn func(ctx context.Context, orgID uuid.UUID) error) {
	s.rebuildCRL = fn
}

// SetRestoreDevices wires cascade-restore (S13.1 D5). Returns (restored, readdressed).
func (s *Service) SetRestoreDevices(fn func(ctx context.Context, orgID, nodeID uuid.UUID) (int, int, error)) {
	s.restoreDevices = fn
}

// SetPushOrg wires the full-sweep reconciliation signal (S13.1). Called after a re-key commits.
func (s *Service) SetPushOrg(fn func(ctx context.Context, orgID uuid.UUID)) { s.pushOrg = fn }

// SetOVPNCRLProvider wires the org CRL delivery (Slice 5) — ovpn.Service.GetCRL.
func (s *Service) SetOVPNCRLProvider(fn func(ctx context.Context, orgID uuid.UUID) (string, error)) {
	s.ovpnCRL = fn
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

// IssueJoinToken mints a single-use enrollment token for an org, optionally
// pinning a node name.
// ⭐ `enrolsKind` IS THE OPERATOR'S DECLARATION — "gateway" or "agent" — and it is captured HERE, at the
// same instant as the issuer, because minting a join token is the one act that says both who is
// accountable and what is being brought online.
// ⚠ An empty string means 'gateway': absence is the closed state (the query COALESCEs it), so a caller
// that has never heard of agents cannot mint one by omission.
func (s *Service) IssueJoinToken(ctx context.Context, actor, orgID uuid.UUID, nodeName, enrolsKind string) (string, error) {
	raw, hash, err := newToken()
	if err != nil {
		return "", err
	}
	var namePin *string
	if nodeName != "" {
		namePin = &nodeName
	}
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		// ⛔ THE CEILING IS CHECKED HERE TOO, AND THIS IS WHERE A HUMAN CAN ACT ON IT.
		//
		// Enforcement lives at ENROLMENT and stays there — an old token must never bypass the band. But
		// enrolment happens on the CUSTOMER'S SERVER, inside the agent, minutes later: the operator pastes
		// a docker command and reads a shell error. The web had already shown them a successful
		// join-token ceremony for an enrolment that could not possibly succeed.
		//
		// > ⛔ **A REFUSAL THAT ARRIVES WHERE NOBODY IS LOOKING IS A REFUSAL NOBODY CAN ACT ON.**
		//
		// ⚠ TWO CHECKS, ONE TRUTH, AND THE SECOND IS NOT REDUNDANT: this one is ADVISORY and early, so the
		// operator meets the limit at the moment they are deciding to add a gateway — the moment they
		// would upgrade. The enrolment check remains authoritative, because the fleet can grow between
		// minting a token and redeeming it.
		if e := s.checkGatewayCeiling(ctx, q); e != nil {
			return e
		}
		// ⛔ THE ACTOR WAS ALWAYS IN HAND AND WAS ALWAYS THROWN AWAY (S15.2 slice 1). This function has
		// received `actor` since it was written and wrote it to the audit log ALONE, so every token minted
		// before 0066 discarded its issuer to a table nobody joins against. One parameter, and it stops.
		if _, e := q.CreateJoinToken(ctx, sqlc.CreateJoinTokenParams{
			OrgID: orgID, NodeName: namePin, TokenHash: hash, ExpiresAt: time.Now().Add(joinTokenTTL),
			IssuedBy:   pgtype.UUID{Bytes: actor, Valid: actor != uuid.Nil},
			EnrolsKind: enrolsKind,
		}); e != nil {
			return e
		}
		// Keyed fingerprint (never the raw token, never a bare hash) so this row
		// correlates with the node.enrolled row that redeems the same token.
		return audit(ctx, q, orgID, &actor, "node.token_issued", "node", nodeName,
			map[string]any{"node_name": nodeName, "token_fingerprint": s.sealer.Fingerprint([]byte(raw))})
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

// EnrollResult is returned to a newly-enrolled agent.
type EnrollResult struct {
	NodeID  string
	CertPEM string
	CAPEM   string
}

// Enroll consumes a join token and issues the agent's first certificate. The
// token is single-use; the cert serial becomes the node's identity.
// checkGatewayCeiling refuses an enrolment that would exceed the licensed band.
//
// ⛔ ENROLMENT ONLY. Nothing running is ever stopped by this — it is the whole reason the trial band is 2
// and not 20 (docs/laws.md: a temporary grant of a create-time limit is a permanent grant of everything
// created under it).
//
// ⚠ A nil manager means Community, matching the fail-open default: a deployment that upgrades into this
// code keeps one gateway rather than losing the ability to enrol at all.
// ⛔ AND IT COUNTS THE WHOLE DEPLOYMENT, NOT ONE ORGANIZATION (founder-found).
//
// The count was `CountLiveNodesForOrg`. Starter allows 5 gateways and UNLIMITED organizations, so the
// real ceiling was 5 × however many orgs the customer felt like creating — and the control that creates
// them is the "+ New" button in the product's own header. No exploit, no API misuse: a paid limit liftable
// by clicking. Growth was 20 × N. Community and trial looked safe only because their ORG ceiling happens
// to be 1, which is two numbers agreeing rather than a boundary.
//
// > ## ⛔ **ONE SIGNED KEY, ONE DEPLOYMENT, ONE COUNT.** A ceiling scoped more narrowly than the thing
// > ## that grants it is not a ceiling.
func (s *Service) checkGatewayCeiling(ctx context.Context, q *sqlc.Queries) error {
	tier := s.effectiveTier(time.Now())
	ceiling, _ := licence.GatewayCeilingFor(tier)
	if ceiling == nil {
		return nil // unlimited
	}
	live, err := q.CountLiveNodes(ctx)
	if err != nil {
		return err
	}
	if live < int64(*ceiling) {
		return nil
	}
	// ⭐ THE MESSAGE IS THE FEATURE. It names the band, the ceiling, what is already enrolled, and what to
	// do — because this refusal is correct behaviour that looks like a broken install if it only says no.
	return apierr.New(403, "gateway_limit_reached", s.ceilingRefusal(tier, *ceiling, live))
}

// effectiveTier resolves the entitlement tier. ⚠ nil manager => Community, the fail-open default.
func (s *Service) effectiveTier(now time.Time) licence.Tier {
	if s.licence == nil {
		return licence.TierCommunity
	}
	return s.licence.Evaluate(now).Tier
}

// ceilingRefusal is the message an operator actually reads. ⭐ Extracted so it is testable without a
// database — the wording is the part of this slice worth guarding.
func (s *Service) ceilingRefusal(tier licence.Tier, ceiling int, live int64) string {
	unit := "gateways"
	if ceiling == 1 {
		unit = "gateway"
	}
	// ⚠ THE COUNT PLURALISES SEPARATELY FROM THE CEILING. "allows 1 gateway, and 1 are already enrolled"
	// shipped to a real screen — same fact, two sentences, one ungrammatical — because only the ceiling was
	// pluralised. This is the message an operator reads at the exact moment they are deciding to pay.
	verb := "are"
	if live == 1 {
		verb = "is"
	}
	// ⛔ THE LAST SENTENCE IS NOT POLISH — IT IS THE ONLY WARNING AN OPERATOR GETS. Someone who upgrades
	// and retries with the SAME token would otherwise meet `invalid_join_token`: a second, unrelated error
	// that describes none of this and sends them hunting for a token problem that does not exist. The
	// check now sits ABOVE `ConsumeJoinToken`, so the promise this sentence makes is true.
	//
	// ⛔ AND IT SAYS **ACROSS EVERY ORGANIZATION**, because the count is deployment-wide and the reader may
	// be standing in an organization with zero gateways. Without those three words the message reads as a
	// bug — "it allows 5 and I have none" — and their next move is a support ticket rather than an upgrade.
	return fmt.Sprintf(
		"This deployment is on the %s band, which allows %d %s across every organization, and %d %s "+
			"already enrolled. Nothing running is affected — existing gateways keep working, and this "+
			"refusal applies only to enrolling a new one. To add another: upgrade the licence, or revoke "+
			"a gateway you no longer use to free a slot. Your join token is still valid — retry with it "+
			"once there is room.",
		tier, ceiling, unit, live, verb)
}

// checkNewPrincipalAllowed refuses to bring a NEW gateway or agent into existence once the licence has
// expired. ⚠ nil manager => allowed, the fail-open default.
func (s *Service) checkNewPrincipalAllowed() error {
	if s.licence == nil || s.licence.AllowsNewPrincipals(time.Now()) {
		return nil
	}
	return apierr.New(403, "licence_expired", s.licence.NewPrincipalRefusal(time.Now()))
}

func (s *Service) Enroll(ctx context.Context, rawToken, csrPEM, nodeName, agentVersion string) (EnrollResult, error) {
	var res EnrollResult
	// ⛔ THE GRACE LADDER (S12.1 slice 7) — AND IT RUNS BEFORE THE TOKEN IS CONSUMED, DELIBERATELY.
	//
	// After a licence expires, everything enrolled keeps working and nothing stops; what stops is GROWTH.
	// This is that refusal for gateways and agents.
	//
	// ⚠ THE ORDERING IS THE CARE HERE. `ConsumeJoinToken` is single-use, so a refusal AFTER it destroys the
	// token — and a licence-state refusal is one the operator FIXES and retries. Burning their token for
	// being a day past expiry would mean renewing the licence still leaves them unable to enrol until they
	// mint a fresh one. A licence check needs no org, so it costs nothing to ask first.
	//
	// ⚠ The band ceiling below still runs inside the tx and still burns the token, because it CANNOT be
	// asked first: the ceiling is per-org and the org is only known once the token is read. Recorded as a
	// known asymmetry rather than pretended away.
	if e := s.checkNewPrincipalAllowed(); e != nil {
		return res, e
	}
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		// ⛔ PEEK, VALIDATE, THEN CONSUME — AND THE ORDER IS THE FIX.
		//
		// This used to consume FIRST, so every refusal below destroyed the token. `node_name_mismatch`
		// burned one twice in a single session: the operator names a gateway in the UI, the agent registers
		// under its container hostname, they disagree — a five-second fix, except the token is now gone and
		// the retry fails `invalid_join_token`, which describes a different problem entirely.
		//
		// > ⛔ **A REFUSAL THE OPERATOR CAN FIX MUST NOT DESTROY WHAT THEY NEED TO RETRY.**
		//
		// ⚠ SINGLE-USE IS UNCHANGED. ConsumeJoinToken still performs the atomic claim and is still the only
		// thing that marks the token spent; the peek merely lets the checks that an operator can ACT on run
		// before the point of no return. Both are inside one transaction, so a concurrent redeemer cannot
		// slip between them.
		tok, e := q.PeekJoinToken(ctx, hashToken(rawToken))
		if errors.Is(e, pgx.ErrNoRows) {
			return apierr.New(401, "invalid_join_token", "the join token is invalid, used, or expired")
		}
		if e != nil {
			return e
		}
		if tok.NodeName != nil && *tok.NodeName != "" {
			if nodeName != "" && nodeName != *tok.NodeName {
				return apierr.BadRequest("node_name_mismatch", "this token is pinned to a different node name")
			}
			nodeName = *tok.NodeName
		}
		if nodeName == "" {
			return apierr.BadRequest("node_name_required", "a node name is required")
		}
		// ⛔ THE GATEWAY CEILING — AT ENROLMENT ONLY (S12.1 slice 4).
		//
		// Community 1 · trial 2 · Starter 5 · Growth 20 · Scale unlimited. A RUNNING GATEWAY IS NEVER
		// STOPPED and an UPGRADE IS NOT AN ENROLMENT: a deployment already over its band keeps everything
		// it has and simply cannot add another. There is no special case for pre-existing excess, because
		// the enrolment-only rule already produces the right behaviour.
		//
		// ⚠ AND THE REFUSAL SAYS WHICH BAND AND WHICH CEILING. A bare failure here is the first thing a
		// real customer meets, and "enrolment failed" tells them nothing they can act on.
		if e := s.checkGatewayCeiling(ctx, q); e != nil {
			return e
		}
		// ⛔ THE POINT OF NO RETURN. Every refusal above is one the operator can fix and retry with the SAME
		// token; everything below has either succeeded or is a state they cannot correct by re-running.
		if _, e := q.ConsumeJoinToken(ctx, hashToken(rawToken)); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				// ⚠ Lost the race to a concurrent redeemer between peek and claim.
				return apierr.New(401, "invalid_join_token", "the join token is invalid, used, or expired")
			}
			return e
		}
		iss, e := s.ca.SignCSR([]byte(csrPEM), nodeName)
		if e != nil {
			return apierr.BadRequest("invalid_csr", "could not sign the certificate request")
		}
		// ⚠ THE OWNER IS THE TOKEN'S ISSUER, AND THE NAME MATTERS (rank-2 ruling). Enrolment is this agent
		// redeeming a token UNATTENDED — no human is present — so the installer is not capturable at all.
		// What is carried here is who AUTHORISED this agent into the org, never who installed it.
		// ⚠ May be NULL for a token minted before 0066. D25 ruled an agent is NEVER refused at use for want
		// of an owner: it degrades and is flagged. The refusal is at ENROLMENT and lands in slice 2.
		node, e := q.CreateNode(ctx, sqlc.CreateNodeParams{OrgID: tok.OrgID, Name: nodeName, CertSerial: iss.Serial,
			AgentVersion: agentVersion, CertNotAfter: pgtype.Timestamptz{Time: iss.NotAfter, Valid: true},
			CertPublicKey: spkiText(iss.PublicKeySPKI), OwnerUserID: tok.IssuedBy,
			EnrolledKind: &tok.EnrolsKind, LifecycleClaim: tok.LifecycleClaim})
		if e != nil {
			if pgerr.IsUnique(e) {
				return apierr.Conflict("node_exists", "a node with this name already exists")
			}
			return e
		}
		// ⛔ D25(B) — THE ENROLMENT REFUSAL, ARMED. An agent may not COME INTO EXISTENCE unowned.
		//
		// ⚠ AT ENROLMENT, NEVER AT USE. D25 ruled that a running agent is never refused for want of an owner
		// — it degrades and is flagged, because an unattributable tunnel is a LOGGING failure and dropping it
		// would buy nothing. This gate is the other half: refuse the CREATION, so the degraded state is only
		// ever inherited by agents that predate the column, never manufactured by one that comes after it.
		//
		// ⚠ AND THE TOKEN IS ALREADY CONSUMED AT THIS POINT — deliberately. A refused enrolment must not
		// leave a reusable token behind: the operator fixes the cause (issue a token as a verified admin)
		// and issues a new one, rather than retrying into the same wall with the same secret.
		if RefuseUnownedEnrolment(tok.IssuedBy.Valid) {
			return apierr.New(422, "enrolment_owner_required",
				"this join token records no issuer, so the agent it enrols could not be attributed to a person — "+
					"issue a new join token and enrol with that")
		}

		// ⛔ A GATEWAY ENROLMENT NO LONGER CREATES AN "AGENT" (S15.3, corrected).
		//
		// It used to allocate a kind='agent' device row here, which made every issuer-enrolled gateway an
		// agent — and, worse, made the agent a GATEWAY. A gateway is what traffic passes THROUGH; nothing it
		// originates is ever forwarded, so no grant could ever match it and the address was held by nothing.
		//
		// > AN AGENT IS A PEER. It is enrolled through the DEVICE path, homed on a gateway, with its own /32
		// > and a config it dials in with — which is what puts it in front of the policy chain at all.
		//
		// ⚠ The join token's `enrols_kind` marker is retained: it still records what the operator declared,
		// and `nodes.enrolled_kind` still distinguishes a node enrolled before the question was asked.
		res = EnrollResult{NodeID: node.ID.String(), CertPEM: iss.CertPEM, CAPEM: string(s.ca.CertPEM())}
		// Same keyed fingerprint as the node.token_issued row — issue and redeem
		// correlate in the audit stream without the raw token appearing anywhere.
		return audit(ctx, q, tok.OrgID, nil, "node.enrolled", "node", node.ID.String(),
			map[string]any{"name": nodeName, "agent_version": agentVersion, "token_fingerprint": s.sealer.Fingerprint([]byte(rawToken))})
	})
	if err != nil {
		return EnrollResult{}, err
	}
	return res, nil
}

// AuthenticateCert maps an mTLS client cert serial to its node, rejecting
// unknown or revoked certs. This is the machine-edition identity↔credential rule.
func (s *Service) AuthenticateCert(ctx context.Context, certSerial string) (sqlc.Node, error) {
	node, err := s.q.GetNodeByCertSerial(ctx, certSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.Node{}, apierr.New(401, "unknown_agent", "unrecognized agent certificate")
	}
	if err != nil {
		return sqlc.Node{}, err
	}
	if node.Status != "active" {
		return sqlc.Node{}, apierr.New(401, "agent_revoked", "this agent has been revoked")
	}
	// FIRST USE MARKS DELIVERY (S13.1 D3). This is the observation that makes the redelivery carve-out safe: a
	// certificate that has authenticated cannot be the subject of a lost-response recovery, so a LIVE gateway is
	// excluded structurally rather than by a liveness check the gate deliberately does not have. A no-op after the
	// first call (the UPDATE's own WHERE), and best-effort: failing an agent request because a marker could not be
	// written would trade a real outage for a bookkeeping one. The cost of a missed write is one node that stays
	// eligible for redelivery until its next request.
	if !node.CertDelivered {
		if merr := s.q.MarkCertDelivered(ctx, node.ID); merr != nil {
			slog.Warn("cert_delivery_mark_failed", "node_id", node.ID.String(), "error", merr.Error())
		}
	}
	return node, nil
}

// Renew issues a fresh short-lived cert for an active node. A revoked node is
// refused — this IS the revocation mechanism (short certs + renewal refusal).
func (s *Service) Renew(ctx context.Context, node sqlc.Node, csrPEM, agentVersion string) (string, error) {
	if node.Status != "active" {
		return "", apierr.New(401, "agent_revoked", "this agent has been revoked")
	}
	iss, err := s.ca.SignCSR([]byte(csrPEM), node.Name)
	if err != nil {
		return "", apierr.BadRequest("invalid_csr", "could not sign the certificate request")
	}
	// Stamped on RENEWAL as well as enrolment (S13.1 D7): that is what makes PoP coverage arrive within one
	// renewal cycle for a running fleet, instead of only for gateways enrolled after 0057 shipped.
	if err := s.q.RenewNodeCert(ctx, sqlc.RenewNodeCertParams{ID: node.ID, CertSerial: iss.Serial,
		AgentVersion: agentVersion, CertNotAfter: pgtype.Timestamptz{Time: iss.NotAfter, Valid: true},
		CertPublicKey: spkiText(iss.PublicKeySPKI)}); err != nil {
		return "", err
	}
	return iss.CertPEM, nil
}

// DesiredState returns the interface config + peers the agent should converge
// to: one Peer per active device owned by an active user, each with its assigned
// /32 as AllowedIPs. The interface address is the org pool's gateway (S3.5);
// MTU is explicit (WireGuard's default 1420).
func (s *Service) DesiredState(ctx context.Context, node sqlc.Node) (DesiredState, error) {
	_ = s.q.TouchNodeSeen(ctx, node.ID)
	return s.desiredState(ctx, node)
}

// HandoffBaseState compiles the same exact ordinary base without falsely
// stamping the node live. P3 may prepare authority for a disconnected standby;
// a control-plane compile is not agent liveness evidence.
func (s *Service) HandoffBaseState(ctx context.Context, node sqlc.Node) (DesiredState, error) {
	return s.desiredState(ctx, node)
}

func (s *Service) desiredState(ctx context.Context, node sqlc.Node) (DesiredState, error) {
	ipv6Pool, err := ipalloc.EnsureOrgIPv6Pool(ctx, s.pool, node.OrgID)
	if err != nil {
		return DesiredState{}, err
	}
	rows, err := s.q.ListActiveWireGuardPeersForNode(ctx, node.ID)
	if err != nil {
		return DesiredState{}, err
	}
	// ⛔ THE EXCLUSION IS REPORTED, NOT SILENT (S15.2 walk Leg 4). A device dropped from the peer set for a
	// malformed key is invisible to its owner — their tunnel simply does not work, and every screen says
	// the gateway is healthy. That is the reassuring-empty class on a data plane.
	//
	// ⚠ ONE LOG LINE PER EXCLUDED DEVICE, NAMED. A count would say "something is wrong somewhere"; the
	// operator needs to know WHICH device, because the fix is per-device (re-enrol, or wait for the agent
	// to report its real key).
	if bad, e := s.q.ListMalformedKeyPeersForNode(ctx, node.ID); e == nil {
		for _, b := range bad {
			slog.Warn("peer_excluded_malformed_key",
				slog.String("node", node.Name), slog.String("device_id", b.ID.String()),
				slog.String("device", b.Name), slog.String("public_key", b.PublicKey),
				slog.String("consequence", "this device is NOT a WireGuard peer on this gateway and its tunnel will not work"),
				slog.String("why", "wg syncconf rejects the ENTIRE interface config on one malformed key, so the peer is dropped to keep every other peer working"))
		}
	}
	peers := make([]Peer, 0, len(rows))
	peerKeys := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		// Keyless (OVPN) devices are excluded AT THE SOURCE now (ListActiveWireGuardPeersForNode's format
		// check — the single owner of the D-S9.4-MODEL invariant). This stays as a cheap subordinate
		// assertion so a query regression can't silently re-brick the fleet (WF-OVPN-10).
		if r.PublicKey == "" {
			continue
		}
		p := Peer{PublicKey: r.PublicKey}
		// AllowedIPs is the peer's assigned tunnel address (its /32). A device with
		// no address yet (shouldn't happen post-S3.4 allocation) carries no routes.
		if r.AssignedIp != nil && *r.AssignedIp != "" {
			p.AllowedIPs = []string{*r.AssignedIp + "/32"}
			if ipv6Pool != "" {
				if v6, e := ipalloc.IPv6DeviceAddr(ipv6Pool, node.OrgID, *r.AssignedIp); e == nil {
					p.AllowedIPs = append(p.AllowedIPs, v6.String()+"/128")
				}
			}
		}
		peers = append(peers, p)
		peerKeys[r.PublicKey] = struct{}{}
	}
	// F05.2 warm stage. The old canonical peer above remains the only peer
	// owning the agent address. The candidate has empty AllowedIPs until this
	// gateway reports its nonzero handshake and the CP commits the key.
	stagedRows, err := s.q.ListPreparedAgentWireGuardPeersForNode(ctx, node.ID)
	if err != nil {
		return DesiredState{}, err
	}
	peers = appendWarmWireGuardCandidates(peers, peerKeys, stagedRows)
	// The interface address is the pool gateway (first usable host) with the
	// pool's prefix, so the server has an on-link route to the whole pool and can
	// route peer traffic. Derived from the org pool (S3.5). If the org row is
	// unavailable (e.g. soft-deleted) or its CIDR is somehow invalid, fall back to
	// the default pool rather than failing the whole fetch — the agent must still
	// be able to converge (e.g. to drop peers), not spin on errors.
	gatewayCIDR := defaultGatewayCIDR
	org, orgErr := s.q.GetOrganizationByID(ctx, node.OrgID)
	if orgErr == nil {
		if gw, gerr := ipalloc.GatewayCIDR(org.PoolCidr); gerr == nil {
			gatewayCIDR = gw
		}
	}
	if ipv6Pool != "" {
		if gw6, e := ipalloc.IPv6GatewayCIDR(ipv6Pool, node.OrgID); e == nil {
			gatewayCIDR += "," + gw6
		}
	}
	ds := DesiredState{
		ProtocolVersion:  ProtocolVersion,
		NodeID:           node.ID.String(),
		InterfaceAddress: gatewayCIDR,
		MTU:              1420,
		ListenPort:       51820,
		Peers:            peers,
		// D-S9.5-OPTIN: run the OVPN server on this gateway iff the org opted in (org-level for now).
		OVPNEnabled: orgErr == nil && org.OvpnEnabled,
	}
	// S9.1 Slice 4c: the OpenVPN roster for this gateway. Out-of-hash plumbing — a query fault DEGRADES
	// (empty roster, logged) rather than failing the WireGuard fetch: an OVPN roster hiccup must never
	// break WG peers (the classes are decoupled). Next fetch retries. The clients' /32s already reach
	// the agent through the compiled Policy; this carries the CN↔/32 binding the agent needs for CCD.
	if ovpnRows, oerr := s.q.ListActiveOVPNDevicesForNode(ctx, node.ID); oerr != nil {
		slog.Warn("ovpn_roster_degraded", "node_id", node.ID.String(), "error", oerr.Error())
	} else {
		for _, r := range ovpnRows {
			ip := ""
			if r.AssignedIp != nil {
				ip = *r.AssignedIp
			}
			if ip == "" {
				continue // a device without an assigned /32 can't be pushed a CCD ifconfig-push
			}
			ds.OVPNClients = append(ds.OVPNClients, OVPNClient{CommonName: r.ID.String(), IP: ip, FullTunnel: r.FullTunnel})
		}
	}
	// D-S9.6-CERT-DELIVERY: when this gateway runs OVPN, deliver its server MATERIAL (mint-once, then
	// re-delivered idempotently) so the agent writes ca.crt/server.crt/server.key at cfgDir — the
	// zero-touch precondition. Degrades (no material, logged) rather than failing the WG fetch; the
	// agent then refuses loudly (ovpn_certs_absent) until the next fetch delivers. OFF → nil → the agent
	// SWEEPS the files.
	if ds.OVPNEnabled && s.ovpnServerCert != nil {
		if ca, cert, key, cerr := s.ovpnServerCert(ctx, node.OrgID, node.ID); cerr != nil {
			slog.Warn("ovpn_server_cert_degraded", "node_id", node.ID.String(), "error", cerr.Error())
		} else {
			// S9.1 Slice 5: deliver the org's signed CRL alongside the server material (crl-verify is
			// ALWAYS-ON). A real-or-EMPTY CRL always accompanies enabled OVPN; a CRL fault DEGRADES the
			// material (no partial delivery — the agent refuses-loudly on the missing crl.pem) rather than
			// serving crl-verify-less.
			if s.ovpnCRL == nil {
				ds.OVPNServer = &OVPNServerMaterial{CA: ca, Cert: cert, Key: key}
			} else if crl, crlErr := s.ovpnCRL(ctx, node.OrgID); crlErr != nil {
				slog.Warn("ovpn_crl_degraded", "node_id", node.ID.String(), "error", crlErr.Error())
			} else {
				ds.OVPNServer = &OVPNServerMaterial{CA: ca, Cert: cert, Key: key, CRL: crl}
			}
		}
	}
	// S8.6 REDUCE #1: load the site topology ONCE up front (site nodes only) and derive the active hub from
	// it BEFORE the policy compile, so the policy transit grant and the data-plane site-link graph cite the
	// SAME hub (one derivation per compile pass, fed to both). A non-site node loads no topology and passes
	// activeHub=Nil — no site→site transit grant lands on a non-gateway node either way. The load moved up
	// from the S8.2 block below; its DesiredState-ATOMIC failure semantics are preserved byte-for-byte.
	var topo siteTopology
	var haveTopo bool
	var activeHub uuid.UUID
	if node.SiteID.Valid {
		load := s.siteTopoLoad
		if load == nil { // directly-constructed Service (tests) → the real loader
			load = s.loadSiteTopology
		}
		t, terr := load(ctx, node.OrgID)
		if terr != nil {
			// DesiredState-ATOMIC LAW (original, unamended): a multi-section artifact assembly error FAILS
			// THE WHOLE FETCH — never a partial artifact that reads whole. The agent's standing FAIL-STATIC
			// contract (since S3.1) then holds LAST-GOOD everything, so nothing (peers, routes, policy) is
			// torn down across the blip. A topology-query error is the SAME class as any other DesiredState
			// query error — a DB fault marginally widening the fetch's failure surface, NOT a new coupling
			// of revocation to sites: revocation rides the push path, and a push landing during a DB
			// outage always waited. (The R1 "omit the section" attempt was WRONG — full-sweep reconcile
			// DELETES an omitted section, tearing down the live site path; F1. The security-precedence
			// amendment is withdrawn: it manufactured partial sections that full-sweep cannot survive.)
			return DesiredState{}, terr
		}
		topo, haveTopo = t, true
		if h := electSiteHub(topo, time.Now()); h != nil { // the ONE derivation head, fed to policy + graph
			activeHub = h.ID
		}
		// WF-A D-WFA-5b — device-peer HOSTING (the companion to endpoint-derivation). A device assigned to a
		// HUB-SET MEMBER is hosted on EVERY member's DesiredState, so the promoted hub already knows the
		// device when the re-homed dial lands (without this, ListActiveWireGuardPeersForNode's node_id scoping means
		// the promoted hub lacks the device → the dial handshake fails → (C) is a half-fix). On the ACTIVE
		// PRIMARY the device peer carries its /32 (crypto-routes the device); on a STANDBY it is WARM (empty
		// AllowedIPs — pubkey known so the handshake completes, the /32 rides the active-primary recompile on
		// promotion, mirroring the site-link single-valued invariant). A device on a NON-member gateway is
		// UNCHANGED (its own /32; it dials its own gateway — the spoke-device gap stays deferred).
		members := activeHubMembers(topo, time.Now())
		isMember, thisIsPrimary := false, false
		memberIDs := make([]uuid.UUID, 0, len(members))
		for i := range members {
			memberIDs = append(memberIDs, members[i].ID)
			if members[i].ID == node.ID {
				isMember, thisIsPrimary = true, i == 0
			}
		}
		if isMember {
			wp, werr := s.widenedDevicePeers(ctx, memberIDs, thisIsPrimary)
			if werr != nil {
				return DesiredState{}, werr // DesiredState-ATOMIC: a widening query fault fails the whole fetch
			}
			// REPLACE the node's own /32 device peers with the union (site-link peers
			// append below), then restore this node's F05 warm candidates. Widening is
			// intentionally authoritative for canonical peers, but it must not erase a
			// prepared candidate before the reporter can acknowledge its empty-
			// AllowedIPs stage.
			ds.Peers = widenedPeersWithWarmCandidates(wp, stagedRows)
			// WF-OVPN-9: widen the OVPN roster (CCD) across the SAME members so a multi-remote .ovpn reaches an
			// accepting gateway whichever it fails over to — the OpenVPN twin of the WG peer widening above,
			// reading the same activeHubMembers authority. REPLACES the node's own per-node roster.
			wr, werr := s.widenedOVPNRoster(ctx, memberIDs)
			if werr != nil {
				return DesiredState{}, werr
			}
			ds.OVPNClients = wr
		}
	}

	if s.policy != nil {
		pol, err := s.policy.CompiledForNode(ctx, node.OrgID, node.ID, activeHub)
		switch {
		case err == nil:
			ds.Policy = pol
		case orgErr == nil && org.ZeroTrustMode == zeroTrustOff:
			// A policy-subsystem error must NOT fail the whole desired state — the PEERS
			// are already built above, so revocation still converges (the <5s SLA is
			// independent of the policy engine, finding #3). Scoping (finding #2): when we
			// can CONFIRM the org has Zero Trust OFF, serve the mesh — a policy-subsystem
			// blip must not blackhole an org that never opted into enforcement. We leave
			// ds.Policy nil (the agent decodes nil = blanket mesh, and onPolicy fires on nil
			// to unset any prior policy). nil matches the compiler's off-mode output for a
			// DEVICE-LESS node exactly (CompiledForNode returns nil there), so the pushed/
			// applied hashes stay "" and PolicyDegradedForNodes never false-alarms (finding
			// #C — a non-nil mesh artifact here diverged from that nil and read as degraded).
			slog.Warn("policy_compile_failed_org_off_serving_mesh",
				slog.String("node_id", node.ID.String()), slog.String("error", err.Error()))
			// ds.Policy stays nil.
		default:
			// Enforcing, OR the org mode is UNKNOWN (org row unreadable): FAIL CLOSED. An
			// enforcing org must never revert to the open mesh on a policy error, and if we
			// cannot confirm the mode we assume the boundary is in force. Serve the peers;
			// lock the policy to a deny-all enforcing artifact identical to the compiler's
			// device-less enforcing fallback — SAME policyspec.ProtocolVersion (finding #D:
			// nodes.ProtocolVersion is a different constant; using it would fork the hash
			// from CompiledForNode's and false-alarm every fail-closed gateway). (nil would
			// decode as mesh = fail-OPEN.)
			slog.Warn("policy_compile_failed_failing_closed",
				slog.String("node_id", node.ID.String()), slog.String("error", err.Error()))
			// Content-derived version (S8.2 D1b): a deny-all has an empty Allow → RequiredVersion == 4,
			// byte-identical to the compiler's device-less enforcing fallback for the SAME node, so the
			// pushed/applied hashes still agree (finding #D preserved — no fork).
			ds.Policy = &policyspec.Compiled{
				Version: policyspec.RequiredVersion(policyspec.Compiled{Mode: "enforcing"}),
				NodeID:  node.ID.String(), Mode: "enforcing", Mesh: false,
			}
		}
	}

	// S8.2 site-to-site plumbing (CORE, all editions): if this node is a site gateway, add its site-link WG
	// peers (hub-and-spoke) + kernel routes, from the org's site topology loaded ONCE above. finalizeArtifact
	// is the SINGLE SOURCE that attaches routes + derives the content version — the SAME step the pushed-hash
	// path (trackDesync / PolicyHealthForNodes) calls, so the served artifact and the desync baseline can
	// NEVER disagree about the artifact's contents (the #1 fix: two compile paths agreeing).
	if haveTopo {
		peers, _ := siteLinkGraphFrom(topo, node)
		ds.Peers = append(ds.Peers, peers...)
		handoffPeers, _ := k8sHandoffGraph(topo, node)
		ds.Peers = append(ds.Peers, handoffPeers...)
		ds.Policy = s.finalizeArtifact(topo, node, ds.Policy)
	}
	return ds, nil
}

func appendWarmWireGuardCandidates(peers []Peer, seen map[string]struct{}, candidates []sqlc.ListPreparedAgentWireGuardPeersForNodeRow) []Peer {
	for _, candidate := range candidates {
		if candidate.CandidatePublicKey == nil {
			continue
		}
		if _, duplicate := seen[*candidate.CandidatePublicKey]; duplicate {
			continue
		}
		peers = append(peers, Peer{PublicKey: *candidate.CandidatePublicKey, AllowedIPs: []string{}})
		seen[*candidate.CandidatePublicKey] = struct{}{}
	}
	return peers
}

func widenedPeersWithWarmCandidates(peers []Peer, candidates []sqlc.ListPreparedAgentWireGuardPeersForNodeRow) []Peer {
	seen := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		seen[peer.PublicKey] = struct{}{}
	}
	return appendWarmWireGuardCandidates(peers, seen, candidates)
}

// widenedDevicePeers is WF-A D-WFA-5b's device-peer hosting: the UNION of device peers across all hub-set
// members (deduped by pubkey), so a device assigned to any member is present on every member. thisIsPrimary
// decides AllowedIPs: the ACTIVE PRIMARY carries each device's /32 (crypto-routing); a STANDBY holds the
// peer WARM (empty AllowedIPs — the /32 lands when it's promoted and recompiles). Sorted by pubkey so the
// agent's reconcile is a steady-state no-op. A per-member query error fails the whole fetch (atomic).
func (s *Service) widenedDevicePeers(ctx context.Context, memberIDs []uuid.UUID, thisIsPrimary bool) ([]Peer, error) {
	seen := map[string]bool{}
	out := make([]Peer, 0)
	for _, mid := range memberIDs {
		rows, err := s.q.ListActiveWireGuardPeersForNode(ctx, mid)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			// WF-OVPN-10: a KEYLESS (OpenVPN) device is NEVER a WireGuard peer — an empty PublicKey
			// renders `PublicKey = ` and makes `wg syncconf` reject the ENTIRE config, bricking this
			// hub member's whole WG reconcile (one OpenVPN client bricking the WireGuard fleet). This
			// guard-not-mirrored miss (the main peer path had the D-S9.4-MODEL skip; this WF-A hub-set
			// path predates keyless devices) is now owned at the SOURCE by ListActiveWireGuardPeersForNode's
			// `public_key <> ''`; this is a subordinate assertion at the second consumer.
			if r.PublicKey == "" {
				continue
			}
			if seen[r.PublicKey] {
				continue
			}
			seen[r.PublicKey] = true
			p := Peer{PublicKey: r.PublicKey}
			if thisIsPrimary && r.AssignedIp != nil && *r.AssignedIp != "" {
				p.AllowedIPs = []string{*r.AssignedIp + "/32"} // active primary crypto-routes the device
			}
			// standby: empty AllowedIPs (warm) — pubkey known, handshake completes, no routing until promotion
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PublicKey < out[j].PublicKey })
	return out, nil
}

// widenedOVPNRoster is WF-OVPN-9's OpenVPN twin of widenedDevicePeers: the UNION of OVPN clients across all
// hub-set members (deduped by device id), so a device homed on ANY member has its CCD on EVERY member. The
// multi-remote .ovpn lists all members; whichever gateway it fails over to ACCEPTS it (ccd-exclusive is
// satisfied WARM everywhere). Unlike the WG peer (warm-EMPTY on standbys), an OVPN CCD is BINARY, so every
// member carries the FULL entry — the device's ONE pool /32 + full-tunnel flag, IDENTICAL across members
// (the indistinguishable-/32 is unchanged; widening is about WHICH gateways host the CCD, never the address).
// Same authority (activeHubMembers). Sorted by CN (steady-state no-op). A per-member fault fails the fetch.
func (s *Service) widenedOVPNRoster(ctx context.Context, memberIDs []uuid.UUID) ([]OVPNClient, error) {
	seen := map[string]bool{}
	out := make([]OVPNClient, 0)
	for _, mid := range memberIDs {
		rows, err := s.q.ListActiveOVPNDevicesForNode(ctx, mid)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.AssignedIp == nil || *r.AssignedIp == "" {
				continue
			}
			cn := r.ID.String()
			if seen[cn] {
				continue
			}
			seen[cn] = true
			out = append(out, OVPNClient{CommonName: cn, IP: *r.AssignedIp, FullTunnel: r.FullTunnel})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CommonName < out[j].CommonName })
	return out, nil
}

// OVPNRemotes returns the .ovpn `remote` HOSTS for a device homed on nodeID (WF-OVPN-9 Part A) — the hub-set
// members' endpoint hosts in PRIORITY ORDER, from activeHubMembers, the SAME authority widenedOVPNRoster
// reads. So the profile's remote list and the gateways the widened roster hosts the CCD on are byte-identical
// (one derivation, two consumers). A NON-hub-set node returns nil → the caller uses the node's own endpoint
// (single remote; the zero-config golden — a device on a plain gateway sees no change).
func (s *Service) OVPNRemotes(ctx context.Context, orgID, nodeID uuid.UUID) ([]string, error) {
	topo, err := s.loadSiteTopology(ctx, orgID)
	if err != nil {
		return nil, err
	}
	members := activeHubMembers(topo, time.Now())
	isMember := false
	for i := range members {
		if members[i].ID == nodeID {
			isMember = true
		}
	}
	if !isMember {
		return nil, nil
	}
	hosts := make([]string, 0, len(members))
	for i := range members {
		if h := endpointHost(members[i].Endpoint); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// endpointHost strips the port from a "host:port" gateway endpoint (the OVPN remote uses its own port 1194).
func endpointHost(endpoint string) string {
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

// siteTopology is the org's site-link input, loaded ONCE (loadSiteTopology) and consumed per-node by the
// PURE siteLinkGraphFrom / finalizeArtifact. Loading once lets the batch pushed-hash path finalize N
// nodes off a single pair of org queries instead of N (and the served path uses the same shape).
type siteTopology struct {
	gws     []sqlc.ListSiteGatewaysForOrgRow
	subnets map[uuid.UUID][]string // site_id -> approved subnet CIDRs
	// dnsForwards (S8.4) is the org's cross-site DNS forwarding table — the union of every site's
	// dns_forwarding entries, compiled onto EVERY gateway so any gateway can answer for any site's zone.
	dnsForwards []policyspec.DNSForward
	// hubMembers (S8.6 Slice 4) is the PERSISTED ACTIVE hub order (org_hub_set.members) resolved to gateway
	// rows IN ORDER — the ONE truth the compiler consumes (a failover promotion changes it, flowing through
	// the ordinary compile+push). Empty when org_hub_set has no row (a not-yet-reconciled org) → the
	// compiler falls back to electSiteHubSet (single-hub), so a fresh org still compiles.
	hubMembers []sqlc.ListSiteGatewaysForOrgRow
	// poolCIDR (A3b, S8.6) is the org's device pool (organizations.pool_cidr), canonical masked form.
	// Consumed by siteLinkGraphFrom (the spoke's hub-PRIMARY peer AllowedIPs — device transit reachability)
	// and finalizeArtifact (Compiled.PoolCIDR → the agent's pool-class DOCKER-USER accepts). Scope (paper):
	// pool rides at most ONE peer per node (the wg single-valued invariant), so A3b covers devices-on-HUB
	// reaching remote sites; devices-on-SPOKES cross-site is the REGISTERED residual (per-device placement
	// on the hub's spoke peers = the churn class D-A3b-1 rejected). Empty when the org row is gone
	// (soft-deleted org — its gateways are converging to teardown anyway).
	poolCIDR string
	// vipMappings (S10.3a) is connector node_id -> the exposed-Service VIP map it alone resolves and DNATs.
	// An unassigned cluster is deliberately absent: guessing among same-site gateways would produce a
	// node with no EndpointSlice watcher and a dead-while-green service.
	vipMappings map[uuid.UUID][]policyspec.VIPMapping
	// k8sDNS (S10.3a) is connector node_id -> the DNS-listen zones for the cluster(s) it fronts:
	// bind :53 on the reserved DNS VIP, serve <cluster>.<zone> direct-answer. Deduped per cluster. Same
	// presence/golden treatment as vipMappings.
	k8sDNS map[uuid.UUID][]policyspec.K8sDNSZone
	// k8sConnectors is the dedicated private service-handoff graph. It is NOT a
	// site link: same-site gateway exclusion remains correct for ordinary LAN
	// routing, while this graph carries only synthetic K8s VIP /32s between an
	// edge hub and its connector.
	k8sConnectors map[uuid.UUID]k8sConnector
}

type k8sConnector struct {
	nodeID    uuid.UUID
	siteID    uuid.UUID
	publicKey string
	endpoint  string
	vips      []string
}

// resolveK8sConnectorRead is the single compatibility boundary for service
// ownership. Pool mode needs the exact joined active member and a positive
// generation; it never falls back to the legacy column. Generation validates
// this CP read only and is not distributed fencing.
func resolveK8sConnectorRead(poolBound bool, legacy, poolActive pgtype.UUID, generation *int64) (uuid.UUID, bool) {
	if !poolBound {
		if !legacy.Valid {
			return uuid.Nil, false
		}
		return uuid.UUID(legacy.Bytes), true
	}
	if !poolActive.Valid || generation == nil || *generation <= 0 {
		return uuid.Nil, false
	}
	return uuid.UUID(poolActive.Bytes), true
}

// loadSiteTopology runs the two org-wide site queries once. Full-sweep by construction: an unbound/
// deleted site drops out of ListSiteGatewaysForOrg / ListSiteSubnetsForOrg, so its peers + routes vanish.
func (s *Service) loadSiteTopology(ctx context.Context, orgID uuid.UUID) (siteTopology, error) {
	gws, err := s.q.ListSiteGatewaysForOrg(ctx, orgID)
	if err != nil {
		return siteTopology{}, err
	}
	subs, err := s.q.ListSiteSubnetsForOrg(ctx, orgID) // approved (site_id, cidr)
	if err != nil {
		return siteTopology{}, err
	}
	sub := map[uuid.UUID][]string{}
	for _, ss := range subs {
		sub[ss.SiteID] = append(sub[ss.SiteID], ss.Cidr.String())
	}
	// S8.4: union the sites' dns_forwarding JSONB into the org table. A malformed row is SKIPPED (never
	// fail the whole topology load over one bad DNS blob — the agent's forwarder also skip-degrades).
	raws, err := s.q.ListSiteDNSForwardsForOrg(ctx, orgID)
	if err != nil {
		return siteTopology{}, err
	}
	var fwds []policyspec.DNSForward
	for _, raw := range raws {
		if len(raw) == 0 {
			continue
		}
		var entries []policyspec.DNSForward
		if e := json.Unmarshal(raw, &entries); e != nil {
			slog.Warn("dns_forwarding_unmarshal_skipped", "org_id", orgID.String(), "error", e.Error())
			continue
		}
		fwds = append(fwds, entries...)
	}
	// S8.6 REDUCE: the PERSISTED active hub order, resolved to gateway rows in order — what the compiler
	// consumes so a failover promotion flows through the ordinary compile. DERIVE-THEN-FILTER (#1 sharpening):
	// the active order is deriveActive(configured, demoted) — the ONE shared derivation — computed FIRST, then
	// the gateway-existence filter is applied to the DERIVED order (never to `configured` upstream of the
	// derivation — that would be a second, shadow derivation input, the exact class the reduce killed). A
	// member no longer a live gateway (unbound/deleted) is dropped from the active order at CONSUMPTION, a
	// transient the membership-event reconcile (ReconcileHubSet on the unbind/delete path) then makes durable.
	// No row → nil → fallback (a not-yet-reconciled org still compiles).
	var hubMembers []sqlc.ListSiteGatewaysForOrgRow
	if hs, herr := s.q.GetOrgHubSet(ctx, orgID); herr == nil {
		byID := make(map[uuid.UUID]sqlc.ListSiteGatewaysForOrgRow, len(gws))
		for _, g := range gws {
			byID[g.ID] = g
		}
		for _, mid := range deriveActive(hs.Configured, hs.Demoted) {
			if g, ok := byID[mid]; ok {
				hubMembers = append(hubMembers, g)
			}
		}
	} else if herr != pgx.ErrNoRows {
		return siteTopology{}, herr
	}
	// A3b: the org's device pool, canonical masked. A read ERROR fails the load (DesiredState-ATOMIC — a
	// silently-empty pool would strand device transit dead-while-green, the exact class the law exists
	// for); ErrNoRows (soft-deleted org) degrades to empty — those gateways are tearing down regardless.
	var poolCIDR string
	if org, oerr := s.q.GetOrganizationByID(ctx, orgID); oerr == nil {
		if p, perr := netip.ParsePrefix(org.PoolCidr); perr == nil {
			poolCIDR = p.Masked().String()
		}
	} else if oerr != pgx.ErrNoRows {
		return siteTopology{}, oerr
	}
	// S10.3: the org's exposed K8s Services, grouped by the SITE whose gateway fronts each cluster. A DesiredState
	// atomic on error (a silently-empty map would strand an exposed Service dead-while-green). Empty for a
	// non-cluster org (map stays nil → finalizeArtifact staples nothing → byte-identical golden).
	vipMappings := map[uuid.UUID][]policyspec.VIPMapping{}
	k8sDNS := map[uuid.UUID][]policyspec.K8sDNSZone{}
	connectors := map[uuid.UUID]k8sConnector{}
	vipSeen := map[uuid.UUID]map[string]bool{} // connector node_id -> synthetic host route -> present
	gatewayByID := make(map[uuid.UUID]sqlc.ListSiteGatewaysForOrgRow, len(gws))
	for _, g := range gws {
		gatewayByID[g.ID] = g
	}
	// Fenced HA keeps every eligible pool member as a warm handoff peer. This
	// identity set is deliberately wider than resolution ownership: during the
	// post-CAS nonterminal interval the new active connector is not yet eligible
	// for VIP programming, but its serving overlay still requires the edge peer
	// to exist in the ordinary base. Empty vips keep the edge side warm-only.
	handoffMembers, hmerr := s.q.ListK8sHandoffGraphPoolMembersForOrg(ctx, orgID)
	if hmerr != nil {
		return siteTopology{}, hmerr
	}
	for _, member := range handoffMembers {
		connectors[member.NodeID] = k8sConnector{
			nodeID:    member.NodeID,
			siteID:    member.SiteID,
			publicKey: member.WgPublicKey,
			endpoint:  member.Endpoint,
		}
	}
	dnsSeen := map[uuid.UUID]map[string]bool{} // connector node_id -> zone -> present (dedup one listen entry per cluster)
	exposed, kerr := s.q.ListActiveK8sServicesForOrg(ctx, orgID)
	if kerr != nil {
		return siteTopology{}, kerr
	}
	for _, e := range exposed {
		if e.ConnectorPoolID.Valid && !e.PoolConnectorEligible {
			continue // exact pool owner is ineligible: withdraw topology and DNS together
		}
		connectorID, resolved := resolveK8sConnectorRead(e.ConnectorPoolID.Valid, e.LegacyConnectorNodeID, e.PoolActiveNodeID, e.ConnectorGeneration)
		if !resolved {
			continue // legacy unassigned or unresolved pool: no VIP/DNS programming
		}
		connector, ok := gatewayByID[connectorID]
		if !ok || !connector.SiteID.Valid || uuid.UUID(connector.SiteID.Bytes) != e.SiteID || connector.WgPublicKey == "" || connector.Endpoint == "" {
			continue // connector left its site/revoked/unreachable: fail closed, never infer a replacement
		}
		pl, ph := 0, 0
		if e.PortLow != nil {
			pl = int(*e.PortLow)
		}
		if e.PortHigh != nil {
			ph = int(*e.PortHigh)
		}
		// The FQDN is always-explicit (S10.3 (B2)): <service>.<namespace>.svc.<cluster>.<zone>. A collapsed
		// form silently breaks the moment a second cluster shares the zone — correctness beats brevity.
		zone := e.ClusterName + "." + e.DnsZone
		dnsName := k8s.FQDN(e.Name, e.Namespace, e.ClusterName, e.DnsZone) // L8: the ONE FQDN constructor, never a second copy
		vipMappings[connectorID] = append(vipMappings[connectorID], policyspec.VIPMapping{
			ServiceID: e.ID.String(), VIP: e.Vip, Namespace: e.Namespace, Service: e.Name, ServiceCIDR: e.ServiceCidr,
			Protocol: e.Protocol, PortLow: pl, PortHigh: ph, DNSName: dnsName,
		})
		c := connectors[connectorID]
		if c.nodeID == uuid.Nil {
			c = k8sConnector{nodeID: connectorID, siteID: e.SiteID, publicKey: connector.WgPublicKey, endpoint: connector.Endpoint}
		}
		if vipSeen[connectorID] == nil {
			vipSeen[connectorID] = map[string]bool{}
		}
		serviceVIP := e.Vip + "/32"
		if !vipSeen[connectorID][serviceVIP] {
			vipSeen[connectorID][serviceVIP] = true
			c.vips = append(c.vips, serviceVIP)
		}
		// One DNS-listen entry per cluster (keyed by zone within the site) — the gateway binds :53 on the
		// cluster's reserved DNS VIP and serves that zone. Skipped if the cluster has no reserved VIP (older
		// row) — the DNS answer degrades to unavailable rather than binding a bad address.
		if e.DnsVip != "" {
			dnsVIP := e.DnsVip + "/32"
			if !vipSeen[connectorID][dnsVIP] {
				vipSeen[connectorID][dnsVIP] = true
				c.vips = append(c.vips, dnsVIP)
			}
			if dnsSeen[connectorID] == nil {
				dnsSeen[connectorID] = map[string]bool{}
			}
			if !dnsSeen[connectorID][zone] {
				dnsSeen[connectorID][zone] = true
				k8sDNS[connectorID] = append(k8sDNS[connectorID], policyspec.K8sDNSZone{ListenVIP: e.DnsVip, Zone: zone})
			}
		}
		connectors[connectorID] = c
	}
	for id, c := range connectors {
		sort.Strings(c.vips)
		connectors[id] = c
	}
	return siteTopology{gws: gws, subnets: sub, dnsForwards: fwds, hubMembers: hubMembers, poolCIDR: poolCIDR, vipMappings: vipMappings, k8sDNS: k8sDNS, k8sConnectors: connectors}, nil
}

// deriveActive is THE shared hub-order derivation (S8.6 REDUCE) — the ONE function every consumer reads
// (loadSiteTopology→the data-plane + policy compilers, the failover controller, GetHubSetView). The ACTIVE
// order = the CONFIGURED order with DEMOTED members moved to the BACK (kept as warm standbys in configured
// order, NEVER dropped — a demoted member is a failover candidate, not a deletion). Pure. When nothing is
// demoted the active order IS the configured order (fail-back is that convergence). Members named in
// `demoted` but absent from `configured` are ignored (a stale demotion the next configured-write clears).
func deriveActive(configured, demoted []uuid.UUID) []uuid.UUID {
	dead := make(map[uuid.UUID]bool, len(demoted))
	for _, id := range demoted {
		dead[id] = true
	}
	live := make([]uuid.UUID, 0, len(configured))
	back := make([]uuid.UUID, 0, len(demoted))
	for _, id := range configured {
		if dead[id] {
			back = append(back, id)
		} else {
			live = append(live, id)
		}
	}
	return append(live, back...)
}

// activeHubMembers is the compiler's ordered hub set — the PERSISTED active order (org_hub_set, maintained
// by ReconcileHubSet + the failover tick), or a fallback single-hub election when org_hub_set has no row
// yet (a not-yet-reconciled org). members[0] is the ACTIVE transit hub. This is the one seam through which
// a failover promotion reaches the data plane: the tick changes the persisted order, the next compile reads
// it here — no failover-special path.
func activeHubMembers(topo siteTopology, now time.Time) []sqlc.ListSiteGatewaysForOrgRow {
	if len(topo.hubMembers) > 0 {
		return topo.hubMembers
	}
	return electSiteHubSet(topo, now)
}

// SelfHomingNodes names the gateways a MANAGED device can be moved onto without re-issuing its config
// (S12.12 D7) — exactly the nodes for which NodeDial returns derived=true.
//
// ⛔ IT EXISTS BECAUSE "MANAGED DEVICES RE-HOME THEMSELVES" IS ONLY TRUE FOR HUB-SET MEMBERS. A managed
// client polls the dial channel, but activeHubDialFrom returns derived=false for a node outside the active
// hub set, and the client then KEEPS ITS BAKED ENDPOINT. So a managed device transferred onto a non-member
// gateway dials the gateway it just left: moved in the database, broken on the wire, and — before this —
// reporting needs_reexport=false on every surface, because ProfileStale's gateway cause is static-only.
//
// That residual was acceptable while the only re-homing path was the operator restore of a revoked
// gateway's devices: rare, deliberate, and already a re-issue event. Transfer makes re-homing ROUTINE, which
// is what turns a registered residual into a defect. Named here rather than inferred at each call site, so
// the transfer's report and the device list's staleness answer the question from ONE derivation.
func (s *Service) SelfHomingNodes(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]bool, error) {
	topo, err := s.loadSiteTopology(ctx, orgID)
	if err != nil {
		return nil, err
	}
	members := activeHubMembers(topo, time.Now())
	out := make(map[uuid.UUID]bool, len(members))
	for i := range members {
		out[members[i].ID] = true
	}
	return out, nil
}

// DeviceDial is WF-A D-WFA-6: a device's CURRENT dial (endpoint + gateway pubkey) derived from the org's
// ACTIVE HUB, so a running device re-homes on promotion via the routed-ranges poll. AUTH (D-WFA-6 cond 2):
// the org-scoped GetDevice is the cross-ORG guard; the owner check is the cross-DEVICE guard — a device
// fetches ONLY its own dial. A non-owned / missing device returns device_not_found (no-oracle: never reveal
// another user's device exists). derived=false (empty endpoint+pubkey) when the device's node is NOT a
// hub-set member — the client then keeps its baked endpoint (the deferred spoke-device case).
func (s *Service) DeviceDial(ctx context.Context, orgID, deviceID, callerUserID uuid.UUID) (endpoint, pubkey string, derived bool, err error) {
	dev, e := s.q.GetDevice(ctx, sqlc.GetDeviceParams{ID: deviceID, OrgID: orgID})
	if e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", "", false, apierr.NotFound("device_not_found", "no such device in this organization")
		}
		return "", "", false, e
	}
	if dev.UserID != callerUserID { // cross-device guard: only the owner may fetch a device's dial (no-oracle NotFound)
		return "", "", false, apierr.NotFound("device_not_found", "no such device in this organization")
	}
	// Active-only (review #3): the data-plane rule is "peers exist only for an ACTIVE device" — a pending
	// device has no gateway peer, so its dial is useless AND serving it would make this API contradict that
	// model. (Revoked devices are already excluded — GetDevice filters deleted_at.) Same no-oracle NotFound.
	if dev.Status != "active" {
		return "", "", false, apierr.NotFound("device_not_found", "no such device in this organization")
	}
	return s.NodeDial(ctx, orgID, dev.NodeID)
}

// NodeDial derives the active-hub dial (endpoint + gateway pubkey) for a NODE (WF-A D-WFA-6) — the shared
// core of DeviceDial + the mint-time device-config derivation (a new device on a hub-set member dials the
// active hub, not its arbitrary assigned gateway). No auth (the caller has already authorized the node/
// device). derived=false when the node is not a hub-set member (caller keeps the node's own endpoint).
func (s *Service) NodeDial(ctx context.Context, orgID, nodeID uuid.UUID) (endpoint, pubkey string, derived bool, err error) {
	topo, e := s.loadSiteTopology(ctx, orgID)
	if e != nil {
		return "", "", false, e
	}
	ep, pk, ok := activeHubDialFrom(nodeID, activeHubMembers(topo, time.Now()))
	return ep, pk, ok, nil
}

// activeHubDialFrom is WF-A's endpoint-derivation primitive (D-WFA-5 (C)): a device whose assigned node is a
// HUB-SET MEMBER dials the ACTIVE PRIMARY (activeMembers[0] — the head of the ONE derivation, activeHub
// Members), so its dial FOLLOWS promotions while identity (node_id) stays put. Returns the active primary's
// (endpoint, pubkey) + derived=true when nodeID is a member; derived=false otherwise — the caller keeps the
// node's OWN endpoint (the deferred spoke-device case; no promotion event fires there). PURE: the active
// order is passed in (already deriveActive'd), never re-elected here.
func activeHubDialFrom(nodeID uuid.UUID, activeMembers []sqlc.ListSiteGatewaysForOrgRow) (endpoint, pubkey string, derived bool) {
	if len(activeMembers) == 0 {
		return "", "", false
	}
	for i := range activeMembers {
		if activeMembers[i].ID == nodeID {
			return activeMembers[0].Endpoint, activeMembers[0].WgPublicKey, true
		}
	}
	return "", "", false
}

// siteLinkGraphFrom builds a site-gateway node's site-link WG peers + kernel routes from a loaded
// siteLinkKeepaliveSecs (S8.3 CK) is the persistent-keepalive interval on every site-link peer — the
// wireguard-conventional 25s, comfortably under NAT UDP-mapping timeouts, so a NAT'd spoke stays dialable
// and an idle link never false-stales for want of a handshake.
const siteLinkKeepaliveSecs = 25

// topology (S8.2 hub-and-spoke, Item 6/7) — PURE. Returns (nil, nil) when the node is not a site gateway
// or there is no remote site to reach. HUB = the site gateway with a public endpoint (v1; deterministic
// by lowest node id if several — multi-hub reserved). A spoke peers ONLY with the hub (AllowedIPs = ALL
// remote subnets, reaching other spokes VIA the hub); the hub peers with every spoke (each peer's
// AllowedIPs = that spoke's OWN subnets); the hub forwards between them. Routes = every remote site's
// approved subnets. Deterministic (sorted) so a steady-state reconcile is a no-op.
// hubStaleWindow — a gateway not seen within this window is UNHEALTHY for hub ORDERING (sorts after fresh
// peers). ~3 missed reports; the server-side twin of the site surface's freshness idea.
const hubStaleWindow = 90 * time.Second

// electSiteHubSet is THE org transit-hub election (S8.6 D1) — ORG-LEVEL (one transit hub for the org's whole
// site mesh; NOT per-site — see docs/S8.6-decisions.md keying correction). Returns the CAPABLE gateways
// (public endpoint + a reported WG key — the ONLY membership criterion, so a capable gateway from ANY site
// enters; the standby need not share the primary's site) ORDERED: hub_priority (admin pin, ascending) >
// health (fresh-before-stale) > id (deterministic). members[0] is the active transit hub; the rest are
// failover candidates in order. PURE given `now` (used only for the health cut).
func electSiteHubSet(topo siteTopology, now time.Time) []sqlc.ListSiteGatewaysForOrgRow {
	capable := make([]sqlc.ListSiteGatewaysForOrgRow, 0, len(topo.gws))
	for _, g := range topo.gws {
		if g.Endpoint != "" && g.WgPublicKey != "" { // the capability gate (endpoint + key)
			capable = append(capable, g)
		}
	}
	sort.Slice(capable, func(i, j int) bool { return hubLess(&capable[i], &capable[j], now) })
	// TWO-TIER MEMBERSHIP (S8.6 (3)) — HA is OPT-IN BY PIN, resolving the "capable ⇒ hub-posture" collision
	// (an endpoint-bearing LEAF, e.g. an accidentally-public spoke, must NOT be drafted into hub duty). The
	// pin was already the top of the ordering; it is now ALSO the membership DECLARATION (operators outrank
	// magic, completing itself):
	//   - ANY pins present → the set is the PINNED, capable gateways (pin declares "carry the org's transit";
	//     capability still GATES — a pinned-but-NAT'd/keyless gateway is ineligible). Pinned are the sorted
	//     prefix, so collecting them preserves pin>health>id order.
	//   - NO pins → a SINGLE auto-elected hub (today's zero-config behavior, BYTE-IDENTICAL — no standbys
	//     without declared intent, so a fresh org needs zero configuration).
	var pinned []sqlc.ListSiteGatewaysForOrgRow
	for _, g := range capable {
		if g.HubPriority != nil {
			pinned = append(pinned, g)
		}
	}
	if len(pinned) > 0 {
		return pinned
	}
	if len(capable) == 0 {
		return nil
	}
	return capable[:1] // single-hub set of one (zero-config)
}

func hubHealthy(g *sqlc.ListSiteGatewaysForOrgRow, now time.Time) bool {
	return g.LastSeenAt.Valid && now.Sub(g.LastSeenAt.Time) < hubStaleWindow
}

// hubLess orders two capable gateways: PINNED (hub_priority non-null, ascending) before unpinned; then
// HEALTHY before stale; then id ascending. The admin pin OUTRANKS health — operators outrank the election.
func hubLess(a, b *sqlc.ListSiteGatewaysForOrgRow, now time.Time) bool {
	ap, bp := a.HubPriority, b.HubPriority
	if (ap != nil) != (bp != nil) {
		return ap != nil // pinned before unpinned
	}
	if ap != nil && *ap != *bp {
		return *ap < *bp // lower priority number = more preferred
	}
	if ah, bh := hubHealthy(a, now), hubHealthy(b, now); ah != bh {
		return ah // healthy before stale
	}
	return a.ID.String() < b.ID.String()
}

// electSiteHub returns the org's transit HUB — the HEAD of the election set (members[0]) — or nil when no
// gateway is capable (the B2 no-carrier condition, all NAT'd). THE election every hub fact projects
// (site-link peers, routes, the is_site_hub API projection); the compiler uses ONLY this primary (single-hub
// v1 — standbys don't grow tunnels until S8.6 Slice 3). PURE given now.
func electSiteHub(topo siteTopology, now time.Time) *sqlc.ListSiteGatewaysForOrgRow {
	set := activeHubMembers(topo, now) // the ACTIVE head (persisted order), so is_site_hub/health reflect failover
	if len(set) == 0 {
		return nil
	}
	return &set[0]
}

// HubSet is the org's persisted transit-hub authority (S8.6 REDUCE) — the two writer-partitioned fields.
// Configured is ReconcileHubSet's output (the CONFIGURED membership); Demoted is the failover controller's
// output. The ACTIVE order is Active() = deriveActive(Configured, Demoted) — never stored, one derivation.
type HubSet struct {
	OrgID      uuid.UUID
	Configured []uuid.UUID
	Demoted    []uuid.UUID
	Generation int64
}

// Active is the derived active hub order (the ONE shared derivation) — Configured with Demoted at the back.
func (h HubSet) Active() []uuid.UUID { return deriveActive(h.Configured, h.Demoted) }

// ReconcileHubSet recomputes the org's CONFIGURED transit-hub membership (electSiteHubSet) and PERSISTS it
// via the configured-field writer, bumping the D5 generation ONLY when the configured order changes (the
// atomic CASE). Called at every membership/order-change point (bind/unbind/pin). It writes `configured` ONLY
// — NEVER `demoted` (the writer partition: the failover controller owns demotion state, so a reconcile
// landing during a live failover updates membership without clobbering the demotion). A configured change is
// AUDITED as its own kind (auditHubMembership, condition 1b) — DISTINCT from a promotion/failback — in the
// SAME tx as the write (swallowed-audit law). System actor: a derived consequence of the bind/unbind/pin
// that carries its own user-actor audit.
func (s *Service) ReconcileHubSet(ctx context.Context, orgID uuid.UUID) (HubSet, error) {
	topo, err := s.siteTopoLoad(ctx, orgID)
	if err != nil {
		return HubSet{}, err
	}
	set := electSiteHubSet(topo, time.Now())
	configured := make([]uuid.UUID, 0, len(set))
	for i := range set {
		configured = append(configured, set[i].ID)
	}
	prev, err := s.GetHubSet(ctx, orgID)
	if err != nil {
		return HubSet{}, err
	}
	var out HubSet
	if txErr := s.withTx(ctx, func(q *sqlc.Queries) error {
		row, err := q.UpsertOrgHubSetConfigured(ctx, sqlc.UpsertOrgHubSetConfiguredParams{OrgID: orgID, Configured: configured})
		if err != nil {
			return err
		}
		out = HubSet{OrgID: row.OrgID, Configured: row.Configured, Demoted: row.Demoted, Generation: row.Generation}
		if !sameOrder(prev.Configured, out.Configured) {
			return audit(ctx, q, orgID, nil, auditHubMembership, "org", orgID.String(), map[string]any{
				"configured": idsToStrings(out.Configured), "generation": out.Generation,
			})
		}
		return nil
	}); txErr != nil {
		return HubSet{}, txErr
	}
	return out, nil
}

// GetHubSet reads the persisted transit-hub set (S8.6 REDUCE) — the two fields + the D5 generation. No rows
// (never reconciled) returns a zero set with empty fields, not an error.
func (s *Service) GetHubSet(ctx context.Context, orgID uuid.UUID) (HubSet, error) {
	hs, err := s.q.GetOrgHubSet(ctx, orgID)
	if err == pgx.ErrNoRows {
		return HubSet{OrgID: orgID, Configured: []uuid.UUID{}, Demoted: []uuid.UUID{}, Generation: 0}, nil
	}
	if err != nil {
		return HubSet{}, err
	}
	return HubSet{OrgID: hs.OrgID, Configured: hs.Configured, Demoted: hs.Demoted, Generation: hs.Generation}, nil
}

// latestByPubKey folds node_peer_status rows to the freshest observation per peer pubkey (S8.6 REDUCE #8 —
// ONE shared helper for the two readers: GetHubSetView's metrics + the failover tick's freshness). A GAUGE,
// not a sum: the LATEST handshake wins, never accumulated.
func latestByPubKey(rows []sqlc.NodePeerStatus) map[string]MemberMetrics {
	latest := map[string]MemberMetrics{}
	for _, r := range rows {
		if r.LastHandshakeAt.Valid && r.LastHandshakeAt.Time.After(latest[r.PublicKey].LastHandshakeAt) {
			latest[r.PublicKey] = MemberMetrics{LastHandshakeAt: r.LastHandshakeAt.Time, RxBytes: r.RxBytes, TxBytes: r.TxBytes}
		}
	}
	return latest
}

// MemberLiveness is ONE hub-set member's liveness verdict from THE ONE derivation (WF-B D-WFB-1,
// founder-ruled shared pure function): spoke-observed handshake freshness ⋂ hub-set membership.
// BOTH the failover controller (reads .Fresh for its Step) AND the site-link health surface (reads
// .Fresh + .Demoted for the badge) call deriveMemberLiveness — a SINGLE symbol, never two functions
// with a "MUST match" comment claiming equivalence (that class died in the S8.6 reduce). A health
// badge disagreeing with the controller about who is stale is the two-truths class at the failover
// seam; one pure function called twice cannot disagree with itself.
type MemberLiveness struct {
	Observed bool          // a living witness reported a VALID (non-NULL) handshake for this member (else NO verdict)
	Fresh    bool          // Observed AND age < failoverStaleWindow (meaningless when !Observed)
	Age      time.Duration // now − last handshake (valid only when Observed; for the controller's log line)
	Demoted  bool          // the failover controller has failed-over-PAST this member (in the demoted set)
}

// deriveMemberLiveness is THE ONE liveness derivation (WF-B D-WFB-1). Pure + clockless (now passed
// in). GREP-RED (docs/WF-B-site-link-badge-decisions.md): no site-link freshness computation
// (`now.Sub(…LastHandshakeAt) < failoverStaleWindow`) exists ANYWHERE outside this function — the
// controller and the health surface both read its output.
func deriveMemberLiveness(configured []uuid.UUID, pubkey map[uuid.UUID]string, rows []sqlc.NodePeerStatus, demoted []uuid.UUID, now time.Time) map[uuid.UUID]MemberLiveness {
	latest := latestByPubKey(rows)
	dem := make(map[uuid.UUID]bool, len(demoted))
	for _, id := range demoted {
		dem[id] = true
	}
	out := make(map[uuid.UUID]MemberLiveness, len(configured))
	for _, id := range configured {
		ml := MemberLiveness{Demoted: dem[id]}
		if m, observed := latest[pubkey[id]]; observed { // latestByPubKey skips NULL handshakes → absence = no witness
			ml.Observed = true
			ml.Age = now.Sub(m.LastHandshakeAt)
			ml.Fresh = ml.Age < failoverStaleWindow
		}
		out[id] = ml
	}
	return out
}

// idsToStrings renders a node-id slice for audit metadata (stable, ordered).
func idsToStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// MemberMetrics is a hub member's LATEST node_peer_status observation (S8.6 L1). PRESENT only when a row
// exists (someone handshook with this member) — a not-reporting link has NO metrics (nil), DISTINCT from an
// idle link (a row with rx/tx = 0). rx/tx are RAW gauges since the last handshake (display only, never
// summed monotonic — S11.1). The render cites THIS storage shape, not the report schema.
type MemberMetrics struct {
	LastHandshakeAt  time.Time
	RxBytes, TxBytes int64
}

// HubMemberView is one hub-set member as SERVED: its node id, its ROLE (primary = members[0], else
// standby), its admin hub_priority (the CONFIGURED order — so the UI can show a promotion "in effect" when
// the active order diverges), and its latest metrics (nil when not reporting).
type HubMemberView struct {
	NodeID      uuid.UUID
	Role        string
	HubPriority *int32
	Metrics     *MemberMetrics
}

// HubSetView is the org's persisted hub set as SERVED (S8.6 Slice 6): the D5 generation (the set's version
// tag) + the ordered members with role + L1 metrics. ONE truth — the same persisted org_hub_set every
// consumer (compiler, health, this view) reads; no inference.
type HubSetView struct {
	Generation int64
	Members    []HubMemberView
}

// GetHubSetView serves the persisted active hub set + per-member L1 metrics (node_peer_status). Empty when
// no set is persisted (a not-yet-pinned org). Org-scoped by the caller (member-readable, D5/S8.3 precedent).
func (s *Service) GetHubSetView(ctx context.Context, orgID uuid.UUID) (HubSetView, error) {
	hs, err := s.GetHubSet(ctx, orgID)
	if err != nil {
		return HubSetView{}, err
	}
	gws, err := s.q.ListSiteGatewaysForOrg(ctx, orgID)
	if err != nil {
		return HubSetView{}, err
	}
	keyByNode := make(map[uuid.UUID]string, len(gws))
	prioByNode := make(map[uuid.UUID]*int32, len(gws))
	for i := range gws {
		keyByNode[gws[i].ID] = gws[i].WgPublicKey
		prioByNode[gws[i].ID] = gws[i].HubPriority
	}
	rows, err := s.q.ListNodePeerStatusForOrg(ctx, orgID)
	if err != nil {
		return HubSetView{}, err
	}
	latest := latestByPubKey(rows)
	// S8.6 #3: DERIVE-THEN-FILTER — the SAME discipline loadSiteTopology applies to the data plane. The
	// active order is derived (HubSet.Active()), then filtered against the LIVE gateways (keyByNode is built
	// from ListSiteGatewaysForOrg, the identical status='active' source the data plane reads). A `configured`
	// member no longer a live gateway (revoked/deleted/departed, before the corrector tick has rewritten
	// configured) is DROPPED here — so the view can never show a member the data plane has failed away from.
	active := make([]uuid.UUID, 0, len(hs.Active()))
	for _, mid := range hs.Active() {
		if _, live := keyByNode[mid]; live {
			active = append(active, mid)
		}
	}
	view := HubSetView{Generation: hs.Generation, Members: make([]HubMemberView, 0, len(active))}
	for i, mid := range active {
		mv := HubMemberView{NodeID: mid, Role: "standby", HubPriority: prioByNode[mid]}
		if i == 0 {
			mv.Role = "primary"
		}
		if m, ok := latest[keyByNode[mid]]; ok {
			mm := m
			mv.Metrics = &mm // present only when a node_peer_status row exists (idle=0 vs not-reporting=nil)
		}
		view.Members = append(view.Members, mv)
	}
	return view, nil
}

// SetHubPriority sets (or clears, nil) a gateway's admin hub PIN (D1) and re-elects. Org-checked (a
// cross-org node id -> 404). Audited in-tx; the re-election persists after so the pin takes effect.
func (s *Service) SetHubPriority(ctx context.Context, actor, orgID, nodeID uuid.UUID, priority *int32) error {
	err := s.withTx(ctx, func(q *sqlc.Queries) error {
		old, e := q.GetNodeHubPriority(ctx, sqlc.GetNodeHubPriorityParams{ID: nodeID, OrgID: orgID})
		if e == pgx.ErrNoRows {
			return apierr.NotFound("node_not_found", "no such node in this organization")
		}
		if e != nil {
			return e
		}
		n, e := q.SetNodeHubPriority(ctx, sqlc.SetNodeHubPriorityParams{NodeID: nodeID, OrgID: orgID, HubPriority: priority})
		if e != nil {
			return e
		}
		if n == 0 {
			return apierr.NotFound("node_not_found", "no such node in this organization")
		}
		// Audit the OLD→NEW pin (a topology-consequential act — pinning creates/edits the HA hub set).
		return audit(ctx, q, orgID, &actor, "node.hub_priority_set", "node", nodeID.String(), map[string]any{"old_priority": old, "new_priority": priority})
	})
	if err != nil {
		return err
	}
	_, err = s.ReconcileHubSet(ctx, orgID)
	return err
}

func siteLinkGraphFrom(topo siteTopology, node sqlc.Node) ([]Peer, []policyspec.Route) {
	if !node.SiteID.Valid {
		return nil, nil
	}
	members := activeHubMembers(topo, time.Now()) // the PERSISTED active order (S8.6 Slice 4), or single-hub fallback
	// B2: no capable gateway (all NAT'd) → NO carrier for site traffic, so emit NO routes and NO peers.
	// A route with no peer to carry it is the silent blackhole; surfaced CP-side as site_hub_down.
	if len(members) == 0 {
		return nil, nil
	}
	mySite := uuid.UUID(node.SiteID.Bytes)
	routeSeen := map[string]bool{}
	var routeCIDRs []string
	for i := range topo.gws {
		g := &topo.gws[i]
		if uuid.UUID(g.SiteID.Bytes) == mySite {
			continue
		}
		for _, c := range topo.subnets[uuid.UUID(g.SiteID.Bytes)] {
			if !routeSeen[c] {
				routeSeen[c] = true
				routeCIDRs = append(routeCIDRs, c)
			}
		}
	}
	sort.Strings(routeCIDRs)
	routes := make([]policyspec.Route, 0, len(routeCIDRs))
	for _, c := range routeCIDRs {
		routes = append(routes, policyspec.Route{DstCIDR: c})
	}

	isMember := false
	for i := range members {
		if members[i].ID == node.ID {
			isMember = true
			break
		}
	}

	var peers []Peer
	if isMember {
		// HUB posture — carried by the PRIMARY *and* every STANDBY (the D2 symmetry: a standby is a hub that
		// isn't preferred yet, so promotion changes nothing hub-side). Peer with every non-self,
		// subnet-advertising gateway NOT in this hub's OWN site. SAME-SITE exclusion (S8.6) is the real
		// invariant — two gateways on one shared LAN need no tunnel between them (kills the spurious same-site
		// hub↔hub link the single-node lift now makes possible). A CROSS-site member keeps its subnet-carrying
		// link — in the data plane it IS a spoke, whatever the election calls it (so its subnets stay reachable).
		for i := range topo.gws {
			g := &topo.gws[i]
			if g.ID == node.ID || uuid.UUID(g.SiteID.Bytes) == mySite {
				continue
			}
			ips := append([]string(nil), topo.subnets[uuid.UUID(g.SiteID.Bytes)]...)
			if len(ips) == 0 {
				continue // a gateway advertising no subnets yet contributes no crypto-routing
			}
			sort.Strings(ips)
			peers = append(peers, Peer{PublicKey: g.WgPublicKey, AllowedIPs: ips, Endpoint: g.Endpoint, SiteLink: true, PersistentKeepalive: siteLinkKeepaliveSecs})
		}
	} else if len(routeCIDRs) > 0 {
		// SPOKE: the remote subnets live in the PRIMARY (members[0]) peer's AllowedIPs ONLY — the single-valued
		// invariant (WG's undefined-which across overlapping AllowedIPs is a nondeterminism generator). Every
		// STANDBY member is a WARM keepalive-only peer: AllowedIPs EMPTY (so WG can never crypto-route traffic
		// to it — the no-traffic property is STRUCTURAL, not a convention), endpoint + keepalive so the tunnel
		// handshakes (warm + observable in node_peer_status). Promotion (Slice 4) re-compiles the subnets onto
		// the standby's AllowedIPs — no build, no handshake wait: the tunnel is already up.
		primary := &members[0]
		// A3b: the device POOL rides the hub-PRIMARY peer's AllowedIPs alongside the remote routes — the
		// far half of device→remote-site transit: inbound, wg admits device-sourced (pool-saddr) packets
		// arriving via the hub; outbound, replies to pool addresses crypto-route back to the hub. Primary
		// ONLY — a standby stays AllowedIPs-empty (single-valued invariant), and promotion recompiles the
		// pool onto the new primary exactly as it does routeCIDRs. Reachability, not permission: the far
		// gateway's ip tunnex chain adjudicates via compiled far-grants (D-A3b-1/2).
		spokeIPs := append([]string(nil), routeCIDRs...)
		if topo.poolCIDR != "" {
			spokeIPs = append(spokeIPs, topo.poolCIDR)
			sort.Strings(spokeIPs)
		}
		peers = append(peers, Peer{PublicKey: primary.WgPublicKey, AllowedIPs: spokeIPs, Endpoint: primary.Endpoint, SiteLink: true, PersistentKeepalive: siteLinkKeepaliveSecs})
		for i := 1; i < len(members); i++ {
			sb := &members[i]
			peers = append(peers, Peer{PublicKey: sb.WgPublicKey, AllowedIPs: []string{}, Endpoint: sb.Endpoint, SiteLink: true, PersistentKeepalive: siteLinkKeepaliveSecs})
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	return peers, routes
}

// k8sHandoffGraph compiles the private service path between a connector and the
// active local hub pair. It deliberately does not reuse siteLinkGraphFrom:
// same-site gateways have no ordinary LAN link, but an exposed Service needs a
// connector-specific encrypted hop. The active local primary is the only peer
// allowed to crypto-route VIP traffic; local standbys remain warm with empty
// AllowedIPs, preserving the same single-valued routing invariant as site HA.
func k8sHandoffGraph(topo siteTopology, node sqlc.Node) ([]Peer, []policyspec.Route) {
	if !node.SiteID.Valid || len(topo.k8sConnectors) == 0 || topo.poolCIDR == "" {
		return nil, nil
	}
	nodeSite := uuid.UUID(node.SiteID.Bytes)
	members := activeHubMembers(topo, time.Now())
	var peers []Peer
	var routes []policyspec.Route
	routeSeen := map[string]bool{}
	for _, connector := range topo.k8sConnectors {
		if connector.siteID != nodeSite {
			continue
		}
		// Only hub members in the connector's OWN site may dial its private
		// endpoint. A cross-cloud hub is not accidentally made a private VPC peer.
		var local []sqlc.ListSiteGatewaysForOrgRow
		for _, m := range members {
			if _, isConnector := topo.k8sConnectors[m.ID]; isConnector {
				continue // an in-cluster resolver is never the client-facing edge for this handoff
			}
			if m.SiteID.Valid && uuid.UUID(m.SiteID.Bytes) == connector.siteID && m.Endpoint != "" && m.WgPublicKey != "" {
				local = append(local, m)
			}
		}
		if len(local) == 0 {
			continue // no reachable local client edge: leave the service unavailable, not guessed
		}
		if node.ID == connector.nodeID {
			// Connector return path: the local primary owns the device pool; warm
			// standbys handshake but cannot receive a reply until promotion.
			for i, edge := range local {
				if edge.ID == node.ID {
					continue
				}
				p := Peer{PublicKey: edge.WgPublicKey, Endpoint: edge.Endpoint, SiteLink: true, PersistentKeepalive: siteLinkKeepaliveSecs}
				if i == 0 {
					p.AllowedIPs = []string{topo.poolCIDR}
					if !routeSeen[topo.poolCIDR] {
						routes = append(routes, policyspec.Route{DstCIDR: topo.poolCIDR})
						routeSeen[topo.poolCIDR] = true
					}
				}
				peers = append(peers, p)
			}
			continue
		}
		for i, edge := range local {
			if edge.ID != node.ID {
				continue
			}
			p := Peer{PublicKey: connector.publicKey, Endpoint: connector.endpoint, SiteLink: true, PersistentKeepalive: siteLinkKeepaliveSecs}
			if i == 0 {
				p.AllowedIPs = append([]string(nil), connector.vips...)
				for _, vip := range connector.vips {
					if !routeSeen[vip] {
						routes = append(routes, policyspec.Route{DstCIDR: vip})
						routeSeen[vip] = true
					}
				}
			}
			peers = append(peers, p)
			break
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].PublicKey < peers[j].PublicKey })
	sort.Slice(routes, func(i, j int) bool { return routes[i].DstCIDR < routes[j].DstCIDR })
	return peers, routes
}

// finalizeArtifact is THE SINGLE SOURCE OF TRUTH for a site gateway's served/hashed compiled artifact
// (the #1 fix). It attaches the node's site-to-site kernel routes to the route-less compiled artifact
// and derives the content version — and BOTH the served desired-state AND the pushed-hash desync
// baseline call it, so the two paths can never disagree about the artifact's contents. A non-site node
// or a node with no remote routes is returned unchanged. A nil route-less artifact WITH routes (open
// build, or an off-mode node that would carry routes) is synthesized as a mesh artifact carrying them.
func (s *Service) finalizeArtifact(topo siteTopology, node sqlc.Node, pol *policyspec.Compiled) *policyspec.Compiled {
	if !node.SiteID.Valid {
		return pol
	}
	_, routes := siteLinkGraphFrom(topo, node)
	_, handoffRoutes := k8sHandoffGraph(topo, node)
	routes = append(routes, handoffRoutes...)
	// S10.3a: the explicitly selected connector, not every gateway in its logical site, owns K8s mapping.
	vips := topo.vipMappings[node.ID]
	dnsZones := topo.k8sDNS[node.ID]
	if len(routes) == 0 && len(vips) == 0 && len(dnsZones) == 0 {
		return pol
	}
	// D2: attach THIS gateway's own approved site subnets (the authoritative local-subnet answer) so the
	// agent can source its site routes from the site LAN. Out-of-hash plumbing; rides with Routes (v5).
	local := append([]string(nil), topo.subnets[uuid.UUID(node.SiteID.Bytes)]...)
	sort.Strings(local)
	// S8.4: attach the org-wide DNS forwarding table (out-of-hash CONVENIENCE — NOT hashed, NO version bump,
	// so a route-carrying artifact stays byte-identical for the desync baseline). Every gateway carries the
	// whole table so any gateway answers for any site's zone. nil for a no-DNS org (empty until Slice 2).
	dns := append([]policyspec.DNSForward(nil), topo.dnsForwards...)
	// A3b: attach the org pool so the agent renders the pool-class DOCKER-USER accepts (device transit /
	// device↔device at the Docker tier; the chain adjudicates). Rides WITH routes (this point is past the
	// routes==0 return), so v6 stays content-derived: only multi-site orgs' gateways carry it — a
	// single-site org keeps its pre-v6 artifact byte-identical (and its Docker-dark device↔device is the
	// REGISTERED PD-3 residual, with non-site gateways).
	if pol != nil {
		// Route-gated (multi-site) plumbing rides ONLY with site routes — a single-site cluster gateway
		// (routes==0) gets the VIP map but NOT pool/local/dns (PoolCIDR's v6 route-gating stays intact).
		if len(routes) > 0 {
			pol.Routes = routes
			pol.LocalSubnets = local
			pol.DNSForwards = dns
			pol.PoolCIDR = topo.poolCIDR
		}
		pol.VIPMappings = vips     // S10.3 (triggers RequiredVersion=7 when present)
		pol.K8sDNSZones = dnsZones // S10.3 (A1) — DNS-listen table, same v7 trigger
		pol.Version = policyspec.RequiredVersion(*pol)
		return pol
	}
	c := policyspec.Compiled{NodeID: node.ID.String(), Mode: "off", Mesh: true, VIPMappings: vips, K8sDNSZones: dnsZones}
	if len(routes) > 0 {
		c.Routes = routes
		c.LocalSubnets = local
		c.DNSForwards = dns
		c.PoolCIDR = topo.poolCIDR
	}
	c.Version = policyspec.RequiredVersion(c)
	return &c
}

// pushedHash is the desync baseline for one node: the CanonicalHash of its FINALIZED artifact, or "" for
// a non-enforcing (off/mesh) artifact — an off org has no enforcement boundary, so it never shows
// policy-desynced (finding #C). Because it finalizes the SAME way the served artifact does, a route-
// carrying ENFORCING gateway's pushed hash matches what the agent applies — no false silent_desync (#1).
func (s *Service) pushedHash(topo siteTopology, node sqlc.Node, routeless *policyspec.Compiled) string {
	final := s.finalizeArtifact(topo, node, routeless)
	if final == nil || final.Mode != "enforcing" {
		return ""
	}
	return policyspec.CanonicalHash(*final)
}

// siteTopoHasHub reports whether ANY gateway carries a public endpoint (a hub exists). Org-wide +
// node-independent, so the batch health path computes it ONCE (R5: was an O(N·G) per-node rescan).
func siteTopoHasHub(topo siteTopology) bool {
	return electSiteHub(topo, time.Now()) != nil // one election: hub existence reads the same picker as the designation
}

// siteHubMissing reports the B2 no-carrier condition for ONE node, given a precomputed hubExists: a site
// gateway with REMOTE site subnets to reach but no hub — surfaced as site_hub_down so it is never a
// silent no-op. False for a non-site node, when a hub exists, or when nothing is remote.
func siteHubMissing(hubExists bool, topo siteTopology, node sqlc.Node) bool {
	if hubExists || !node.SiteID.Valid {
		return false
	}
	mySite := uuid.UUID(node.SiteID.Bytes)
	for sid, cidrs := range topo.subnets {
		if sid != mySite && len(cidrs) > 0 {
			return true // remote subnets exist but no hub to carry them
		}
	}
	return false
}

// validEndpoint reports whether s is a clean host:port with a numeric port and
// no whitespace/control characters (which would allow config injection).
func validEndpoint(s string) bool {
	if s == "" || len(s) > 259 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p > 0 && p <= 65535
}

// PeerStatus is per-peer live telemetry reported by the agent.
type PeerStatus struct {
	PublicKey     string
	LastHandshake int64 // unix seconds, 0 = never
	RxBytes       int64
	TxBytes       int64
}

// ReportStatus upserts the reported per-peer telemetry, mapping each pubkey to
// its active device on the node. Batched (one round-trip); unknown pubkeys no-op.
func (s *Service) ReportStatus(ctx context.Context, node sqlc.Node, stats []PeerStatus) error {
	if len(stats) == 0 {
		return nil
	}
	// Reject an implausibly-future handshake (bogus counter / bad clock): stored
	// verbatim it would make time.Since() negative and pin the device "online"
	// forever. A small skew tolerance is allowed. This is the SINGLE enforcement
	// point of the "handshake is never in the future" data invariant that every
	// online reader relies on (see tenancy.OnlineWindow) — hence the regression
	// test in status_test.go. A dropped future report degrades in the HONEST
	// direction: it nulls a previously-valid handshake (fake-offline is a
	// tolerable degradation; fake-online would be a lie).
	maxHS := time.Now().Add(2 * time.Minute).Unix()
	committedWGKey := false
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		for _, st := range stats {
			publicKey := st.PublicKey
			if _, err := q.StageAgentWireGuardCandidate(ctx, sqlc.StageAgentWireGuardCandidateParams{
				NodeID: node.ID, PublicKey: &publicKey,
			}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if st.LastHandshake <= 0 || st.LastHandshake > maxHS {
				continue
			}
			if _, err := q.CommitAgentWireGuardCandidate(ctx, sqlc.CommitAgentWireGuardCandidateParams{
				NodeID: node.ID, PublicKey: &publicKey,
				LastHandshakeAt: time.Unix(st.LastHandshake, 0).UTC(),
				RxBytes:         st.RxBytes, TxBytes: st.TxBytes,
			}); err == nil {
				committedWGKey = true
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if committedWGKey && s.pushOrg != nil {
		s.pushOrg(ctx, node.OrgID)
	}
	params := make([]sqlc.UpsertDeviceStatusParams, 0, len(stats))
	peerParams := make([]sqlc.UpsertNodePeerStatusParams, 0, len(stats)) // S8.6: the gateway-peer sibling
	for _, st := range stats {
		var hs pgtype.Timestamptz
		if st.LastHandshake > 0 && st.LastHandshake <= maxHS {
			hs = pgtype.Timestamptz{Time: time.Unix(st.LastHandshake, 0).UTC(), Valid: true}
		}
		params = append(params, sqlc.UpsertDeviceStatusParams{
			NodeID: node.ID, PublicKey: st.PublicKey, LastHandshakeAt: hs,
			RxBytes: st.RxBytes, TxBytes: st.TxBytes,
		})
		// S8.6 SIBLING upsert: the SAME report also feeds node_peer_status for peers that are GATEWAYS. Each
		// upsert's own EXISTS guard routes the peer — a device pubkey no-ops here, a gateway pubkey no-ops in
		// device_status — so neither table crosses. No new agent field: the CP finally stores the gateway-peer
		// telemetry the agent already sends (REPORTED != STORED, fixed).
		peerParams = append(peerParams, sqlc.UpsertNodePeerStatusParams{
			NodeID: node.ID, PublicKey: st.PublicKey, LastHandshakeAt: hs,
			RxBytes: st.RxBytes, TxBytes: st.TxBytes,
		})
	}
	// br.Exec closes the batch results itself, so we do not Close separately.
	var firstErr error
	record := func(_ int, err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.q.UpsertDeviceStatus(ctx, params).Exec(record)
	s.q.UpsertNodePeerStatus(ctx, peerParams).Exec(record)
	return firstErr
}

// AppliedPolicy is the agent-reported Zero Trust policy IN FORCE on the gateway
// (S7.2 staleness): the version + canonical hash of the last successfully applied
// Compiled, and the last apply error if any. Stored in the capabilities JSONB;
// the control plane compares it against what it pushed — a gateway running stale
// policy must be VISIBLE (a policy violation in slow motion), never silent.
type AppliedPolicy struct {
	Version int    `json:"policy_version"`
	Hash    string `json:"policy_hash"`
	Error   string `json:"policy_error"`
	// FailingSince (RFC3339, empty when healthy) is the agent-reported mismatch
	// onset: when apply FIRST started failing. The stale alarm measures from here,
	// so a normal push that applies cleanly never registers stale (finding #3).
	FailingSince string `json:"policy_failing_since"`
	// RefusedVersion (S8.1 D1) is the compiled-artifact version the agent REFUSED as
	// unsupported (> its MaxSupportedVersion), or 0 when none. Surfaced as the distinct
	// `unsupported_policy_version` health kind (remedy: upgrade the agent).
	RefusedVersion int `json:"policy_refused_version"`
	// SiteLinkStale (S8.2 H5) is agent-computed: at least one of this gateway's SITE-LINK peers (the
	// hub, or a spoke) has a stale/absent WG handshake — site-to-site traffic on that link is dead.
	// Surfaced as site_link_down so a down bridge is never green-on-the-dashboard.
	SiteLinkStale bool `json:"site_link_stale"`
	// SiteSubnetUnreachable (S8.2c D3) is agent-computed: the gateway advertises a local site subnet no
	// host address is inside (bridge-trapped wg0 / misconfig). Surfaced as site_subnet_unreachable.
	SiteSubnetUnreachable bool `json:"site_subnet_unreachable"`
	// ConntrackFlushUnavailable (S8.7 Slice 2) is agent-reported: the expired-grant conntrack flush is
	// failing (no CAP_NET_ADMIN / netlink fault) — revoked grants' flows may linger. Surfaced as
	// conntrack_flush_unavailable.
	ConntrackFlushUnavailable bool `json:"conntrack_flush_unavailable"`
	// K8sEndpointsUnavailable (S10.3 WF-K5) — the agent has no successful K8s endpoint view (API unreachable
	// / RBAC-denied / watch not synced), so exposed Services can't be DNAT-programmed (fail-closed). Drives
	// the k8s_endpoints_unavailable health kind.
	K8sEndpointsUnavailable bool `json:"k8s_endpoints_unavailable"`
	// MaxSupportedVersion (S8.3 CW) is the highest artifact Version the agent can apply. Observability
	// (outside the hash); stored so the UI can warn which gateways would deny-all on a version bump.
	MaxSupportedVersion int `json:"max_policy_version"`
	// OVPNHealth (S9.1 4d) is the OpenVPN server's refuse-loudly kind ("" / ovpn_certs_absent /
	// ovpn_binary_absent) — a DIFFERENT axis from policy health, stored so the gateway surface shows WHY
	// an enabled gateway isn't serving.
	OVPNHealth string `json:"ovpn_health"`
	// DNSResolveRPCVersion is the highest selected-gateway DNS RPC wire version
	// this agent supports. It is persisted in the existing server-built
	// capabilities projection so known older gateways are refused before a DNS
	// request is queued, rather than being misclassified as a resolver timeout.
	DNSResolveRPCVersion int `json:"dns_resolve_rpc_version"`
}

// ReportWGInfo records the agent's locally-generated WireGuard public key and
// public endpoint. It validates the key is a well-formed 32-byte base64 value and
// the endpoint (if present) is a clean host:port — a malformed value would poison
// the .conf of every peer on this node. A zero-row update (e.g. the node was
// revoked mid-report) is an error, not a silent no-op.
func (s *Service) ReportWGInfo(ctx context.Context, node sqlc.Node, publicKey, endpoint string, egressNAT, egressIPv6 bool, applied AppliedPolicy) error {
	if !wgkey.Valid(publicKey) {
		return apierr.BadRequest("invalid_wg_key", "public_key must be a 32-byte base64 WireGuard key")
	}
	// A non-empty endpoint must be a clean host:port. This is the value that gets
	// concatenated verbatim into every peer's .conf, so an unvalidated endpoint
	// (newlines, extra directives) from a compromised agent could inject arbitrary
	// wg-quick config into other users' downloads. Empty is allowed (COALESCE in
	// the query keeps any prior value).
	if endpoint != "" && !validEndpoint(endpoint) {
		return apierr.BadRequest("invalid_endpoint", "endpoint must be a host:port with no whitespace")
	}
	// Bound the agent-supplied policy-status strings (they land in a JSONB column and
	// in dashboards) — a compromised agent must not stuff megabytes or control bytes.
	if len(applied.Hash) > 64 {
		applied.Hash = applied.Hash[:64]
	}
	if len(applied.Error) > 512 {
		applied.Error = applied.Error[:512]
	}
	// Bound the agent-supplied failing_since string too (it lands in JSONB).
	if len(applied.FailingSince) > 40 {
		applied.FailingSince = applied.FailingSince[:40]
	}
	// Gateway capabilities the agent probes + re-reports every reconcile (S3.7 +
	// S7.2 applied-policy status). The column is a forward-compat JSONB map; we build
	// it server-side from the typed report so a compromised agent can't inject
	// arbitrary JSON. egress_nat gates full-tunnel device creation (gateway_no_egress).
	caps, err := json.Marshal(map[string]any{
		"egress_nat":                  egressNAT,
		"egress_ipv6":                 egressIPv6,
		"policy_version":              applied.Version,
		"policy_hash":                 applied.Hash,
		"policy_error":                applied.Error,
		"policy_failing_since":        applied.FailingSince,
		"policy_refused_version":      applied.RefusedVersion,
		"site_link_stale":             applied.SiteLinkStale, // VESTIGIAL (WF-B D-WFB-1b): still reported+persisted for backward-compat, but NO LONGER CONSUMED — the CP derives site-link health from the ONE liveness derivation (fillSiteLinkVerdict). Retire or re-adopt deliberately in an agent-vN; do not silently resurrect.
		"site_subnet_unreachable":     applied.SiteSubnetUnreachable,
		"conntrack_flush_unavailable": applied.ConntrackFlushUnavailable,
		"k8s_endpoints_unavailable":   applied.K8sEndpointsUnavailable,
		"max_policy_version":          applied.MaxSupportedVersion,
		"ovpn_health":                 applied.OVPNHealth, // S9.1 4d
		"dns_resolve_rpc_version":     applied.DNSResolveRPCVersion,
	})
	if err != nil {
		return err
	}
	n, err := s.q.SetNodeWGInfo(ctx, sqlc.SetNodeWGInfoParams{ID: node.ID, WgPublicKey: publicKey, Endpoint: endpoint, Capabilities: caps})
	if err != nil {
		return err
	}
	if n == 0 {
		return apierr.Conflict("node_not_active", "node is no longer active; key not stored")
	}
	s.trackDesync(ctx, node, applied.Hash)
	return nil
}

// trackDesync is the SINGLE WRITER of nodes.policy_desync_since (S7.4b X-4 + single-writer
// amendment): on each FRESH report it stamps the term-3 desync onset (CP clock, X-2) or clears
// on reconvergence / non-enforcing. Called from exactly one site (ReportWGInfo). The OPEN build
// (s.policy == nil) is provably SILENT — no query runs, no error, no enterprise hash-compare
// import in the open binary. The value is ALWAYS the CP clock (time.Now) — an agent report can
// never supply it (AppliedPolicy has no desync field; the column is not in the agent-fed caps).
func (s *Service) trackDesync(ctx context.Context, node sqlc.Node, appliedHash string) {
	if s.policy == nil {
		return // open build — desync tracking is enterprise-only; silent, no write
	}
	// The pushed hash is finalized the SAME way the served artifact is (route-attach + version), so a
	// route-carrying enforcing gateway compares clean instead of a false silent_desync (the #1 fix). Only
	// a SITE gateway needs the topology (finalizeArtifact no-ops for non-site nodes) — skip the queries
	// otherwise. The topology loads BEFORE the compile so the derived active hub threads in (S8.6 REDUCE
	// #1 — the pushed baseline cites the same hub the served artifact does).
	var topo siteTopology
	var activeHub uuid.UUID
	if node.SiteID.Valid {
		t, terr := s.loadSiteTopology(ctx, node.OrgID)
		if terr != nil {
			return // topology unavailable → can't-determine; never stamp/clear on a partial baseline
		}
		topo = t
		if h := electSiteHub(topo, time.Now()); h != nil {
			activeHub = h.ID
		}
	}
	arts, err := s.policy.CompiledArtifactsForNodes(ctx, node.OrgID, []uuid.UUID{node.ID}, activeHub)
	if err != nil {
		return // pushed artifact unavailable (compile fault) → can't-determine; never stamp/clear
	}
	pushed := s.pushedHash(topo, node, arts[node.ID])
	if pushed == "" || pushed == appliedHash {
		// non-enforcing (off/mesh) OR reconverged — convergence is a STATE predicate, so a
		// revert-to-clear (target moved back to the applied hash) legitimately clears.
		// [fold 2] LOG a failed clear (don't swallow): a stale onset would render the NEXT
		// legit push as a false red silent_desync. Self-healing bound ≤ R — the next report
		// re-evaluates + retries this clear (the node stays reconverged).
		if err := s.q.ClearNodePolicyDesyncSince(ctx, sqlc.ClearNodePolicyDesyncSinceParams{ID: node.ID, OrgID: node.OrgID}); err != nil {
			slog.Warn("policy_desync_clear_failed", "node_id", node.ID, "error", err.Error())
		}
		return
	}
	// enforcing + mismatch → stamp the onset (idempotent: WHERE IS NULL preserves the first
	// onset PER EPISODE; a re-push after a clear re-stamps a NEW onset).
	// [fold 5] LOG a failed stamp: a NULL onset would render a genuinely stuck node as
	// converging forever. Self-healing bound ≤ R — the next report retries (still mismatched).
	if err := s.q.StampNodePolicyDesyncSince(ctx, sqlc.StampNodePolicyDesyncSinceParams{
		ID:                node.ID,
		OrgID:             node.OrgID,
		PolicyDesyncSince: pgtype.Timestamptz{Time: time.Now(), Valid: true},
	}); err != nil {
		slog.Warn("policy_desync_stamp_failed", "node_id", node.ID, "error", err.Error())
	}
}

// NodeCapabilities is the typed view of a node's capabilities JSONB, read where the
// control plane gates on a gateway's abilities (e.g. full-tunnel egress) or surfaces
// its applied-policy status (S7.2 staleness).
type NodeCapabilities struct {
	EgressNAT     bool   `json:"egress_nat"`
	EgressIPv6    bool   `json:"egress_ipv6"`
	PolicyVersion int    `json:"policy_version"`
	PolicyHash    string `json:"policy_hash"`
	PolicyError   string `json:"policy_error"`
	// PolicyFailingSince (RFC3339) is the agent-reported mismatch ONSET: when apply
	// first started failing (empty when healthy). The stale window measures from
	// here, not the applied-hash age -- so a normal push never false-alarms (#3).
	PolicyFailingSince string `json:"policy_failing_since"`
	// PolicyRefusedVersion (S8.1 D1) is the compiled-artifact version the agent REFUSED
	// as unsupported (0 = none). Drives the `unsupported_policy_version` health kind.
	PolicyRefusedVersion int `json:"policy_refused_version"`
	// SiteLinkStale (S8.2 H5) — agent-computed: a site-link peer has a stale/absent handshake.
	// Drives the `site_link_down` health kind (a dead bridge is never green).
	SiteLinkStale bool `json:"site_link_stale"`
	// SiteSubnetUnreachable (S8.2c D3) — agent-computed: advertises a local subnet no host addr is inside.
	// Drives the `site_subnet_unreachable` health kind (the reassuring-green bridge-mode trap).
	SiteSubnetUnreachable bool `json:"site_subnet_unreachable"`
	// ConntrackFlushUnavailable (S8.7 Slice 2) — agent-reported: the expired-grant conntrack flush is
	// failing. Drives the `conntrack_flush_unavailable` health kind (lowest priority).
	ConntrackFlushUnavailable bool `json:"conntrack_flush_unavailable"`
	// K8sEndpointsUnavailable (S10.3 WF-K5) — agent-reported: no successful K8s endpoint view (API
	// unreachable / RBAC-denied / watch not synced) → exposed-Service DNAT unprogrammed (fail-closed). Drives
	// the k8s_endpoints_unavailable health kind.
	K8sEndpointsUnavailable bool `json:"k8s_endpoints_unavailable"`
	// MaxPolicyVersion (S8.3 CW) — the agent's reported max-supported policy version. 0 = never reported
	// (a pre-CW/pre-upgrade agent): read as BELOW the ceiling, never unknown-treated-as-ready (S7.5.3
	// absence-is-not-compliance). Surfaced on the Node API for the cross-site upgrade warning.
	MaxPolicyVersion int `json:"max_policy_version"`
	// OVPNHealth (S9.1 4d) — the agent-reported OpenVPN refuse-loudly kind ("" / ovpn_certs_absent /
	// ovpn_binary_absent). Surfaced on the gateway so an operator sees WHY an OVPN-enabled gateway is
	// not serving.
	OVPNHealth string `json:"ovpn_health"`
	// DNSResolveRPCVersion is the highest authenticated selected-gateway DNS
	// RPC version the node reports. Zero is semantically an unsupported legacy
	// node, not an unknown/optimistic capability: FQDN enforcement must refuse
	// before queueing a resolver request when this is below the required wire
	// version.
	DNSResolveRPCVersion int `json:"dns_resolve_rpc_version"`
}

// SupportsDNSResolveRPC is deliberately a capability comparison rather than a
// truthiness check. Future protocol versions must not be accepted by a node
// that merely reports some older DNS RPC implementation.
func (c NodeCapabilities) SupportsDNSResolveRPC(required int) bool {
	return required > 0 && c.DNSResolveRPCVersion >= required
}

// zeroTrustOff mirrors organizations.zero_trust_mode = 'off' (the compiler's ModeOff).
// Kept as a neutral local const so the open build never imports enterprise/policy.
const zeroTrustOff = "off"

// PolicyDegradedForNodes computes ONE conservative Zero Trust health signal per node for
// the API — the COLLAPSED staleness surface (S7.2 design change; see docs/S7.2-decisions.md
// for the 3-signal→2-field→gap-states→3→1-disjunction history). All nodes must belong to
// orgID. A node is DEGRADED iff any of:
//
//	(1) caps.PolicyError != ""          — an apply is failing right now. This is ALSO the
//	                                      stuck-enforcing case: a gateway that failed to
//	                                      apply a mesh/off ruleset and is still enforcing a
//	                                      disabled policy sets applyErr (the "silent stale
//	                                      policy = violation in slow motion" case found live
//	                                      across passes 2–4).
//	(2) caps.PolicyFailingSince != ""   — an enforcing apply has been failing since its
//	                                      onset (any duration — conservative).
//	(3) enforcing AND pushed != applied — a silent desync: the policy IN FORCE differs from
//	                                      what the control plane would push now. "" pushed
//	                                      means non-enforcing (off/mesh), which has no
//	                                      boundary and never degrades. INSTANTANEOUS compare
//	                                      (no silent-desync onset is tracked server-side —
//	                                      that would be new state, against the reduce goal),
//	                                      so it may briefly over-report during a normal
//	                                      push's converge window; that is intentional per the
//	                                      OVER-report principle below.
//
// The field errs toward OVER-reporting (a false "degraded" is an annoyance; a false
// "healthy" is the silent-blackhole class we hit three times) — EXCEPT in the provider
// CAN'T-DETERMINE window: when the compile transiently errors (pushed nil), term (3) is
// skipped, so an enforcing gateway already desynced reads not-degraded for that window.
// This is bounded + safe: the gateway is guaranteed on its LAST-GOOD fail-closed policy
// (never open, never blackholing-from-this-cause), and it matches the couldn't-determine
// disposition (a transient control-plane fault is not a gateway fault). The rich agent
// signals (failingSince / hash / applyErr) still land in the capabilities JSONB unchanged;
// the DIFFERENTIATED surface (which-kind-of-degraded + badge UX) is S7.4, reading that JSONB.
//
// Open build / no policy provider: nothing degrades (no policy engine).
// PolicyHealth is the atomic per-node health: the authoritative bool + the advisory kind,
// derived from ONE snapshot (fold [0]) — a single pushed-hash compile + one caps read per node —
// so the two can NEVER read different snapshots (the cross-snapshot race that suppressed the
// badge on a genuinely-desynced gateway).
type PolicyHealth struct {
	Degraded bool
	Kind     PolicyDegradedKind
	// PushKnown/PushedHash/AppliedHash are the exact finalized comparison
	// already computed for health. F08 consumes these secret-free facts rather
	// than rebuilding a route-less hash in a parallel diagnostic path.
	PushKnown   bool
	PushedHash  string
	AppliedHash string
	// WF-B: the SUBORDINATE site-link note — INDEPENDENT of the headline Kind (D-WFB-2/D-WFB-3). Set when a
	// DEMOTED hub member's link is dead WHILE transit rides the active primary (healthy): the site's
	// headline stays its real state, and this names the demoted-dead peer as a distinct line item
	// ("aws-gw-1 (demoted)"). Empty peer = no note. NEVER set when the headline is site_link_down (a real
	// transit failure is not accompanied by a reassuring subordinate line — the inverse red's guard).
	SiteLinkNotePeer    string // the demoted-dead peer's display name ("" = no note)
	SiteLinkNoteDemoted bool   // always true when SiteLinkNotePeer set (carries the render's "(demoted)" qualifier)
}

// NodeDisplayExtras is per-node S8.3 display truth surfaced on the Node API: the hub designation (a
// PROJECTION of electSiteHub, never re-elected UI-side — D2) and the agent's reported max policy version.
type NodeDisplayExtras struct {
	IsSiteHub        bool
	MaxPolicyVersion int    // 0 = never reported (pre-CW agent) → the UI reads this as below-ceiling
	OVPNHealth       string // S9.1 4d: "" ok, or ovpn_certs_absent / ovpn_binary_absent
}

// SiteTopoBatch is the per-request site topology + elected hub, loaded ONCE for a node list and shared by
// the health + display passes so ListNodes does not load the topology (and elect the hub) TWICE (R5 batch
// discipline — review #3). Opaque: build it with LoadSiteTopoBatch and pass it to both methods.
type SiteTopoBatch struct {
	topo   siteTopology
	ok     bool      // false = a node is a site gateway but the topology LOAD failed (hub-health can't determine)
	hubID  uuid.UUID // the elected hub's node id (valid only when hasHub)
	hasHub bool      // electSiteHub(topo) != nil — the ONE election, computed once for the batch
	// WF-B (site-link health from THE ONE liveness derivation — deriveMemberLiveness): the ORG-LEVEL
	// site-link verdict, computed ONCE per batch and applied to every site gateway (transit health is
	// org-level — the hub set serves all sites). NEVER caps.SiteLinkStale (the retired agent bool, which
	// cannot name a peer or know demotion — D-WFB-1b).
	siteLinkHeadlineDown bool      // the ACTIVE PRIMARY hub is stale → org site transit is genuinely dead (the headline)
	demotedDeadPeer      uuid.UUID // a DEMOTED member is dead while the primary is fresh → subordinate named line (Nil = none)
	// memberLive (WF-C L2): per hub-set member, its FULL liveness verdict from THE ONE derivation
	// (deriveMemberLiveness — Observed/Fresh/Age). The zombie-hub kind reads .Observed/.Fresh (wire fresh)
	// AND .Age (the last-handshake age) for the WF-C-L2-1 settle. A non-member is absent (zero value).
	memberLive map[uuid.UUID]MemberLiveness
}

// LoadSiteTopoBatch loads the site topology once for a node list + elects the hub once (electSiteHub — the
// same picker the site-link graph uses). A zero batch (ok=true, no hub) when no node is a site gateway.
// Pass the result to PolicyHealthForNodes + NodeDisplayExtrasForNodes so neither reloads it.
func (s *Service) LoadSiteTopoBatch(ctx context.Context, orgID uuid.UUID, nodes []sqlc.Node) SiteTopoBatch {
	b := SiteTopoBatch{ok: true}
	anySite := false
	for _, n := range nodes {
		if n.SiteID.Valid {
			anySite = true
			break
		}
	}
	if anySite {
		now := time.Now()
		if t, err := s.loadSiteTopology(ctx, orgID); err == nil {
			b.topo = t
			if hub := electSiteHub(t, now); hub != nil {
				b.hubID, b.hasHub = hub.ID, true
			}
			s.fillSiteLinkVerdict(ctx, orgID, &b, now)
		} else {
			b.ok = false // load failed → can't determine hub-health (never a wrong designation)
		}
	}
	return b
}

// EvaluateAgentAccess evaluates one selected agent tuple against the exact
// FINALIZED artifact used by this gateway. It reuses the same topology batch,
// active-hub choice and finalizeArtifact seam as DesiredState/PolicyHealth, so
// diagnostics cannot invent a second hash or route model. It is read-only.
func (s *Service) EvaluateAgentAccess(ctx context.Context, orgID, deviceID uuid.UUID, node sqlc.Node, sourceIP, destination, protocol string, port int, pre ...SiteTopoBatch) (policyspec.AccessEvaluation, []string, error) {
	if s == nil || s.policy == nil || node.ID == uuid.Nil || node.OrgID != orgID {
		return policyspec.AccessEvaluation{}, nil, errors.New("agent policy unavailable")
	}
	b := s.siteTopoBatchFor(ctx, orgID, []sqlc.Node{node}, pre)
	if !b.ok {
		return policyspec.AccessEvaluation{}, nil, errors.New("agent policy topology unavailable")
	}
	artifacts, err := s.policy.CompiledArtifactsForNodes(ctx, orgID, []uuid.UUID{node.ID}, b.hubID)
	if err != nil {
		return policyspec.AccessEvaluation{}, nil, err
	}
	final := s.finalizeArtifact(b.topo, node, artifacts[node.ID])
	if final == nil {
		// Off-mode mesh is intentionally nil on the wire. For explanation it is
		// permitted-without-enforcement, not a missing grant.
		return policyspec.AccessEvaluation{Allowed: true, Mode: "off"}, nil, nil
	}
	routes := make([]string, 0, len(final.Routes))
	for _, route := range final.Routes {
		routes = append(routes, route.DstCIDR)
	}
	return policyspec.EvaluateAccess(final, deviceID, sourceIP, destination, protocol, port), routes, nil
}

// fillSiteLinkVerdict derives the ORG-LEVEL site-link health (WF-B) from THE ONE liveness derivation
// (deriveMemberLiveness — the same symbol the failover controller reads; no second freshness, the
// two-truths guard). PINNED org: members = the persisted hub set, active primary = deriveActive[0], a
// DEMOTED-yet-dead member becomes the subordinate note. UNPINNED-but-hubbed org: the sole member = the
// ELECTED hub (no failover, so no demotion → no subordinate note, just the headline). No hub → no verdict
// (the batch's zero value: headline false, no peer). A no-witness (unobserved) member yields NO verdict
// (never a headline-down on silence — the same HOLD the controller applies).
func (s *Service) fillSiteLinkVerdict(ctx context.Context, orgID uuid.UUID, b *SiteTopoBatch, now time.Time) {
	// A single directly attached site has no site-to-site transit peer. In that topology the
	// absence of a WireGuard site-link handshake is expected, not a degraded link. Keep the
	// site-link health signal reserved for actual multi-site transit.
	if !siteTopologyHasTransit(b.topo) {
		return
	}
	pubkey := make(map[uuid.UUID]string, len(b.topo.gws))
	for i := range b.topo.gws {
		pubkey[b.topo.gws[i].ID] = b.topo.gws[i].WgPublicKey
	}
	hs, herr := s.GetHubSet(ctx, orgID) // empty (Configured nil) on ErrNoRows — an unpinned org
	var members, demoted []uuid.UUID
	var activePrimary uuid.UUID
	if herr == nil && len(hs.Configured) > 0 {
		members, demoted = hs.Configured, hs.Demoted
		if active := deriveActive(hs.Configured, hs.Demoted); len(active) > 0 {
			activePrimary = active[0]
		}
	} else if b.hasHub {
		members, activePrimary = []uuid.UUID{b.hubID}, b.hubID // unpinned: the elected hub, no demotion
	} else {
		return // no hub → no site-link verdict
	}
	rows, err := s.q.ListNodePeerStatusForOrg(ctx, orgID)
	if err != nil {
		return // can't read the substrate → no verdict (never a false headline)
	}
	live := deriveMemberLiveness(members, pubkey, rows, demoted, now)
	b.siteLinkHeadlineDown, b.demotedDeadPeer = siteLinkVerdictFrom(members, activePrimary, live)
	// WF-C L2: surface the FULL per-member liveness from THE SAME map (no recompute) — the zombie-hub kind
	// reads wire freshness AND the handshake age (for the WF-C-L2-1 settle) from it.
	b.memberLive = live
}

// siteTopologyHasTransit reports whether the loaded topology contains at least two distinct
// sites. A one-site topology is a local/attached LAN (for example an AWS VPC on the gateway
// host), so there is no remote site-link peer whose handshake can be stale.
func siteTopologyHasTransit(topo siteTopology) bool {
	seen := make(map[uuid.UUID]struct{}, len(topo.gws))
	for _, gw := range topo.gws {
		if gw.SiteID.Valid {
			seen[uuid.UUID(gw.SiteID.Bytes)] = struct{}{}
		}
	}
	return len(seen) >= 2
}

// siteLinkVerdictFrom is the PURE WF-B verdict (unit-pinnable, no DB): given the hub members, the active
// primary, and THE ONE liveness map (deriveMemberLiveness), returns (headlineDown, demotedDeadPeer).
//   - HEADLINE: the active primary is observed-but-stale → org transit is genuinely dead. A real transit
//     failure is the headline and NO subordinate note competes with it (the inverse-red guard).
//   - SUBORDINATE: else, a DEMOTED member observed-but-stale while the primary is fresh — the walk's exact
//     case (transit rides the primary at 0% loss; the demoted-dead link is a named line, not the headline).
//   - A no-witness (unobserved) member yields neither — never a headline-down on silence.
func siteLinkVerdictFrom(members []uuid.UUID, activePrimary uuid.UUID, live map[uuid.UUID]MemberLiveness) (headlineDown bool, demotedDead uuid.UUID) {
	ap, apObserved := live[activePrimary]
	if apObserved && !ap.Fresh {
		return true, uuid.Nil // primary observed-STALE → org transit is genuinely dead → the headline
	}
	if !apObserved {
		// SILENCE on the primary yields NOTHING — no headline (silence ≠ death) AND no subordinate. A
		// subordinate note asserts "transit is fine, only this demoted link is down"; an UNOBSERVED primary
		// is precisely the state where we cannot assert transit is fine, so a reassuring subordinate here is
		// the reassuring-green class rebuilt one tier down — the combination the inverse-red didn't cover
		// (WF-B review F1). Silence yields nothing: no headline, no subordinate, no reassurance.
		return false, uuid.Nil
	}
	// primary observed-FRESH → transit is healthy; a DEMOTED member observed-stale is the subordinate note.
	for _, id := range members {
		if ml := live[id]; ml.Demoted && ml.Observed && !ml.Fresh {
			return false, id
		}
	}
	return false, uuid.Nil
}

// siteTopoBatchFor returns the caller-provided prefetched batch, or loads one — so a caller that passes no
// batch (every existing test) behaves EXACTLY as before (one load), while ListNodes passes a shared batch.
func (s *Service) siteTopoBatchFor(ctx context.Context, orgID uuid.UUID, nodes []sqlc.Node, pre []SiteTopoBatch) SiteTopoBatch {
	if len(pre) > 0 {
		return pre[0]
	}
	return s.LoadSiteTopoBatch(ctx, orgID, nodes)
}

// NodeDisplayExtrasForNodes returns the hub designation + reported max-version per node. The hub is a
// PROJECTION of the ONE election (electSiteHub, from the shared batch — not a second one). Max-version is
// read from each node's caps JSONB (absence → 0). All nodes must belong to orgID. Pass the shared batch to
// avoid reloading the topology (review #3).
func (s *Service) NodeDisplayExtrasForNodes(ctx context.Context, orgID uuid.UUID, nodes []sqlc.Node, pre ...SiteTopoBatch) map[uuid.UUID]NodeDisplayExtras {
	out := make(map[uuid.UUID]NodeDisplayExtras, len(nodes))
	b := s.siteTopoBatchFor(ctx, orgID, nodes, pre)
	for _, n := range nodes {
		var caps NodeCapabilities
		_ = json.Unmarshal(n.Capabilities, &caps) // absent/garbage caps → zero-value (MaxPolicyVersion 0)
		out[n.ID] = NodeDisplayExtras{IsSiteHub: b.hasHub && n.SiteID.Valid && n.ID == b.hubID, MaxPolicyVersion: caps.MaxPolicyVersion, OVPNHealth: caps.OVPNHealth}
	}
	return out
}

// PolicyHealthForNodes computes both the bool and the advisory kind from a SINGLE org compile.
// Atomicity unit = everything the render consumes, per node, from one snapshot: the pushed hash
// (one CompiledHashesForNodes), the caps, the CP-stamped onset, and the report-freshness — all
// from the same node row + the same pushed map. (Residual: the node rows are read by ListNodes
// slightly before this compile; a push in that gap makes pushed reflect the new policy while
// applied reflects the old — which is a REAL just-pushed desync and correctly renders
// `converging`, so it is harmless, not a suppressed alarm.)
func (s *Service) PolicyHealthForNodes(ctx context.Context, orgID uuid.UUID, nodes []sqlc.Node, pre ...SiteTopoBatch) map[uuid.UUID]PolicyHealth {
	out := make(map[uuid.UUID]PolicyHealth, len(nodes))
	enterprise := s.policy != nil
	// Site topology — loaded ONCE for the batch, in BOTH editions (site-link routing + its health are
	// CORE, D11). Only when some node is a site gateway. Drives site_hub_down (B2: no carrier) AND
	// finalizes the pushed hash (enterprise) the SAME way the served artifact is (#1: no false desync).
	// The batch is loaded here when unset (existing callers) or shared from ListNodes (review #3) — same
	// topo + hub, so the health output is byte-identical either way.
	b := s.siteTopoBatchFor(ctx, orgID, nodes, pre)
	topo := b.topo
	topoOK := b.ok
	hubExists := b.hasHub // R5: the ONE election (== siteTopoHasHub(topo)), computed once for the batch
	var pushed map[uuid.UUID]string
	pushKnown := false
	if enterprise && topoOK {
		ids := make([]uuid.UUID, len(nodes))
		for i, n := range nodes {
			ids[i] = n.ID
		}
		// err (transient compile/DB) -> pushKnown stays false: term (3) can't be evaluated, but the
		// agent-reported terms still apply. A transient control-plane hiccup is not a gateway fault.
		// S8.6 REDUCE #1: the batch's ONE elected hub (b.hubID, computed once via electSiteHub in the
		// SiteTopoBatch) is threaded in — the pushed-hash baseline cites the same hub the served artifact
		// does. uuid.Nil when the batch has no hub.
		if arts, err := s.policy.CompiledArtifactsForNodes(ctx, orgID, ids, b.hubID); err == nil {
			pushed = make(map[uuid.UUID]string, len(nodes))
			for _, n := range nodes {
				pushed[n.ID] = s.pushedHash(topo, n, arts[n.ID])
			}
			pushKnown = true
		}
	}
	now := time.Now()
	// WF-B: resolve the demoted-dead peer's display NAME once (from the node list — the peer is a hub
	// member, present in an org-wide ListNodes). Fallback to a short id if a subset call omits it.
	nameByID := make(map[uuid.UUID]string, len(nodes))
	for _, n := range nodes {
		nameByID[n.ID] = n.Name
	}
	subPeerName := ""
	if b.demotedDeadPeer != uuid.Nil {
		if nm := nameByID[b.demotedDeadPeer]; nm != "" {
			subPeerName = nm
		} else {
			subPeerName = b.demotedDeadPeer.String()[:8]
		}
	}
	for _, n := range nodes {
		caps := Capabilities(n.Capabilities)
		// Site-link health (S8.2, edition-independent — routing is core). site_hub_down (B2): this site
		// gateway has remote subnets to reach but the org has NO hub (no carrier) — CP-derived from the
		// topology. site_link_down (H5, WF-B): the ORG-LEVEL site-link HEADLINE — the ACTIVE PRIMARY hub is
		// stale (org transit dead), derived from THE ONE liveness derivation (SiteTopoBatch.fillSiteLink
		// Verdict), applied to every site gateway. NOT caps.SiteLinkStale: the agent bool is RETIRED from
		// consumption (D-WFB-1b) — it cannot name a peer or know demotion, so the CP derivation replaces it
		// as the one truth. The field stays reported in the caps payload (backward-compat), VESTIGIAL until
		// an agent-vN drops or re-adopts it deliberately (dormant-data guard: not silently resurrected).
		siteHubDown := topoOK && siteHubMissing(hubExists, topo, n)
		siteLinkDown := n.SiteID.Valid && b.siteLinkHeadlineDown
		// site_subnet_unreachable (S8.2c D3): the gateway advertises a local subnet it isn't on
		// (bridge-trapped wg0 / misconfig). A REACHABILITY fault the agent detects even when the link is
		// fresh — the reassuring-green trap. Edition-independent (routing is core, D11).
		siteSubnetUnreachable := caps.SiteSubnetUnreachable
		// conntrack_flush_unavailable (S8.7 Slice 2): the agent's expired-grant flush is failing — a
		// LOWEST-priority enforcement-hygiene degradation (revoked grants' flows may linger). Only fires in
		// enterprise (an open gateway has no grants → no flush → never set).
		conntrackFlushUnavailable := caps.ConntrackFlushUnavailable
		// k8s_endpoints_unavailable (S10.3 WF-K5): the agent has no successful K8s endpoint view (API
		// unreachable / RBAC-denied / watch not synced) → exposed-Service DNAT unprogrammed (fail-closed).
		// Edition-independent (the DNAT is open connectivity).
		k8sEndpointsUnavail := caps.K8sEndpointsUnavailable
		// hub_forwarding_not_reconciling (WF-C L2): the zombie hub — this member's wire is FRESH (spokes still
		// handshake it) while its own agent has been SILENT a full hub-stale window LONGER than that last
		// handshake. The SETTLE (WF-C-L2-1) is what makes it honest: on a CLEAN death the agent report AND the
		// wire handshake stop TOGETHER, so their ages track within a report cycle and (agentAge − wireAge)
		// never reaches the settle → no flicker to "still forwarding" before it settles to offline; a TRUE
		// zombie's wire keeps refreshing while last_seen freezes, so the gap grows past the settle → asserts +
		// persists. Stateless (two timestamps), no third clock — the settle IS the hub-stale liveness window,
		// the same principle the failover window applied to the primary badge. A non-member is absent (zero
		// value → !Observed → false), so this only fires for a hub-set member.
		ml := b.memberLive[n.ID]
		// F-Z1 (class): age-difference arithmetic on an AGENT-SUPPLIED timestamp clamps at zero — a skewed
		// agent clock could report a FUTURE handshake (negative Age), which would inflate the (agentAge −
		// wireAge) settle and spuriously fire. A skewed clock must never inflate a staleness computation.
		wireAge := ml.Age
		if wireAge < 0 {
			wireAge = 0
		}
		hubForwardingNotReconciling := ml.Observed && ml.Fresh && zombieAgentAge(now, n.LastSeenAt)-wireAge >= hubStaleWindow
		// A refused (unsupported-version) gateway is deny-all — definitively degraded,
		// edition-independent (S8.1 D1). Terms (1)+(2) are the agent-reported apply faults.
		deg := caps.PolicyError != "" || caps.PolicyFailingSince != "" || caps.PolicyRefusedVersion > 0 || siteHubDown || siteLinkDown || siteSubnetUnreachable || conntrackFlushUnavailable || hubForwardingNotReconciling
		if !deg && pushKnown {
			if h := pushed[n.ID]; h != "" && h != caps.PolicyHash { // term (3)
				deg = true
			}
		}
		// [fold 8] the open build has NO policy engine → no desync path. The kind must AGREE
		// with the bool structurally (not just architecturally): if caps somehow carry an apply
		// error, reflect it (apply_failing/stuck) so {Degraded,Kind} can't disagree; else healthy.
		// (Normally the open agent reports neither field — this is the structural guarantee.)
		// S11 WF-S11-6 — EDITION-INDEPENDENT and evaluated before everything else. An expired client cert
		// blocks the mTLS channel itself, which has nothing to do with the policy engine, so this is core and
		// not enterprise. NULL cert_not_after means "issued before we recorded expiry" = UNKNOWN, never
		// expired: a column added in 0054 must not retroactively declare every pre-existing gateway bricked.
		// ACTIVE nodes only (WF-S11-10). A revoked gateway's certificate expiring is not a fault — refusing its
		// renewal IS the revocation mechanism, so an expired cert on a revoked node is the system working as
		// designed. Reporting cert_expired_cannot_reconnect there would prescribe "re-enroll this gateway" for a
		// gateway an operator deliberately retired, contradicting the `revoked` state shown beside it. It also
		// keeps this per-node kind consistent with the fleet metric, whose query already filters revoked rows —
		// one truth, two renderings.
		certExpired := CertExpiredForNode(n.Status, n.CertNotAfter.Time, n.CertNotAfter.Valid, now)
		if certExpired {
			// The authoritative BOOL must agree with the kind (structural agreement — a gateway that cannot
			// connect is degraded by any definition). The bool stays the load-bearing signal.
			deg = true
		}

		kind := KindHealthy
		switch {
		case certExpired:
			// FIRST, both editions. Every case below reads the agent's LAST REPORT, which is stale by
			// construction once the certificate lapsed — so any other kind would describe a past state and
			// prescribe a remedy that cannot work. Only re-enrolment recovers this.
			kind = KindCertExpiredCannotReconnect
		case !enterprise && caps.PolicyRefusedVersion > 0:
			// S8.1 D1: the version gate is on the AGENT — edition-independent. An open-build
			// gateway has no policy engine (no desync path) but still refuses a too-new artifact.
			kind = KindUnsupportedPolicyVersion
		case !enterprise && siteHubDown:
			kind = KindSiteHubDown // edition-independent (routing/peers are core, D11)
		case !enterprise && siteLinkDown:
			kind = KindSiteLinkDown
		case !enterprise && siteSubnetUnreachable:
			kind = KindSiteSubnetUnreachable // D3, edition-independent
		case !enterprise && hubForwardingNotReconciling:
			// WF-C L2 (D-WFC2-1a): zombie hub — edition-independent (a crashed agent is core). Ranked above
			// the apply kinds (a dead agent's stale report must not mask it), below the site-reachability kinds.
			kind = KindHubForwardingNotReconciling
		case !enterprise && caps.PolicyFailingSince != "":
			kind = KindApplyFailing
		case !enterprise && caps.PolicyError != "":
			kind = KindStuckEnforcing
		case !enterprise && k8sEndpointsUnavail:
			// S10.3 — edition-independent (the VIP DNAT is OPEN connectivity). Ranked above the conntrack
			// hygiene label; below the apply/link faults so a louder failure is never masked.
			kind = KindK8sEndpointsUnavailable
		case !enterprise && conntrackFlushUnavailable:
			// [3] LOWEST priority — ranked AFTER the apply faults so a louder failure is never masked by the
			// hygiene label (structural agreement; open never sets it — no grants).
			kind = KindConntrackFlushUnavailable
		case enterprise:
			kind = degradedKind(KindInput{
				PolicyError:                 caps.PolicyError,
				PolicyFailingSince:          caps.PolicyFailingSince,
				PushKnown:                   pushKnown,
				PushedHash:                  pushed[n.ID],
				AppliedHash:                 caps.PolicyHash,
				DesyncSince:                 tsTime(n.PolicyDesyncSince),
				ReportAge:                   reportAge(now, n.PolicyReportedAt), // [fold 1] the REPORT clock, not last_seen
				Now:                         now,
				UnsupportedVersion:          caps.PolicyRefusedVersion > 0, // S8.1 D1: highest-priority kind
				SiteHubDown:                 siteHubDown,                   // S8.2 Item 7/9 (B2)
				SiteLinkDown:                siteLinkDown,                  // S8.2 H5
				SiteSubnetUnreachable:       siteSubnetUnreachable,         // S8.2c D3
				ConntrackFlushUnavailable:   conntrackFlushUnavailable,     // S8.7 Slice 2 (lowest priority)
				K8sEndpointsUnavailable:     k8sEndpointsUnavail,           // S10.3 WF-K5 (above conntrack, below apply/link)
				HubForwardingNotReconciling: hubForwardingNotReconciling,   // WF-C L2 D-WFC2-1a (zombie hub)
				CertExpired:                 certExpired,                   // S11 WF-S11-6 — ranked first inside degradedKind too
			})
		}
		ph := PolicyHealth{Degraded: deg, Kind: kind, PushKnown: pushKnown, AppliedHash: caps.PolicyHash}
		if pushKnown {
			ph.PushedHash = pushed[n.ID]
		}
		// WF-B subordinate note: a DEMOTED member is dead while transit rides the active primary. Attach the
		// named line to every OTHER site gateway (not the dead peer itself — it renders offline), and NEVER
		// when this node's own headline is site_link_down (the inverse-red guard: a real transit failure gets
		// no reassuring subordinate). INDEPENDENT of Kind — the headline stays its real state.
		if subPeerName != "" && n.SiteID.Valid && n.ID != b.demotedDeadPeer && !siteLinkDown {
			ph.SiteLinkNotePeer = subPeerName
			ph.SiteLinkNoteDemoted = true
		}
		out[n.ID] = ph
	}
	return out
}

// HandoffPolicyAcknowledgements adapts the existing single-source pushed-vs-
// applied policy health to the connector handoff scheduler. It deliberately
// does not compile a second artifact or trust the agent-reported hash as the
// expected value. A missing node, cross-site node, topology load failure, or
// unavailable policy compile is omitted and therefore remains unknown to the
// fail-closed health model.
func (s *Service) HandoffPolicyAcknowledgements(ctx context.Context, orgID, siteID uuid.UUID, nodeIDs []uuid.UUID) (map[uuid.UUID]k8s.PolicyAcknowledgement, error) {
	if s == nil || s.q == nil || orgID == uuid.Nil || siteID == uuid.Nil {
		return nil, errors.New("handoff policy acknowledgement scope is invalid")
	}
	wanted := make(map[uuid.UUID]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if id == uuid.Nil {
			return nil, errors.New("handoff policy acknowledgement node is invalid")
		}
		if _, duplicate := wanted[id]; duplicate {
			return nil, errors.New("handoff policy acknowledgement node is duplicated")
		}
		wanted[id] = struct{}{}
	}
	if len(wanted) == 0 {
		return map[uuid.UUID]k8s.PolicyAcknowledgement{}, nil
	}
	nodes, err := s.q.ListNodes(ctx, orgID)
	if err != nil {
		return nil, err
	}
	selected := make([]sqlc.Node, 0, len(wanted))
	for _, node := range nodes {
		if _, ok := wanted[node.ID]; !ok || node.OrgID != orgID || !node.SiteID.Valid || uuid.UUID(node.SiteID.Bytes) != siteID {
			continue
		}
		selected = append(selected, node)
	}
	if len(selected) == 0 {
		return map[uuid.UUID]k8s.PolicyAcknowledgement{}, nil
	}
	batch := s.LoadSiteTopoBatch(ctx, orgID, selected)
	health := s.PolicyHealthForNodes(ctx, orgID, selected, batch)
	return handoffPolicyAcknowledgementsFromHealth(siteID, wanted, selected, health), nil
}

func handoffPolicyAcknowledgementsFromHealth(siteID uuid.UUID, wanted map[uuid.UUID]struct{}, nodes []sqlc.Node, health map[uuid.UUID]PolicyHealth) map[uuid.UUID]k8s.PolicyAcknowledgement {
	out := make(map[uuid.UUID]k8s.PolicyAcknowledgement, len(wanted))
	for _, node := range nodes {
		if _, ok := wanted[node.ID]; !ok || !node.SiteID.Valid || uuid.UUID(node.SiteID.Bytes) != siteID {
			continue
		}
		value, ok := health[node.ID]
		if !ok {
			continue
		}
		out[node.ID] = k8s.PolicyAcknowledgement{
			ExpectedKnown: value.PushKnown,
			ExpectedHash:  value.PushedHash,
			HealthKnown:   value.PushKnown,
			Degraded:      value.Degraded,
		}
	}
	return out
}

// tsTime unwraps a nullable timestamp to a zero-or-value time.
func tsTime(ts pgtype.Timestamptz) time.Time {
	if !ts.Valid {
		return time.Time{}
	}
	return ts.Time
}

// zombieAgentAge is how long since the node last CHECKED IN (last_seen_at) — the AGENT-liveness clock for
// the WF-C L2 zombie settle (distinct from reportAge's policy_reported_at). Compared against the wire
// handshake age to distinguish a clean death (ages track → no flicker) from a true zombie (agent frozen
// while the wire keeps refreshing → the gap grows past the settle).
//
// NEVER-SEEN invariant (F-Z2/F-Z3): a never-seen node → a large sentinel (definitively stale). A never-seen
// agent is DEAD, and there is NO prior report to co-die with the wire, so there is no co-death flicker to
// guard against — the zombie kind fires immediately, and the never-seen red asserts it. The settle is a
// no-op for this case by construction (the sentinel dwarfs any wire age), which is correct.
func zombieAgentAge(now time.Time, lastSeen pgtype.Timestamptz) time.Duration {
	if !lastSeen.Valid {
		return 1<<62 - 1 // never seen → forever stale
	}
	return now.Sub(lastSeen.Time)
}

// reportAge is how long since the node last REPORTED its applied policy (policy_reported_at,
// [fold 1] — NOT last_seen_at, which polls also bump). NULL (never reported / pre-migration) →
// forever-stale → desync_unknown on the desync path, NEVER fresh.
func reportAge(now time.Time, reportedAt pgtype.Timestamptz) time.Duration {
	if !reportedAt.Valid {
		return 1<<62 - 1 // effectively "forever stale"
	}
	return now.Sub(reportedAt.Time)
}

// Capabilities decodes a node row's capabilities JSONB (an empty/invalid value → all
// false, the safe default: no capability claimed).
func Capabilities(raw []byte) NodeCapabilities {
	var c NodeCapabilities
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// K8sEndpointViewEvidence distinguishes an explicit false report from absent,
// null, wrongly typed, or malformed evidence. Unknown always fails closed for
// connector HA.
func K8sEndpointViewEvidence(raw []byte) (known, unavailable bool) {
	var fields map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &fields) != nil {
		return false, false
	}
	v, ok := fields["k8s_endpoints_unavailable"]
	if !ok {
		return false, false
	}
	var reported *bool
	if json.Unmarshal(v, &reported) != nil || reported == nil {
		return false, false
	}
	return true, *reported
}

// Revoke marks a node revoked (renewal will then be refused).
// ConnectorEvidenceFromNode copies only persisted node/report evidence into
// the pure HA adapter. A reported generation is provenance, never fencing.
func ConnectorEvidenceFromNode(node sqlc.Node, policyAck k8s.PolicyAcknowledgement) k8s.ConnectorEvidence {
	caps := Capabilities(node.Capabilities)
	endpointViewKnown, endpointViewUnavailable := K8sEndpointViewEvidence(node.Capabilities)
	siteID := ""
	if node.SiteID.Valid {
		siteID = uuid.UUID(node.SiteID.Bytes).String()
	}
	return k8s.ConnectorEvidence{
		ID: node.ID.String(), OrgID: node.OrgID.String(), SiteID: siteID,
		Status: node.Status, Revoked: node.RevokedAt.Valid,
		WGPublicKeyReady: wgkey.Valid(node.WgPublicKey),
		EndpointReady:    node.Endpoint != "" && validEndpoint(node.Endpoint),
		LastSeenAt:       tsTime(node.LastSeenAt), PolicyReportedAt: tsTime(node.PolicyReportedAt),
		AppliedPolicyHash: caps.PolicyHash, AppliedPolicyError: caps.PolicyError,
		AppliedPolicyRefusal:    caps.PolicyRefusedVersion,
		K8sEndpointViewKnown:    endpointViewKnown,
		K8sEndpointsUnavailable: endpointViewUnavailable,
		Policy:                  policyAck,
	}
}

func (s *Service) Revoke(ctx context.Context, actor, orgID, nodeID uuid.UUID) error {
	// Is this node a SITE GATEWAY? (Read before the revoke — RevokeNode leaves site_id set, so it reads the
	// same either way, but this is the pre-revoke truth.) S8.6 #9: only a gateway revoke reconciles the hub
	// set; a non-gateway device revoke must NOT churn a full reconcile.
	binding, bErr := s.q.GetNodeSiteBinding(ctx, sqlc.GetNodeSiteBindingParams{ID: nodeID, OrgID: orgID})
	wasGateway := bErr == nil && binding.Valid
	if err := s.withTx(ctx, func(q *sqlc.Queries) error {
		return s.revokeNodeInTx(ctx, q, actor, orgID, nodeID)
	}); err != nil {
		return err
	}
	s.afterNodeRevoke(ctx, orgID, wasGateway)
	return nil
}

func (s *Service) revokeNodeInTx(ctx context.Context, q *sqlc.Queries, actor, orgID, nodeID uuid.UUID) error {
	return s.revokeNodeInTxAttributed(ctx, q, actor, "", "", orgID, nodeID)
}

func (s *Service) revokeNodeInTxAttributed(ctx context.Context, q *sqlc.Queries, actorUserID uuid.UUID, actorSystem, cause string, orgID, nodeID uuid.UUID) error {
	// ⛔ REVOKE DOES NOT PROCEED WHILE DEVICES ARE STILL HOMED HERE (S12.12 D1).
	//
	// The cascade below is real and permanent: a revoked gateway is never active again, so an operator who
	// revokes with fifty devices homed here has disconnected fifty people with no un-revoke. The old design
	// answered that with a warning that COUNTED the devices; the ruling replaced it with a step that MOVES
	// them, and a refusal is what makes the step unskippable.
	//
	// ⭐ THE ORDER IS THE WHOLE POINT. Transfer-first means the abandoned state is "devices moved, old
	// gateway still running" — harmless and resumable. Cascade-then-restore's abandoned state is an outage
	// the product cannot undo, because the operator who closed the tab halfway has no way back.
	//
	// ⚠ INSIDE THE TRANSACTION, and it must stay here. RevokeNode already took this node's row lock, so an
	// enrolment racing to home a device onto this gateway either commits first (we count it and refuse) or
	// waits behind us. Asked before the transaction, the check could pass and the device arrive anyway —
	// which is a revoke that disconnects someone after proving it would not.
	live, cErr := q.CountLiveDevicesForNode(ctx, nodeID)
	if cErr != nil {
		return cErr
	}
	if live > 0 {
		return errDevicesStillHomed(live)
	}
	if e := q.RevokeNode(ctx, sqlc.RevokeNodeParams{OrgID: orgID, ID: nodeID}); e != nil {
		return e
	}
	// Cascade: the node's peers can no longer reach a gateway, so revoke them
	// too — no dangling active devices counting against caps or peer lists.
	if _, e := q.RevokeDevicesForNode(ctx, nodeID); e != nil {
		return e
	}
	// S9.1 Slice 5 (B2): the same sweep revokes those devices' OVPN client certs in-tx (the second
	// revocation path — the CRL rebuild after commit is the SHARED seam, D-S9.5-1 iii).
	if _, e := q.RevokeOVPNClientCertsForNode(ctx, nodeID); e != nil {
		return e
	}
	return auditAttributed(ctx, q, orgID, actorUserID, actorSystem, cause, "node.revoked", "node", nodeID.String(), map[string]any{})
}

func (s *Service) afterNodeRevoke(ctx context.Context, orgID uuid.UUID, wasGateway bool) {
	// S8.6 #4/#9: a revoked GATEWAY left the hub-set candidate pool (status='active' filter) → re-elect +
	// persist so the drop is durable + audited immediately. Best-effort belt: a hiccup self-heals on the next
	// failover tick (the configured corrector). Gated on gateway-ness — a laptop revoke is a no-op here.
	if wasGateway {
		if _, err := s.ReconcileHubSet(ctx, orgID); err != nil {
			slog.WarnContext(ctx, "hub_set_reconcile_failed", "op", "revoke", "org_id", orgID.String(), "error", err.Error())
		}
	}
	// S9.1 Slice 5: regenerate the org's CRL from the full revoked set (the SHARED seam), after commit. A
	// revoked gateway's OVPN clients must land on the CRL just as a device revoke's do. Best-effort (the
	// devices are revoked regardless); the scheduled rebuild backstops a failure.
	if s.rebuildCRL != nil {
		if err := s.rebuildCRL(ctx, orgID); err != nil {
			slog.WarnContext(ctx, "ovpn_crl_rebuild_failed_after_node_revoke", "org_id", orgID.String(), "error", err.Error())
		}
	}
}

// ListNodes returns an org's nodes.
func (s *Service) ListNodes(ctx context.Context, orgID uuid.UUID) ([]sqlc.Node, error) {
	return s.q.ListNodes(ctx, orgID)
}

// ListAgents returns the org's agents — the nodes an operator DECLARED as agents, plus the ones enrolled
// before the declaration existed (S15.3).
//
// ⚠ UNDETERMINED IS INCLUDED, WITH ITS KIND. Excluding it would assert a fact nobody has; including it
// silently would repeat the defect the marker fixed. The surface says which it is.
func (s *Service) ListAgents(ctx context.Context, orgID uuid.UUID) ([]sqlc.ListAgentsForOrgRow, error) {
	return s.q.ListAgentsForOrg(ctx, orgID)
}

// OwnerEmails maps node id -> the owner's email, resolved from `users` (S15.2; D22 applied to agents).
//
// ⚠ A NODE MISSING FROM THIS MAP IS UNATTRIBUTABLE, and that is the ONLY thing absence means here — the
// join is inner, so a node with no owner simply has no row. Callers must not read absence as "the lookup
// failed": a failed lookup returns an error, and the two are different states.
func (s *Service) OwnerEmails(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := s.q.ListNodeOwnerEmails(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]string, len(rows))
	for _, r := range rows {
		out[r.NodeID] = r.OwnerEmail
	}
	return out, nil
}

func newToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

func audit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor *uuid.UUID, action, targetType, targetID string, meta map[string]any) error {
	actorID := uuid.Nil
	if actor != nil {
		actorID = *actor
	}
	return auditAttributed(ctx, q, orgID, actorID, "", "", action, targetType, targetID, meta)
}

func auditLifecycle(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actor LifecycleActor, action, targetType, targetID string, meta map[string]any) error {
	return auditAttributed(ctx, q, orgID, actor.AuditUserID, actor.AuditSystem, actor.Cause, action, targetType, targetID, meta)
}

func auditAttributed(ctx context.Context, q *sqlc.Queries, orgID, actorUserID uuid.UUID, actorSystem, cause, action, targetType, targetID string, meta map[string]any) error {
	if meta == nil {
		meta = map[string]any{}
	}
	if cause != "" {
		meta["cause"] = cause
	}
	b, _ := json.Marshal(meta)
	if actorSystem != "" {
		_, err := q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{
			OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorSystem: &actorSystem,
			Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
		})
		return err
	}
	_, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID: pgtype.UUID{Bytes: orgID, Valid: true}, ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: actorUserID != uuid.Nil},
		Action: action, TargetType: &targetType, TargetID: &targetID, Metadata: b,
	})
	return err
}

// spkiText encodes an SPKI DER blob for storage. base64 rather than hex: it is the form every TLS tool prints and
// roughly a third shorter, and the column is read only by verification code that decodes it symmetrically.
// An empty blob stores NULL — honestly unknown, never an empty string masquerading as a key.
func spkiText(spki []byte) *string {
	if len(spki) == 0 {
		return nil
	}
	enc := base64.StdEncoding.EncodeToString(spki)
	return &enc
}

// allocateAgentDevice gives an owned agent its /32 — the address D15 makes binding.
//
// ⛔ THE SAME ALLOCATION DEFINITION AS A HUMAN'S DEVICE, DELIBERATELY. `ListActiveDeviceAllocations` is the
// query the resize orphan-check also uses, so "live allocation" has ONE definition. A second read with its
// own filter is how two views of the same pool drift, and a drifted pool hands out an address twice.
//
// ⚠ EXHAUSTION IS A HARD REFUSAL AND IT REFUSES THE ENROLMENT. 253 allocatable addresses on the default
// /24, org-wide, shared with every human's devices — a fleet collectively exhausts a pool that the per-user
// cap does not watch (D15's named cost). Failing the enrolment is correct: an agent that enrolled without
// an address would be silently unattributable, which is the state D25(C) reserves for agents that never had
// an owner, not for ones we could not allocate for.
func (s *Service) allocateAgentDevice(ctx context.Context, q *sqlc.Queries, orgID, ownerID, nodeID uuid.UUID, nodeName string) error {
	org, err := q.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return err
	}
	allocs, err := q.ListActiveDeviceAllocations(ctx, orgID)
	if err != nil {
		return err
	}
	used := make([]string, 0, len(allocs))
	for _, r := range allocs {
		if r.AssignedIp != nil {
			used = append(used, *r.AssignedIp)
		}
	}
	ip, err := ipalloc.Allocate(org.PoolCidr, used)
	if err != nil {
		if errors.Is(err, ipalloc.ErrPoolExhausted) {
			return apierr.Conflict("pool_exhausted", "no free tunnel address in the org pool for this agent")
		}
		return err
	}
	// ⚠ THE AGENT'S OWN PUBLIC KEY IS NOT KNOWN AT ENROLMENT — the agent generates its WireGuard key after
	// it has a certificate. The row is created with a placeholder keyed to the node so the UNIQUE index on
	// (node_id, public_key) cannot collide, and the reconcile replaces it. A placeholder that looked like a
	// real key would be worse: it would be indistinguishable from a peer that had never handshaked.
	_, err = q.CreateDevice(ctx, sqlc.CreateDeviceParams{
		OrgID: orgID, UserID: ownerID, NodeID: nodeID,
		Name: nodeName, Platform: "agent", PublicKey: "pending-agent-" + nodeID.String(),
		AssignedIp: &ip, Status: "active", Kind: "agent",
		// ⛔ EXPLICIT, AND THE SECOND INSTANCE OF THIS CLASS IN ONE SLICE. `devices` has several
		// CHECK-constrained text columns whose valid set does NOT include Go's zero value "" — `kind`,
		// `status`, `transport`. A new caller of CreateDevice that names some and not others compiles
		// cleanly and fails at INSERT time, which is exactly how this was found: on a FRESH database, not
		// on the local one, because the local failures were masked by an unrelated environmental class.
		// ⚠ An agent's own tunnel is WireGuard; it is never an OpenVPN client.
		Transport: "wireguard",
	})
	return err
}

// WithLicence wires the entitlement source. ⚠ Optional by construction: a Service without one behaves as
// Community, which is the fail-open default rather than a failure.
func (s *Service) WithLicence(m *licence.Manager) *Service {
	s.licence = m
	return s
}
