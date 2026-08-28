package k8s

import (
	"strings"
	"time"

	"github.com/google/uuid"
)

// OwnershipRole is the role an eventual P2 artifact asks one connector to
// assume for one exact pool/cluster. PreparedNonServing may observe the
// cluster, but it must not own a VIP, DNS address, WireGuard AllowedIP, or
// handoff route. This file is a pure prerequisite model: it neither creates a
// manifest nor changes an agent's data plane.
type OwnershipRole string

const (
	PreparedNonServing OwnershipRole = "prepared_non_serving"
	Serving            OwnershipRole = "serving"
)

// OwnershipScope prevents a connector-wide token from being reused for a
// second pool. All fields are required even though the current database also
// enforces tenant and cluster ownership: this model must fail closed before a
// future persistence or transport caller exists.
type OwnershipScope struct {
	OrgID       uuid.UUID
	SiteID      uuid.UUID
	PoolID      uuid.UUID
	ClusterID   uuid.UUID
	ConnectorID uuid.UUID
}

// CPOwnershipLease is an already-issued and validated CP lease. Issuance is a
// typed prerequisite because this pure package has neither signing keys nor
// persistence. Its epoch is pool-scoped; it is never connector-wide.
type CPOwnershipLease struct {
	Epoch     uint64
	ExpiresAt time.Time
	// CPIssuedValidated is CP-constructed provenance after the CP has
	// authenticated and matched untrusted wire data to its issued lease. An
	// agent must never be able to assert or serialize this boolean.
	CPIssuedValidated bool
}

// ArtifactPrerequisite carries opaque P2-owned artifact identity. The pure
// model compares identity exactly but deliberately does not generate, parse,
// or claim a digest algorithm for it. ManifestRevision orders ordinary
// same-generation service changes as well as promotion artifacts.
type ArtifactPrerequisite struct {
	Scope               OwnershipScope
	PromotionGeneration uint64
	ManifestRevision    uint64
	ManifestIdentity    string
	// ExpectedRouteDigest and ExpectedVIPMapDigest are opaque, CP-validated P2
	// v2 evidence. P1 compares them byte-for-byte but never receives routes or
	// VIPs and never implements P2's digest algorithm.
	ExpectedRouteDigest  string
	ExpectedVIPMapDigest string
	// IdentityValidated is CP-constructed provenance after the CP has
	// authenticated and matched untrusted wire data to the P2-owned manifest.
	// It is not an agent assertion or wire field.
	IdentityValidated bool
	Lease             CPOwnershipLease
	Role              OwnershipRole
}

// P2HandoffCanonicalEmptyRouteDigest is the fixed v2 P2-owned digest for an
// empty owned-route set. Prepared and withdrawal artifacts must carry this
// exact value and no VIP-map digest. It is a protocol constant, not a value
// P1 derives from route data.
const P2HandoffCanonicalEmptyRouteDigest = "5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d"

// ArtifactAcknowledgement is a future agent report after the CP has matched
// it to an expected artifact. ReceiptAt is recorded by the CP on arrival and
// is the only timestamp used for eligibility. AgentObservedAt is diagnostic
// data only: it is intentionally never read by this model.
type ArtifactAcknowledgement struct {
	Artifact  ArtifactPrerequisite
	ReceiptAt time.Time

	AgentObservedAt time.Time // diagnostic only; never trusted for eligibility

	// Prepared acknowledgements must assert both conditions. A future agent
	// needs to prove these against its actual DNAT/DNS/WireGuard/route state.
	NonServingAttested bool
	ServingAttested    bool

	// WithdrawalLeaseEpoch acknowledges withdrawal of this prior serving lease.
	// It is meaningful only for the old owner's prepared acknowledgement.
	WithdrawalLeaseEpoch uint64
}

type OwnershipDecisionTransition string

const (
	OwnershipRefused       OwnershipDecisionTransition = "refused"
	OwnershipPrepared      OwnershipDecisionTransition = "prepared"
	OwnershipEnableServing OwnershipDecisionTransition = "enable_serving"
)

// OwnershipDecision is decision-only. It must be consumed by a later
// scheduler/transport owner; this model never mutates state or treats a
// returned decision as distributed fencing.
type OwnershipDecision struct {
	Transition          OwnershipDecisionTransition
	Reason              string
	LeaseExpiryFallback bool
}

// PreparedOwnershipInput evaluates whether an exact future P2 preparation
// acknowledgement is usable. Previous is the CP-recorded last accepted
// artifact for this connector/pool, or nil for a deliberately initialized
// first artifact. A replay or same-revision conflict is refused.
type PreparedOwnershipInput struct {
	Now             time.Time
	MaxAckAge       time.Duration
	ClockSkewMargin time.Duration
	Expected        ArtifactPrerequisite
	Previous        *ArtifactPrerequisite
	Acknowledgement ArtifactAcknowledgement
}

// ServingOwnershipInput evaluates whether a prepared candidate may receive a
// serving artifact. OldServing is the current owner's CP-issued lease;
// OldWithdrawal is the exact prepared artifact expected from that owner. The
// candidate can enable only after a fresh withdrawal acknowledgement, or after
// the old lease has expired plus ClockSkewMargin.
type ServingOwnershipInput struct {
	Now             time.Time
	MaxAckAge       time.Duration
	ClockSkewMargin time.Duration
	NewPrepared     ArtifactPrerequisite
	NewServing      ArtifactPrerequisite
	PreparedAck     ArtifactAcknowledgement
	OldServing      ArtifactPrerequisite
	OldWithdrawal   ArtifactPrerequisite
	WithdrawalAck   *ArtifactAcknowledgement
}

// EvaluatePreparedOwnership accepts only a freshly CP-received, exact,
// non-serving acknowledgement whose opaque manifest revision strictly advances
// the CP-recorded prior artifact. It does not inspect agent clocks.
func EvaluatePreparedOwnership(in PreparedOwnershipInput) OwnershipDecision {
	if in.Now.IsZero() || in.MaxAckAge <= 0 || in.ClockSkewMargin <= 0 || !in.Expected.valid() || in.Expected.Role != PreparedNonServing ||
		!leaseUsable(in.Expected.Lease, in.Now, in.ClockSkewMargin) {
		return refuse("prepared artifact prerequisites are incomplete")
	}
	if in.Previous != nil {
		if !in.Previous.valid() || !sameScope(in.Expected.Scope, in.Previous.Scope) {
			return refuse("previous artifact scope is invalid")
		}
		if in.Expected.PromotionGeneration < in.Previous.PromotionGeneration || in.Expected.ManifestRevision <= in.Previous.ManifestRevision {
			return refuse("manifest generation or revision is stale, replayed, or conflicting")
		}
		// A same-generation service update may retain its pool lease epoch, but
		// cannot roll it back or quietly retime it. A new promotion generation
		// establishes a new fence and therefore needs a strictly newer epoch.
		if in.Expected.PromotionGeneration == in.Previous.PromotionGeneration {
			if in.Expected.Lease.Epoch < in.Previous.Lease.Epoch ||
				(in.Expected.Lease.Epoch == in.Previous.Lease.Epoch && !sameLease(in.Expected.Lease, in.Previous.Lease)) {
				return refuse("same-generation lease epoch regressed or conflicted")
			}
		} else if in.Expected.Lease.Epoch <= in.Previous.Lease.Epoch {
			return refuse("advanced promotion generation requires a newer lease epoch")
		}
	}
	if !matchesAcknowledgement(in.Acknowledgement, in.Expected, in.Now, in.MaxAckAge) {
		return refuse("prepared acknowledgement is missing, stale, or does not match the expected artifact")
	}
	if !in.Acknowledgement.NonServingAttested || in.Acknowledgement.ServingAttested {
		return refuse("prepared acknowledgement does not prove non-serving state")
	}
	return OwnershipDecision{Transition: OwnershipPrepared, Reason: "exact prepared acknowledgement is fresh and non-serving"}
}

// EvaluateServingOwnership requires a prepared candidate, a newer serving
// artifact, and either an exact old-owner withdrawal acknowledgement or a
// conservative CP-clock lease-expiry fallback. The same evaluator is used for
// promotion and failback; priority is outside this ownership fence.
func EvaluateServingOwnership(in ServingOwnershipInput) OwnershipDecision {
	if in.Now.IsZero() || in.MaxAckAge <= 0 || in.ClockSkewMargin <= 0 {
		return refuse("CP clock, acknowledgement age, and clock-skew margin are required")
	}
	if !in.NewPrepared.valid() || !in.NewServing.valid() || !in.OldServing.valid() || !in.OldWithdrawal.valid() {
		return refuse("artifact or lease prerequisites are incomplete")
	}
	if in.NewPrepared.Role != PreparedNonServing || in.NewServing.Role != Serving || in.OldServing.Role != Serving || in.OldWithdrawal.Role != PreparedNonServing {
		return refuse("artifact roles do not describe a prepare-withdraw-enable transition")
	}
	if !sameScope(in.NewPrepared.Scope, in.NewServing.Scope) || !samePoolCluster(in.NewPrepared.Scope, in.OldServing.Scope) ||
		!sameScope(in.OldServing.Scope, in.OldWithdrawal.Scope) || in.NewPrepared.Scope.ConnectorID == in.OldServing.Scope.ConnectorID {
		return refuse("pool, cluster, or connector scope is inconsistent")
	}
	if in.NewPrepared.PromotionGeneration != in.NewServing.PromotionGeneration || in.NewServing.PromotionGeneration != in.OldWithdrawal.PromotionGeneration ||
		in.NewServing.PromotionGeneration <= in.OldServing.PromotionGeneration {
		return refuse("promotion generation is stale or inconsistent")
	}
	if in.NewServing.ManifestRevision <= in.NewPrepared.ManifestRevision || in.OldWithdrawal.ManifestRevision <= in.OldServing.ManifestRevision ||
		in.NewServing.ManifestIdentity == in.NewPrepared.ManifestIdentity || in.OldWithdrawal.ManifestIdentity == in.OldServing.ManifestIdentity {
		return refuse("manifest revision or identity does not advance the ownership state")
	}
	if !sameLease(in.NewPrepared.Lease, in.NewServing.Lease) || !sameLease(in.NewServing.Lease, in.OldWithdrawal.Lease) ||
		in.NewServing.Lease.Epoch <= in.OldServing.Lease.Epoch || !leaseUsable(in.NewServing.Lease, in.Now, in.ClockSkewMargin) {
		return refuse("new CP-issued lease is stale, inconsistent, or too close to expiry")
	}
	if !matchesAcknowledgement(in.PreparedAck, in.NewPrepared, in.Now, in.MaxAckAge) ||
		!in.PreparedAck.NonServingAttested || in.PreparedAck.ServingAttested {
		return refuse("candidate is not freshly acknowledged as prepared and non-serving")
	}
	if in.WithdrawalAck != nil {
		ack := *in.WithdrawalAck
		if !matchesAcknowledgement(ack, in.OldWithdrawal, in.Now, in.MaxAckAge) || !ack.NonServingAttested || ack.ServingAttested ||
			ack.WithdrawalLeaseEpoch != in.OldServing.Lease.Epoch {
			return refuse("old-owner withdrawal acknowledgement is invalid")
		}
		return OwnershipDecision{Transition: OwnershipEnableServing, Reason: "old owner withdrew before enabling new owner"}
	}
	if leaseExpiredWithMargin(in.OldServing.Lease, in.Now, in.ClockSkewMargin) {
		return OwnershipDecision{Transition: OwnershipEnableServing, Reason: "old owner lease expired without withdrawal acknowledgement", LeaseExpiryFallback: true}
	}
	return refuse("old owner has neither withdrawn nor passed conservative lease expiry")
}

func (a ArtifactPrerequisite) valid() bool {
	return a.Scope.valid() && a.PromotionGeneration > 0 && a.ManifestRevision > 0 && strings.TrimSpace(a.ManifestIdentity) != "" &&
		a.IdentityValidated && a.Lease.valid() && validP2ArtifactEvidence(a.Role, a.ExpectedRouteDigest, a.ExpectedVIPMapDigest)
}

func validP2ArtifactEvidence(role OwnershipRole, routeDigest, vipMapDigest string) bool {
	switch role {
	case PreparedNonServing:
		return routeDigest == P2HandoffCanonicalEmptyRouteDigest && vipMapDigest == ""
	case Serving:
		return routeDigest != P2HandoffCanonicalEmptyRouteDigest && validP2Digest(routeDigest) && validP2Digest(vipMapDigest)
	default:
		return false
	}
}

func validP2Digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func (s OwnershipScope) valid() bool {
	return s.OrgID != uuid.Nil && s.SiteID != uuid.Nil && s.PoolID != uuid.Nil && s.ClusterID != uuid.Nil && s.ConnectorID != uuid.Nil
}

func (l CPOwnershipLease) valid() bool {
	return l.CPIssuedValidated && l.Epoch > 0 && !l.ExpiresAt.IsZero()
}

func matchesAcknowledgement(ack ArtifactAcknowledgement, expected ArtifactPrerequisite, now time.Time, maxAge time.Duration) bool {
	return nowReceiptFresh(now, ack.ReceiptAt, maxAge) && sameArtifact(ack.Artifact, expected)
}

// nowReceiptFresh intentionally considers only the CP-recorded receipt time.
// AgentObservedAt is neither read nor bounded: it cannot establish eligibility.
func nowReceiptFresh(now, receipt time.Time, maxAge time.Duration) bool {
	return !now.IsZero() && maxAge > 0 && !receipt.IsZero() && !receipt.After(now) && now.Sub(receipt) < maxAge
}

func leaseUsable(lease CPOwnershipLease, now time.Time, skew time.Duration) bool {
	return lease.valid() && skew > 0 && lease.ExpiresAt.After(now.Add(skew))
}

func leaseExpiredWithMargin(lease CPOwnershipLease, now time.Time, skew time.Duration) bool {
	return lease.valid() && skew > 0 && !lease.ExpiresAt.Add(skew).After(now)
}

func sameArtifact(a, b ArtifactPrerequisite) bool {
	return sameScope(a.Scope, b.Scope) && a.PromotionGeneration == b.PromotionGeneration && a.ManifestRevision == b.ManifestRevision &&
		a.ManifestIdentity == b.ManifestIdentity && a.ExpectedRouteDigest == b.ExpectedRouteDigest && a.ExpectedVIPMapDigest == b.ExpectedVIPMapDigest &&
		a.IdentityValidated == b.IdentityValidated && sameLease(a.Lease, b.Lease) && a.Role == b.Role
}

func sameScope(a, b OwnershipScope) bool {
	return a == b
}

func samePoolCluster(a, b OwnershipScope) bool {
	return a.OrgID == b.OrgID && a.SiteID == b.SiteID && a.PoolID == b.PoolID && a.ClusterID == b.ClusterID
}

func sameLease(a, b CPOwnershipLease) bool {
	return a.Epoch == b.Epoch && a.ExpiresAt.Equal(b.ExpiresAt) && a.CPIssuedValidated == b.CPIssuedValidated
}

func refuse(reason string) OwnershipDecision {
	return OwnershipDecision{Transition: OwnershipRefused, Reason: reason}
}
