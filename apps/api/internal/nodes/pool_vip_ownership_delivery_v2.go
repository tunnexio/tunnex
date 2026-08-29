package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// PoolVIPOwnershipDeliveryAttestationVersion is deliberately separate from
// receipt-only v1. A v1 receipt is never applied-state evidence.
const PoolVIPOwnershipDeliveryAttestationVersion = 2

const (
	// Keep v2 route evidence comfortably below the existing 16 KiB JSON frame:
	// a canonical IPv4 prefix is at most len("255.255.255.255/32") bytes, so
	// 512 entries plus JSON punctuation and fixed envelope fields remain bounded.
	// This is an internal protocol-safety ceiling, not a service exposure quota.
	poolVIPOwnershipMaxOwnedRoutes     = 512
	poolVIPOwnershipMaxOwnedRouteBytes = len("255.255.255.255/32")
)

// PoolVIPOwnershipDeliveryEnvelopeV2 is issued only to an authenticated agent
// that advertises exactly capability 2.
type PoolVIPOwnershipDeliveryEnvelopeV2 struct {
	PoolVIPOwnershipDeliveryEnvelope
	OwnedRoutes          []string `json:"owned_routes"`
	ExpectedRouteDigest  string   `json:"expected_route_digest"`
	ExpectedVIPMapDigest string   `json:"expected_vip_map_digest"`
	PriorLeaseEpoch      uint64   `json:"prior_lease_epoch,omitempty"`
}

// PoolVIPOwnershipDeliveryAckV2 echoes the v2 envelope and supplies exact
// applied-state read-back evidence. AgentObservedAt is diagnostic-only.
type PoolVIPOwnershipDeliveryAckV2 struct {
	PoolVIPOwnershipDeliveryAck
	AppliedRole                string `json:"applied_role"`
	AppliedManifestIdentity    string `json:"applied_manifest_identity"`
	AppliedPromotionGeneration uint64 `json:"applied_promotion_generation"`
	AppliedManifestRevision    uint64 `json:"applied_manifest_revision"`
	AppliedLeaseEpoch          uint64 `json:"applied_lease_epoch"`
	OwnedRouteDigest           string `json:"owned_route_digest"`
	VIPMapDigest               string `json:"vip_map_digest"`
}

// PoolVIPOwnershipAppliedAttestationScope names exactly one issued v2 artifact
// and durable P1 phase. It deliberately cannot enumerate receipts.
type PoolVIPOwnershipAppliedAttestationScope struct {
	OrgID, SiteID, ClusterID, PoolID                  string
	ConnectorNodeID, TargetNodeID, OperationID        string
	ManifestIdentity, Role, DeliveryPhase, DeliveryID string
	PromotionGeneration, ManifestRevision, LeaseEpoch uint64
}

// PoolVIPOwnershipAppliedAttestation is the only v2 evidence P1 may consume
// later. ReceiptTime is CP-recorded; this type makes no readiness decision.
type PoolVIPOwnershipAppliedAttestation struct {
	Envelope    PoolVIPOwnershipDeliveryEnvelopeV2
	Ack         PoolVIPOwnershipDeliveryAckV2
	ReceiptTime time.Time
	ExpiresAt   time.Time
}

// PoolVIPOwnershipAppliedAttestationReader is deliberately narrower than a
// delivery projection: it returns one exact v2 applied attestation or nothing.
type PoolVIPOwnershipAppliedAttestationReader interface {
	LoadPoolVIPOwnershipAppliedAttestation(ctx context.Context, scope PoolVIPOwnershipAppliedAttestationScope) (PoolVIPOwnershipAppliedAttestation, bool, error)
}

// PoolVIPOwnershipDeliveryAttestationStore is the capability-2 extension of
// the existing receipt-only store. Keeping it separate leaves the v1 interface
// and agent behavior byte-compatible during mixed-version rollout.
type PoolVIPOwnershipDeliveryAttestationStore interface {
	LoadIssuedPoolVIPOwnershipDeliveryV2(ctx context.Context, agent PoolVIPOwnershipAgentIdentity) (PoolVIPOwnershipDeliveryEnvelopeV2, bool, error)
	UpdatePoolVIPOwnershipAckV2(ctx context.Context, agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAckV2, receiptTime time.Time, validate func(PoolVIPOwnershipDeliveryEnvelopeV2, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error)) (PoolVIPOwnershipAckValidation, error)
}

// ValidatePoolVIPOwnershipDeliveryEnvelopeV2 validates the complete issued
// v2 artifact, including role-dependent non-serving/withdrawal intent.
func ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope PoolVIPOwnershipDeliveryEnvelopeV2) error {
	base := envelope.PoolVIPOwnershipDeliveryEnvelope
	if base.Version != PoolVIPOwnershipDeliveryAttestationVersion {
		return fmt.Errorf("unsupported ownership attestation version")
	}
	base.Version = PoolVIPOwnershipDeliveryVersion
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(base); err != nil {
		return err
	}
	digest, err := PoolVIPOwnershipOwnedRouteDigest(envelope.OwnedRoutes)
	if err != nil || digest != envelope.ExpectedRouteDigest {
		return fmt.Errorf("invalid expected owned-route digest")
	}
	switch envelope.Role {
	case policyspec.PoolVIPOwnershipServing:
		if len(envelope.OwnedRoutes) == 0 || !poolVIPOwnershipIdentityHexRE.MatchString(envelope.ExpectedVIPMapDigest) || envelope.PriorLeaseEpoch != 0 {
			return fmt.Errorf("serving attestation requires routes, VIP digest, and no prior lease")
		}
	case policyspec.PoolVIPOwnershipPreparedNonServing:
		if len(envelope.OwnedRoutes) != 0 || envelope.ExpectedVIPMapDigest != "" || envelope.PriorLeaseEpoch != 0 {
			return fmt.Errorf("prepared attestation requires zero owned routes")
		}
	case policyspec.PoolVIPOwnershipWithdrawal:
		if len(envelope.OwnedRoutes) != 0 || envelope.ExpectedVIPMapDigest != "" || envelope.PriorLeaseEpoch == 0 || envelope.PriorLeaseEpoch >= envelope.LeaseEpoch {
			return fmt.Errorf("withdrawal attestation requires prior lease and zero owned routes")
		}
	}
	return nil
}

// ValidatePoolVIPOwnershipDeliveryAckV2 checks authenticated principal, exact
// envelope echo, applied evidence, and the same durable monotonic replay fence
// used by v1. It does not treat AgentObservedAt as freshness evidence.
func ValidatePoolVIPOwnershipDeliveryAckV2(receiptTime time.Time, agent PoolVIPOwnershipAgentIdentity, envelope PoolVIPOwnershipDeliveryEnvelopeV2, ack PoolVIPOwnershipDeliveryAckV2, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
	if receiptTime.IsZero() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("control-plane receipt time required")
	}
	receiptTime = receiptTime.UTC()
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || envelope.TargetNodeID != agent.NodeID.String() || envelope.OrgID != agent.OrgID.String() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("authenticated agent does not own delivery scope")
	}
	if err := validPoolVIPOwnershipAckV2Echo(envelope, ack); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if err := validatePoolVIPOwnershipAppliedEvidence(envelope, ack); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	scopeIdentity, err := poolVIPOwnershipDeliveryScopeIdentityV2(envelope)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if state.ScopeIdentity != "" && state.ScopeIdentity != scopeIdentity {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("acknowledgement state belongs to another delivery scope")
	}
	fingerprint, err := poolVIPOwnershipAckV2Fingerprint(ack)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if prior, ok := state.Seen[ack.DeliveryID]; ok {
		if prior.Fingerprint != fingerprint {
			return PoolVIPOwnershipAckValidation{}, fmt.Errorf("delivery ID replayed with different acknowledgement")
		}
		return PoolVIPOwnershipAckValidation{Duplicate: true, ReceiptTime: prior.ReceiptTime, NextState: clonePoolVIPOwnershipAckState(state)}, nil
	}
	if envelope.ManifestRevision <= state.ManifestRevision || envelope.LeaseEpoch < state.LeaseEpoch || envelope.PromotionGeneration < state.PromotionGeneration {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("stale promotion generation, manifest revision, or lease epoch")
	}
	next := clonePoolVIPOwnershipAckState(state)
	if next.Seen == nil {
		next.Seen = make(map[string]PoolVIPOwnershipAckReceipt)
	}
	next.ScopeIdentity = scopeIdentity
	next.PromotionGeneration = envelope.PromotionGeneration
	next.ManifestRevision = envelope.ManifestRevision
	next.LeaseEpoch = envelope.LeaseEpoch
	next.Seen[envelope.DeliveryID] = PoolVIPOwnershipAckReceipt{Fingerprint: fingerprint, ReceiptTime: receiptTime}
	return PoolVIPOwnershipAckValidation{ReceiptTime: receiptTime, NextState: next}, nil
}

func validPoolVIPOwnershipAckV2Echo(envelope PoolVIPOwnershipDeliveryEnvelopeV2, ack PoolVIPOwnershipDeliveryAckV2) error {
	base := ack.PoolVIPOwnershipDeliveryAck
	if base.Version != envelope.Version || base.OrgID != envelope.OrgID || base.SiteID != envelope.SiteID || base.ClusterID != envelope.ClusterID || base.PoolID != envelope.PoolID || base.ConnectorNodeID != envelope.ConnectorNodeID || base.TargetNodeID != envelope.TargetNodeID || base.OperationID != envelope.OperationID || base.ManifestIdentity != envelope.ManifestIdentity || base.Role != envelope.Role || base.PromotionGeneration != envelope.PromotionGeneration || base.ManifestRevision != envelope.ManifestRevision || base.LeaseEpoch != envelope.LeaseEpoch || base.DeliveryPhase != envelope.DeliveryPhase || base.DeliveryID != envelope.DeliveryID || base.DeliveryNonce != envelope.DeliveryNonce {
		return fmt.Errorf("attestation acknowledgement does not exactly match delivery")
	}
	return nil
}

func validatePoolVIPOwnershipAppliedEvidence(envelope PoolVIPOwnershipDeliveryEnvelopeV2, ack PoolVIPOwnershipDeliveryAckV2) error {
	if ack.AppliedRole != envelope.Role || ack.AppliedManifestIdentity != envelope.ManifestIdentity || ack.AppliedPromotionGeneration != envelope.PromotionGeneration || ack.AppliedManifestRevision != envelope.ManifestRevision || ack.OwnedRouteDigest != envelope.ExpectedRouteDigest {
		return fmt.Errorf("applied ownership state does not exactly match delivery")
	}
	wantLease := envelope.LeaseEpoch
	if envelope.Role == policyspec.PoolVIPOwnershipWithdrawal {
		wantLease = envelope.PriorLeaseEpoch
	}
	if ack.AppliedLeaseEpoch != wantLease {
		return fmt.Errorf("applied ownership lease epoch does not match delivery")
	}
	if envelope.Role == policyspec.PoolVIPOwnershipServing {
		if ack.VIPMapDigest != envelope.ExpectedVIPMapDigest {
			return fmt.Errorf("applied ownership VIP digest does not match delivery")
		}
	} else if ack.VIPMapDigest != "" {
		return fmt.Errorf("non-serving ownership state must not attest a VIP digest")
	}
	return nil
}

// PoolVIPOwnershipOwnedRouteDigest returns the domain-separated digest over
// canonical, duplicate-free IPv4 prefixes. Input order cannot affect evidence.
func PoolVIPOwnershipOwnedRouteDigest(routes []string) (string, error) {
	if len(routes) > poolVIPOwnershipMaxOwnedRoutes {
		return "", fmt.Errorf("too many owned routes")
	}
	// The empty set has one canonical JSON representation. In particular, nil
	// and [] must not hash differently: P1 persists the protocol's canonical
	// empty-route digest for prepared/withdrawal artifacts, while callers may
	// naturally supply either Go form.
	canonical := append([]string{}, routes...)
	for _, route := range canonical {
		if len(route) > poolVIPOwnershipMaxOwnedRouteBytes {
			return "", fmt.Errorf("owned route exceeds canonical IPv4 length")
		}
		prefix, err := netip.ParsePrefix(route)
		if err != nil || !prefix.Addr().Is4() || prefix.String() != route {
			return "", fmt.Errorf("noncanonical owned route")
		}
	}
	sort.Strings(canonical)
	for i := 1; i < len(canonical); i++ {
		if canonical[i] == canonical[i-1] {
			return "", fmt.Errorf("duplicate owned route")
		}
	}
	b, _ := json.Marshal(struct {
		Domain string   `json:"domain"`
		Routes []string `json:"routes"`
	}{"tunnex.pool-vip-ownership-owned-routes/v1", canonical})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func poolVIPOwnershipDeliveryScopeIdentityV2(envelope PoolVIPOwnershipDeliveryEnvelopeV2) (string, error) {
	base := envelope.PoolVIPOwnershipDeliveryEnvelope
	base.Version = PoolVIPOwnershipDeliveryVersion
	return PoolVIPOwnershipDeliveryScopeIdentity(base)
}

func poolVIPOwnershipAckV2Fingerprint(ack PoolVIPOwnershipDeliveryAckV2) (string, error) {
	// AgentObservedAt is intentionally excluded: only CP ReceiptTime can later
	// establish freshness, and retries must retain its original value.
	v := ack
	v.AgentObservedAt = time.Time{}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
