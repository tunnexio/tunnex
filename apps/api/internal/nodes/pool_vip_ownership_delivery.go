package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// PoolVIPOwnershipDeliveryVersion versions only this future mTLS-channel
// envelope/ack contract. Nothing in this file is routed, sent, persisted, or
// applied yet.
const PoolVIPOwnershipDeliveryVersion = 1

const (
	poolVIPOwnershipPhasePrepare  = "prepare"
	poolVIPOwnershipPhaseServe    = "serve"
	poolVIPOwnershipPhaseWithdraw = "withdraw"
)

var (
	poolVIPOwnershipDeliveryUUIDRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	poolVIPOwnershipIdentityHexRE   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	poolVIPOwnershipDeliveryNonceRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// PoolVIPOwnershipDeliveryEnvelope is the future control-plane-issued envelope
// for one authenticated agent. Its scope fields are strings so a future decoder
// cannot normalize malformed wire values before this validator rejects them.
type PoolVIPOwnershipDeliveryEnvelope struct {
	Version             int    `json:"version"`
	OrgID               string `json:"org_id"`
	SiteID              string `json:"site_id"`
	ClusterID           string `json:"cluster_id"`
	PoolID              string `json:"pool_id"`
	ConnectorNodeID     string `json:"connector_node_id"`
	TargetNodeID        string `json:"target_node_id"`
	OperationID         string `json:"operation_id"`
	ManifestIdentity    string `json:"manifest_identity"`
	Role                string `json:"role"`
	PromotionGeneration uint64 `json:"promotion_generation"`
	ManifestRevision    uint64 `json:"manifest_revision"`
	LeaseEpoch          uint64 `json:"lease_epoch"`
	DeliveryPhase       string `json:"delivery_phase"`
	DeliveryID          string `json:"delivery_id"`
	DeliveryNonce       string `json:"delivery_nonce"`
}

// PoolVIPOwnershipDeliveryAck is the future agent echo. AgentObservedAt is
// diagnostic-only and never participates in freshness or eligibility; receipt
// time comes exclusively from the control plane caller of Validate…Ack.
type PoolVIPOwnershipDeliveryAck struct {
	Version             int       `json:"version"`
	OrgID               string    `json:"org_id"`
	SiteID              string    `json:"site_id"`
	ClusterID           string    `json:"cluster_id"`
	PoolID              string    `json:"pool_id"`
	ConnectorNodeID     string    `json:"connector_node_id"`
	TargetNodeID        string    `json:"target_node_id"`
	OperationID         string    `json:"operation_id"`
	ManifestIdentity    string    `json:"manifest_identity"`
	Role                string    `json:"role"`
	PromotionGeneration uint64    `json:"promotion_generation"`
	ManifestRevision    uint64    `json:"manifest_revision"`
	LeaseEpoch          uint64    `json:"lease_epoch"`
	DeliveryPhase       string    `json:"delivery_phase"`
	DeliveryID          string    `json:"delivery_id"`
	DeliveryNonce       string    `json:"delivery_nonce"`
	AgentObservedAt     time.Time `json:"agent_observed_at"`
}

// PoolVIPOwnershipAgentIdentity is built from the existing mTLS certificate
// seam (node/org), never from an acknowledgement body.
type PoolVIPOwnershipAgentIdentity struct {
	NodeID uuid.UUID
	OrgID  uuid.UUID
}

// PoolVIPOwnershipAckReceipt is the durable shape a later CP owner will need
// per delivery ID. This pure prerequisite neither writes nor retains it.
type PoolVIPOwnershipAckReceipt struct {
	Fingerprint string
	ReceiptTime time.Time
}

// PoolVIPOwnershipAckState is a caller-owned snapshot for one manifest scope.
// Seen is copied on every accepted result, so validation is pure and callers can
// persist/reconcile it later without aliasing this input.
type PoolVIPOwnershipAckState struct {
	PromotionGeneration uint64
	ScopeIdentity       string
	ManifestRevision    uint64
	LeaseEpoch          uint64
	Seen                map[string]PoolVIPOwnershipAckReceipt
}

// PoolVIPOwnershipAckValidation is the pure output for a later authenticated
// handler. Duplicate means the exact same delivery ACK was already received;
// ReceiptTime then remains the original CP receipt timestamp.
type PoolVIPOwnershipAckValidation struct {
	Duplicate   bool
	ReceiptTime time.Time
	NextState   PoolVIPOwnershipAckState
}

// PoolVIPOwnershipDeliveryStore is the durable owner of issued envelopes and
// acknowledgement replay state. It remains an interface so the HTTP channel
// does not own database mechanics or provide an in-memory fallback.
// UpdateAck must atomically load the exact issued envelope and scope-bound
// replay state, run validate, and persist validate's accepted NextState and
// original receipt time before returning.
type PoolVIPOwnershipDeliveryStore interface {
	LoadIssuedPoolVIPOwnershipDelivery(ctx context.Context, agent PoolVIPOwnershipAgentIdentity) (PoolVIPOwnershipDeliveryEnvelope, bool, error)
	UpdatePoolVIPOwnershipAck(ctx context.Context, agent PoolVIPOwnershipAgentIdentity, ack PoolVIPOwnershipDeliveryAck, receiptTime time.Time, validate func(PoolVIPOwnershipDeliveryEnvelope, PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error)) (PoolVIPOwnershipAckValidation, error)
}

// PoolVIPOwnershipDeliveryReadScope permits an internal owner to inspect one
// exact issued delivery without granting a broad pool or organization scan.
// All fields are canonical wire values; callers must not use a receipt as an
// applied/serving signal.
type PoolVIPOwnershipDeliveryReadScope struct {
	OrgID            string
	SiteID           string
	PoolID           string
	OperationID      string
	ManifestIdentity string
	DeliveryID       string
}

// PoolVIPOwnershipDeliveryReceiptProjection records only that the authenticated
// agent channel accepted an exact acknowledgement. It deliberately has no
// readiness or applied-state meaning: leader-session binding and applied-state
// attestation remain future prerequisites.
type PoolVIPOwnershipDeliveryReceiptProjection struct {
	ReceiptTime time.Time
}

// PoolVIPOwnershipDeliveryProjection is an internal, exact delivery/receipt
// read model. Receipt is nil until the delivery has been acknowledged.
type PoolVIPOwnershipDeliveryProjection struct {
	Envelope  PoolVIPOwnershipDeliveryEnvelope
	ExpiresAt time.Time
	Receipt   *PoolVIPOwnershipDeliveryReceiptProjection
}

// PoolVIPOwnershipDeliveryProjectionReader is separate from the mTLS polling
// store contract. It is for a future operation owner, not an agent endpoint.
type PoolVIPOwnershipDeliveryProjectionReader interface {
	LoadPoolVIPOwnershipDeliveryProjection(ctx context.Context, scope PoolVIPOwnershipDeliveryReadScope) (PoolVIPOwnershipDeliveryProjection, bool, error)
}

// ValidatePoolVIPOwnershipDeliveryEnvelope verifies one canonical v1 envelope
// before the control plane emits it. It is separate from acknowledgement
// validation so the transport never sends a malformed issued artifact.
func ValidatePoolVIPOwnershipDeliveryEnvelope(envelope PoolVIPOwnershipDeliveryEnvelope) error {
	return validPoolVIPOwnershipDeliveryEnvelope(envelope)
}

// PoolVIPOwnershipDeliveryScopeIdentity returns the canonical fence key for a
// valid issued envelope. Durable stores use it to preserve monotonic state
// across expired delivery cleanup and process restarts.
func PoolVIPOwnershipDeliveryScopeIdentity(envelope PoolVIPOwnershipDeliveryEnvelope) (string, error) {
	if err := validPoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return "", err
	}
	return poolVIPOwnershipDeliveryScopeIdentity(envelope)
}

// ValidatePoolVIPOwnershipDeliveryAck validates an echo against a CP-issued
// envelope and the existing mTLS identity. receiptTime must be recorded by the
// control plane; AgentObservedAt is intentionally ignored for freshness. The
// returned state is a pure replay/idempotency reduction, not persistence.
func ValidatePoolVIPOwnershipDeliveryAck(receiptTime time.Time, agent PoolVIPOwnershipAgentIdentity, envelope PoolVIPOwnershipDeliveryEnvelope, ack PoolVIPOwnershipDeliveryAck, state PoolVIPOwnershipAckState) (PoolVIPOwnershipAckValidation, error) {
	if receiptTime.IsZero() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("control-plane receipt time required")
	}
	receiptTime = receiptTime.UTC()
	if err := validPoolVIPOwnershipDeliveryEnvelope(envelope); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if agent.NodeID == uuid.Nil || agent.OrgID == uuid.Nil || envelope.TargetNodeID != agent.NodeID.String() || envelope.OrgID != agent.OrgID.String() {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("authenticated agent does not own delivery scope")
	}
	if err := validPoolVIPOwnershipAckEcho(envelope, ack); err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	scopeIdentity, err := poolVIPOwnershipDeliveryScopeIdentity(envelope)
	if err != nil {
		return PoolVIPOwnershipAckValidation{}, err
	}
	if state.ScopeIdentity != "" && state.ScopeIdentity != scopeIdentity {
		return PoolVIPOwnershipAckValidation{}, fmt.Errorf("acknowledgement state belongs to another delivery scope")
	}
	fingerprint, err := poolVIPOwnershipAckFingerprint(ack)
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

func validPoolVIPOwnershipDeliveryEnvelope(envelope PoolVIPOwnershipDeliveryEnvelope) error {
	if envelope.Version != PoolVIPOwnershipDeliveryVersion {
		return fmt.Errorf("unsupported delivery version")
	}
	for field, value := range map[string]string{
		"org_id": envelope.OrgID, "site_id": envelope.SiteID, "cluster_id": envelope.ClusterID, "pool_id": envelope.PoolID,
		"connector_node_id": envelope.ConnectorNodeID, "target_node_id": envelope.TargetNodeID, "operation_id": envelope.OperationID, "delivery_id": envelope.DeliveryID,
	} {
		if !validPoolVIPOwnershipDeliveryUUID(value) {
			return fmt.Errorf("invalid %s", field)
		}
	}
	if !poolVIPOwnershipIdentityHexRE.MatchString(envelope.ManifestIdentity) || !poolVIPOwnershipDeliveryNonceRE.MatchString(envelope.DeliveryNonce) {
		return fmt.Errorf("invalid manifest identity or delivery nonce")
	}
	if envelope.PromotionGeneration == 0 || envelope.ManifestRevision == 0 || envelope.LeaseEpoch == 0 {
		return fmt.Errorf("promotion generation, manifest revision, and lease epoch must be positive")
	}
	return validPoolVIPOwnershipDeliveryRolePhase(envelope.Role, envelope.DeliveryPhase)
}

func validPoolVIPOwnershipAckEcho(envelope PoolVIPOwnershipDeliveryEnvelope, ack PoolVIPOwnershipDeliveryAck) error {
	if ack.Version != envelope.Version || ack.OrgID != envelope.OrgID || ack.SiteID != envelope.SiteID || ack.ClusterID != envelope.ClusterID ||
		ack.PoolID != envelope.PoolID || ack.ConnectorNodeID != envelope.ConnectorNodeID || ack.TargetNodeID != envelope.TargetNodeID ||
		ack.OperationID != envelope.OperationID || ack.ManifestIdentity != envelope.ManifestIdentity || ack.Role != envelope.Role ||
		ack.PromotionGeneration != envelope.PromotionGeneration || ack.ManifestRevision != envelope.ManifestRevision || ack.LeaseEpoch != envelope.LeaseEpoch ||
		ack.DeliveryPhase != envelope.DeliveryPhase || ack.DeliveryID != envelope.DeliveryID || ack.DeliveryNonce != envelope.DeliveryNonce {
		return fmt.Errorf("acknowledgement does not exactly match delivery")
	}
	return validPoolVIPOwnershipDeliveryEnvelope(PoolVIPOwnershipDeliveryEnvelope{
		Version: ack.Version, OrgID: ack.OrgID, SiteID: ack.SiteID, ClusterID: ack.ClusterID, PoolID: ack.PoolID,
		ConnectorNodeID: ack.ConnectorNodeID, TargetNodeID: ack.TargetNodeID, OperationID: ack.OperationID,
		ManifestIdentity: ack.ManifestIdentity, Role: ack.Role, PromotionGeneration: ack.PromotionGeneration,
		ManifestRevision: ack.ManifestRevision, LeaseEpoch: ack.LeaseEpoch, DeliveryPhase: ack.DeliveryPhase,
		DeliveryID: ack.DeliveryID, DeliveryNonce: ack.DeliveryNonce,
	})
}

func validPoolVIPOwnershipDeliveryRolePhase(role, phase string) error {
	switch role {
	case policyspec.PoolVIPOwnershipPreparedNonServing:
		if phase != poolVIPOwnershipPhasePrepare {
			return fmt.Errorf("prepared role requires prepare phase")
		}
	case policyspec.PoolVIPOwnershipServing:
		if phase != poolVIPOwnershipPhaseServe {
			return fmt.Errorf("serving role requires serve phase")
		}
	case policyspec.PoolVIPOwnershipWithdrawal:
		if phase != poolVIPOwnershipPhaseWithdraw {
			return fmt.Errorf("withdrawal role requires withdraw phase")
		}
	default:
		return fmt.Errorf("invalid delivery role")
	}
	return nil
}

func poolVIPOwnershipAckFingerprint(ack PoolVIPOwnershipDeliveryAck) (string, error) {
	// Deliberately omit AgentObservedAt: it is diagnostic-only and must never
	// split an idempotent retry or influence the CP receipt/freshness record.
	v := struct {
		Version             int    `json:"version"`
		OrgID               string `json:"org_id"`
		SiteID              string `json:"site_id"`
		ClusterID           string `json:"cluster_id"`
		PoolID              string `json:"pool_id"`
		ConnectorNodeID     string `json:"connector_node_id"`
		TargetNodeID        string `json:"target_node_id"`
		OperationID         string `json:"operation_id"`
		ManifestIdentity    string `json:"manifest_identity"`
		Role                string `json:"role"`
		PromotionGeneration uint64 `json:"promotion_generation"`
		ManifestRevision    uint64 `json:"manifest_revision"`
		LeaseEpoch          uint64 `json:"lease_epoch"`
		DeliveryPhase       string `json:"delivery_phase"`
		DeliveryID          string `json:"delivery_id"`
		DeliveryNonce       string `json:"delivery_nonce"`
	}{ack.Version, ack.OrgID, ack.SiteID, ack.ClusterID, ack.PoolID, ack.ConnectorNodeID, ack.TargetNodeID, ack.OperationID, ack.ManifestIdentity, ack.Role, ack.PromotionGeneration, ack.ManifestRevision, ack.LeaseEpoch, ack.DeliveryPhase, ack.DeliveryID, ack.DeliveryNonce}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func poolVIPOwnershipDeliveryScopeIdentity(envelope PoolVIPOwnershipDeliveryEnvelope) (string, error) {
	v := struct {
		Domain          string `json:"domain"`
		OrgID           string `json:"org_id"`
		SiteID          string `json:"site_id"`
		ClusterID       string `json:"cluster_id"`
		PoolID          string `json:"pool_id"`
		ConnectorNodeID string `json:"connector_node_id"`
	}{"tunnex.pool-vip-ownership-delivery-scope/v1", envelope.OrgID, envelope.SiteID, envelope.ClusterID, envelope.PoolID, envelope.ConnectorNodeID}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func clonePoolVIPOwnershipAckState(in PoolVIPOwnershipAckState) PoolVIPOwnershipAckState {
	out := PoolVIPOwnershipAckState{PromotionGeneration: in.PromotionGeneration, ScopeIdentity: in.ScopeIdentity, ManifestRevision: in.ManifestRevision, LeaseEpoch: in.LeaseEpoch}
	if len(in.Seen) != 0 {
		out.Seen = make(map[string]PoolVIPOwnershipAckReceipt, len(in.Seen))
		for id, receipt := range in.Seen {
			out.Seen[id] = receipt
		}
	}
	return out
}

func validPoolVIPOwnershipDeliveryUUID(value string) bool {
	return poolVIPOwnershipDeliveryUUIDRE.MatchString(value) && value != "00000000-0000-0000-0000-000000000000"
}
