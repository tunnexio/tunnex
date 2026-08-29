package nodes

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestPoolVIPOwnershipDeliveryAckAcceptsMTLSBoundExactEcho(t *testing.T) {
	receiptTime := time.Date(2026, 8, 13, 13, 0, 0, 0, time.UTC)
	envelope, agent := ownershipDelivery()
	ack := ownershipAck(envelope)
	ack.AgentObservedAt = receiptTime.Add(90 * time.Hour) // diagnostic-only; intentionally implausible
	got, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ack, PoolVIPOwnershipAckState{})
	if err != nil || got.Duplicate || !got.ReceiptTime.Equal(receiptTime) || got.NextState.PromotionGeneration != envelope.PromotionGeneration || got.NextState.ManifestRevision != envelope.ManifestRevision || got.NextState.LeaseEpoch != envelope.LeaseEpoch {
		t.Fatalf("valid acknowledgement = %+v, %v", got, err)
	}
	if len(got.NextState.Seen) != 1 {
		t.Fatalf("accepted ack must record one replay key: %+v", got.NextState)
	}
	if got.NextState.ScopeIdentity == "" {
		t.Fatal("accepted acknowledgement must bind its replay state to delivery scope")
	}
}

func TestPoolVIPOwnershipDeliveryAckRejectsScopeAndBindingSwaps(t *testing.T) {
	envelope, agent := ownershipDelivery()
	for name, tc := range map[string]struct {
		mutateEnvelope func(*PoolVIPOwnershipDeliveryEnvelope)
		mutateAck      func(*PoolVIPOwnershipDeliveryAck)
	}{
		"cross org": {mutateEnvelope: func(e *PoolVIPOwnershipDeliveryEnvelope) { e.OrgID = "00000000-0000-4000-8000-000000000010" }},
		"pool":      {mutateAck: func(a *PoolVIPOwnershipDeliveryAck) { a.PoolID = "00000000-0000-4000-8000-000000000011" }},
		"operation": {mutateAck: func(a *PoolVIPOwnershipDeliveryAck) { a.OperationID = "00000000-0000-4000-8000-000000000012" }},
		"identity":  {mutateAck: func(a *PoolVIPOwnershipDeliveryAck) { a.ManifestIdentity = strings.Repeat("b", 64) }},
		"role":      {mutateAck: func(a *PoolVIPOwnershipDeliveryAck) { a.Role = policyspec.PoolVIPOwnershipWithdrawal }},
		"phase":     {mutateAck: func(a *PoolVIPOwnershipDeliveryAck) { a.DeliveryPhase = poolVIPOwnershipPhaseWithdraw }},
	} {
		t.Run(name, func(t *testing.T) {
			e := envelope
			a := ownershipAck(e)
			if tc.mutateEnvelope != nil {
				tc.mutateEnvelope(&e)
			}
			if tc.mutateAck != nil {
				tc.mutateAck(&a)
			}
			if got, err := ValidatePoolVIPOwnershipDeliveryAck(time.Now().UTC(), agent, e, a, PoolVIPOwnershipAckState{}); err == nil || got.ReceiptTime != (time.Time{}) {
				t.Fatalf("swapped %s acknowledgement = %+v, %v", name, got, err)
			}
		})
	}
}

func TestPoolVIPOwnershipDeliveryAckRejectsInvalidRolePhaseEnvelope(t *testing.T) {
	envelope, agent := ownershipDelivery()
	envelope.Role = policyspec.PoolVIPOwnershipPreparedNonServing
	// An agent echoing an invalid issued envelope must still be rejected; echo
	// equality is not authorization for an incoherent role/phase combination.
	if got, err := ValidatePoolVIPOwnershipDeliveryAck(time.Now().UTC(), agent, envelope, ownershipAck(envelope), PoolVIPOwnershipAckState{}); err == nil || got.Duplicate {
		t.Fatalf("prepared/serve envelope = %+v, %v", got, err)
	}
}

func TestPoolVIPOwnershipDeliveryAckRejectsStaleStateAndMakesDuplicatesIdempotent(t *testing.T) {
	receiptTime := time.Date(2026, 8, 13, 13, 0, 0, 0, time.UTC)
	envelope, agent := ownershipDelivery()
	ack := ownershipAck(envelope)
	first, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ack, PoolVIPOwnershipAckState{})
	if err != nil {
		t.Fatal(err)
	}
	successor := envelope
	successor.OperationID = "00000000-0000-4000-8000-000000000009"
	successor.ManifestIdentity = strings.Repeat("c", 64)
	successor.PromotionGeneration++
	successor.ManifestRevision++
	successor.LeaseEpoch++
	successor.DeliveryID = "00000000-0000-4000-8000-000000000010"
	successor.DeliveryNonce = strings.Repeat("d", 64)
	advanced, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime.Add(time.Minute), agent, successor, ownershipAck(successor), first.NextState)
	if err != nil || advanced.NextState.PromotionGeneration != successor.PromotionGeneration {
		t.Fatalf("higher-generation successor = %+v, %v", advanced, err)
	}
	ack.AgentObservedAt = receiptTime.Add(-365 * 24 * time.Hour) // must not perturb an idempotent retry
	duplicate, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime.Add(time.Hour), agent, envelope, ack, advanced.NextState)
	if err != nil || !duplicate.Duplicate || !duplicate.ReceiptTime.Equal(receiptTime) {
		t.Fatalf("duplicate acknowledgement = %+v, %v", duplicate, err)
	}
	if first.NextState.PromotionGeneration != envelope.PromotionGeneration || first.NextState.Seen[envelope.DeliveryID].ReceiptTime != receiptTime {
		t.Fatal("returned replay state aliases a later duplicate result")
	}
	if got, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ownershipAck(envelope), PoolVIPOwnershipAckState{ManifestRevision: envelope.ManifestRevision, LeaseEpoch: envelope.LeaseEpoch - 1}); err == nil || got.Duplicate {
		t.Fatalf("same revision under a new delivery must be stale: %+v, %v", got, err)
	}
	if got, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ownershipAck(envelope), PoolVIPOwnershipAckState{ManifestRevision: envelope.ManifestRevision - 1, LeaseEpoch: envelope.LeaseEpoch + 1}); err == nil || got.Duplicate {
		t.Fatalf("regressed lease epoch must be stale: %+v, %v", got, err)
	}
	regressedGeneration := envelope
	regressedGeneration.ManifestRevision++
	regressedGeneration.PromotionGeneration--
	regressedGeneration.DeliveryID = "00000000-0000-4000-8000-000000000011"
	regressedGeneration.DeliveryNonce = strings.Repeat("e", 64)
	if got, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, regressedGeneration, ownershipAck(regressedGeneration), first.NextState); err == nil || got.Duplicate {
		t.Fatalf("regressed promotion generation must be stale: %+v, %v", got, err)
	}
	crossPool := envelope
	crossPool.PoolID = "00000000-0000-4000-8000-000000000010"
	crossPool.ManifestRevision++
	if got, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, crossPool, ownershipAck(crossPool), first.NextState); err == nil || got.Duplicate {
		t.Fatalf("cross-pool state reuse = %+v, %v", got, err)
	}
}

func TestPoolVIPOwnershipDeliveryAckRejectsDeliveryIDNonceReplay(t *testing.T) {
	receiptTime := time.Date(2026, 8, 13, 13, 0, 0, 0, time.UTC)
	envelope, agent := ownershipDelivery()
	ack := ownershipAck(envelope)
	first, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ack, PoolVIPOwnershipAckState{})
	if err != nil {
		t.Fatal(err)
	}
	// The delivery ID is reused with a different nonce. It is a distinct valid
	// envelope shape, but must not be accepted through the prior replay record.
	envelope.DeliveryNonce = strings.Repeat("c", 64)
	ack = ownershipAck(envelope)
	if got, err := ValidatePoolVIPOwnershipDeliveryAck(receiptTime, agent, envelope, ack, first.NextState); err == nil || got.Duplicate {
		t.Fatalf("delivery-ID nonce replay = %+v, %v", got, err)
	}
}

func ownershipDelivery() (PoolVIPOwnershipDeliveryEnvelope, PoolVIPOwnershipAgentIdentity) {
	org := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	target := uuid.MustParse("00000000-0000-4000-8000-000000000006")
	return PoolVIPOwnershipDeliveryEnvelope{
		Version: 1, OrgID: org.String(), SiteID: "019f6400-0000-4000-8000-000000000002", ClusterID: "00000000-0000-4000-8000-000000000003",
		PoolID: "00000000-0000-4000-8000-000000000004", ConnectorNodeID: "00000000-0000-4000-8000-000000000005", TargetNodeID: target.String(),
		OperationID: "00000000-0000-4000-8000-000000000007", ManifestIdentity: strings.Repeat("a", 64), Role: policyspec.PoolVIPOwnershipServing,
		PromotionGeneration: 7, ManifestRevision: 11, LeaseEpoch: 13, DeliveryPhase: poolVIPOwnershipPhaseServe,
		DeliveryID: "00000000-0000-4000-8000-000000000008", DeliveryNonce: strings.Repeat("b", 64),
	}, PoolVIPOwnershipAgentIdentity{NodeID: target, OrgID: org}
}

func ownershipAck(e PoolVIPOwnershipDeliveryEnvelope) PoolVIPOwnershipDeliveryAck {
	return PoolVIPOwnershipDeliveryAck{
		Version: e.Version, OrgID: e.OrgID, SiteID: e.SiteID, ClusterID: e.ClusterID, PoolID: e.PoolID, ConnectorNodeID: e.ConnectorNodeID,
		TargetNodeID: e.TargetNodeID, OperationID: e.OperationID, ManifestIdentity: e.ManifestIdentity, Role: e.Role,
		PromotionGeneration: e.PromotionGeneration, ManifestRevision: e.ManifestRevision, LeaseEpoch: e.LeaseEpoch,
		DeliveryPhase: e.DeliveryPhase, DeliveryID: e.DeliveryID, DeliveryNonce: e.DeliveryNonce,
	}
}
