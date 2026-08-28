package nodes

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestDecodePoolVIPOwnershipFreshHandoffEnvelopeRequiresV3Authority(t *testing.T) {
	want, _ := ownershipDeliveryV3(t)
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := decodePoolVIPOwnershipFreshHandoffEnvelope(raw)
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded fresh envelope ok=%t got=%+v want=%+v", ok, got, want)
	}
	v2, _ := ownershipDeliveryV2(policyspec.PoolVIPOwnershipServing)
	v2Raw, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := decodePoolVIPOwnershipFreshHandoffEnvelope(v2Raw); ok || got.Version != 0 {
		t.Fatalf("v2 envelope must not become fresh handoff authority: ok=%t got=%+v", ok, got)
	}
	if got, ok := decodeLegacyPoolVIPOwnershipFreshHandoffEnvelopeV2(v2Raw); !ok || !reflect.DeepEqual(got, v2) {
		t.Fatalf("legacy v2 compatibility decode ok=%t got=%+v want=%+v", ok, got, v2)
	}
	if got, ok := decodePoolVIPOwnershipFreshHandoffEnvelope([]byte(`{"version":3}`)); ok || got.Version != 0 {
		t.Fatalf("malformed envelope must remain a zero refused value: ok=%t got=%+v", ok, got)
	}
}

func TestPoolVIPOwnershipDeliveryV2RequiresExactAppliedEvidence(t *testing.T) {
	for _, role := range []string{policyspec.PoolVIPOwnershipPreparedNonServing, policyspec.PoolVIPOwnershipServing, policyspec.PoolVIPOwnershipWithdrawal} {
		t.Run(role, func(t *testing.T) {
			envelope, agent := ownershipDeliveryV2(role)
			ack := ownershipAckV2(envelope)
			got, err := ValidatePoolVIPOwnershipDeliveryAckV2(time.Date(2026, 8, 13, 18, 0, 0, 0, time.UTC), agent, envelope, ack, PoolVIPOwnershipAckState{})
			if err != nil || got.Duplicate || got.ReceiptTime.IsZero() {
				t.Fatalf("valid v2 %s acknowledgement=%+v err=%v", role, got, err)
			}
		})
	}
}

func TestPoolVIPOwnershipDeliveryV2RejectsV1AndMismatchedEvidence(t *testing.T) {
	envelope, agent := ownershipDeliveryV2(policyspec.PoolVIPOwnershipServing)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePoolVIPOwnershipDeliveryEnvelope(envelope.PoolVIPOwnershipDeliveryEnvelope); err == nil {
		t.Fatal("receipt-only v1 validator must reject a v2 artifact")
	}
	for name, mutate := range map[string]func(*PoolVIPOwnershipDeliveryAckV2){
		"role":       func(v *PoolVIPOwnershipDeliveryAckV2) { v.AppliedRole = policyspec.PoolVIPOwnershipWithdrawal },
		"route":      func(v *PoolVIPOwnershipDeliveryAckV2) { v.OwnedRouteDigest = strings.Repeat("d", 64) },
		"vip":        func(v *PoolVIPOwnershipDeliveryAckV2) { v.VIPMapDigest = strings.Repeat("e", 64) },
		"lease":      func(v *PoolVIPOwnershipDeliveryAckV2) { v.AppliedLeaseEpoch++ },
		"echo nonce": func(v *PoolVIPOwnershipDeliveryAckV2) { v.DeliveryNonce = strings.Repeat("f", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			ack := ownershipAckV2(envelope)
			mutate(&ack)
			if _, err := ValidatePoolVIPOwnershipDeliveryAckV2(time.Now().UTC(), agent, envelope, ack, PoolVIPOwnershipAckState{}); err == nil {
				t.Fatal("mismatched v2 evidence must fail closed")
			}
		})
	}
	first, err := ValidatePoolVIPOwnershipDeliveryAckV2(time.Now().UTC(), agent, envelope, ownershipAckV2(envelope), PoolVIPOwnershipAckState{})
	if err != nil {
		t.Fatal(err)
	}
	changedReplay := ownershipAckV2(envelope)
	changedReplay.VIPMapDigest = strings.Repeat("f", 64)
	if _, err := ValidatePoolVIPOwnershipDeliveryAckV2(time.Now().UTC(), agent, envelope, changedReplay, first.NextState); err == nil {
		t.Fatal("changed delivery-ID replay must fail closed")
	}
	for name, mutate := range map[string]func(*PoolVIPOwnershipDeliveryEnvelopeV2){
		"revision": func(v *PoolVIPOwnershipDeliveryEnvelopeV2) { v.ManifestRevision = envelope.ManifestRevision },
		"lease":    func(v *PoolVIPOwnershipDeliveryEnvelopeV2) { v.ManifestRevision++; v.LeaseEpoch-- },
	} {
		t.Run("stale "+name, func(t *testing.T) {
			candidate := envelope
			candidate.DeliveryID = "00000000-0000-4000-8000-000000000009"
			candidate.DeliveryNonce = strings.Repeat("d", 64)
			mutate(&candidate)
			ack := ownershipAckV2(candidate)
			if _, err := ValidatePoolVIPOwnershipDeliveryAckV2(time.Now().UTC(), agent, candidate, ack, first.NextState); err == nil {
				t.Fatal("stale v2 successor must fail closed")
			}
		})
	}
}

func TestPoolVIPOwnershipDeliveryV2BoundsOwnedRoutesBeforeDigestOrStateMutation(t *testing.T) {
	envelope, agent := ownershipDeliveryV2(policyspec.PoolVIPOwnershipServing)

	overCount := make([]string, poolVIPOwnershipMaxOwnedRoutes+1)
	// Use canonical distinct prefixes so this red demonstrates the cardinality
	// boundary rather than an earlier syntax rejection.
	for i := range overCount {
		overCount[i] = fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
	}
	envelope.OwnedRoutes = overCount
	envelope.ExpectedRouteDigest = strings.Repeat("d", 64)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(envelope); err == nil {
		t.Fatal("over-limit owned routes must fail before digest/state work")
	}
	if _, err := preparePoolVIPOwnershipDeliveryV2Issue(envelope, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("over-limit owned routes must fail before issue preparation copies or persists them")
	}
	if _, err := ValidatePoolVIPOwnershipDeliveryAckV2(time.Now().UTC(), agent, envelope, ownershipAckV2(envelope), PoolVIPOwnershipAckState{}); err == nil {
		t.Fatal("over-limit routes must not produce an acknowledgement state")
	}

	overlong, _ := ownershipDeliveryV2(policyspec.PoolVIPOwnershipServing)
	overlong.OwnedRoutes = []string{strings.Repeat("1", poolVIPOwnershipMaxOwnedRouteBytes+1)}
	overlong.ExpectedRouteDigest = strings.Repeat("d", 64)
	if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV2(overlong); err == nil {
		t.Fatal("overlong route string must fail before parsing/digest allocation")
	}
}

func ownershipDeliveryV2(role string) (PoolVIPOwnershipDeliveryEnvelopeV2, PoolVIPOwnershipAgentIdentity) {
	base, agent := ownershipDelivery()
	base.Version = PoolVIPOwnershipDeliveryAttestationVersion
	envelope := PoolVIPOwnershipDeliveryEnvelopeV2{PoolVIPOwnershipDeliveryEnvelope: base}
	switch role {
	case policyspec.PoolVIPOwnershipPreparedNonServing:
		envelope.Role, envelope.DeliveryPhase = role, poolVIPOwnershipPhasePrepare
	case policyspec.PoolVIPOwnershipWithdrawal:
		envelope.Role, envelope.DeliveryPhase, envelope.PriorLeaseEpoch = role, poolVIPOwnershipPhaseWithdraw, base.LeaseEpoch-1
	default:
		envelope.OwnedRoutes = []string{"10.44.0.0/16"}
		envelope.ExpectedVIPMapDigest = strings.Repeat("c", 64)
	}
	digest, _ := PoolVIPOwnershipOwnedRouteDigest(envelope.OwnedRoutes)
	envelope.ExpectedRouteDigest = digest
	return envelope, agent
}

func TestPoolVIPOwnershipOwnedRouteDigestCanonicalEmptySet(t *testing.T) {
	nilDigest, err := PoolVIPOwnershipOwnedRouteDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	emptyDigest, err := PoolVIPOwnershipOwnedRouteDigest([]string{})
	if err != nil {
		t.Fatal(err)
	}
	const canonicalEmpty = "5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d"
	if nilDigest != canonicalEmpty || emptyDigest != canonicalEmpty {
		t.Fatalf("nil/empty routes must retain the P1/P2 canonical empty digest: nil=%s empty=%s", nilDigest, emptyDigest)
	}
}

func ownershipAckV2(envelope PoolVIPOwnershipDeliveryEnvelopeV2) PoolVIPOwnershipDeliveryAckV2 {
	lease := envelope.LeaseEpoch
	if envelope.Role == policyspec.PoolVIPOwnershipWithdrawal {
		lease = envelope.PriorLeaseEpoch
	}
	return PoolVIPOwnershipDeliveryAckV2{
		PoolVIPOwnershipDeliveryAck: ownershipAck(envelope.PoolVIPOwnershipDeliveryEnvelope),
		AppliedRole:                 envelope.Role, AppliedManifestIdentity: envelope.ManifestIdentity,
		AppliedPromotionGeneration: envelope.PromotionGeneration, AppliedManifestRevision: envelope.ManifestRevision,
		AppliedLeaseEpoch: lease, OwnedRouteDigest: envelope.ExpectedRouteDigest, VIPMapDigest: envelope.ExpectedVIPMapDigest,
	}
}
