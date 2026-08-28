package k8s

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

var leaseNow = time.Date(2026, time.August, 13, 13, 0, 0, 0, time.UTC)

var (
	leaseOrg       = uuid.MustParse("00000000-0000-0000-0000-000000000001")
	leaseSite      = uuid.MustParse("00000000-0000-0000-0000-000000000002")
	leasePool      = uuid.MustParse("00000000-0000-0000-0000-000000000003")
	leaseCluster   = uuid.MustParse("00000000-0000-0000-0000-000000000004")
	leasePrimary   = uuid.MustParse("00000000-0000-0000-0000-000000000005")
	leaseStandby   = uuid.MustParse("00000000-0000-0000-0000-000000000006")
	leaseOtherNode = uuid.MustParse("00000000-0000-0000-0000-000000000007")
)

func leaseArtifact(connector uuid.UUID, generation, revision, epoch uint64, role OwnershipRole, identity string, expiry time.Time) ArtifactPrerequisite {
	routeDigest, vipMapDigest := P2HandoffCanonicalEmptyRouteDigest, ""
	if role == Serving {
		routeDigest = "1111111111111111111111111111111111111111111111111111111111111111"
		vipMapDigest = "2222222222222222222222222222222222222222222222222222222222222222"
	}
	return ArtifactPrerequisite{
		Scope:               OwnershipScope{OrgID: leaseOrg, SiteID: leaseSite, PoolID: leasePool, ClusterID: leaseCluster, ConnectorID: connector},
		PromotionGeneration: generation, ManifestRevision: revision, ManifestIdentity: identity, ExpectedRouteDigest: routeDigest, ExpectedVIPMapDigest: vipMapDigest, IdentityValidated: true,
		Lease: CPOwnershipLease{Epoch: epoch, ExpiresAt: expiry, CPIssuedValidated: true}, Role: role,
	}
}

func TestServingArtifactRefusesCanonicalEmptyRouteDigest(t *testing.T) {
	artifact := leaseArtifact(leaseStandby, 8, 12, 18, Serving, "opaque-serving", leaseNow.Add(time.Minute))
	artifact.ExpectedRouteDigest = P2HandoffCanonicalEmptyRouteDigest
	if artifact.valid() {
		t.Fatal("serving artifact with the canonical empty route digest must fail closed")
	}
}

func preparedAck(a ArtifactPrerequisite, receipt time.Time) ArtifactAcknowledgement {
	return ArtifactAcknowledgement{Artifact: a, ReceiptAt: receipt, NonServingAttested: true}
}

func TestEvaluatePreparedOwnershipRejectsStaleReplayedAndConflictingRevisions(t *testing.T) {
	expected := leaseArtifact(leaseStandby, 8, 12, 18, PreparedNonServing, "opaque-prepared-12", leaseNow.Add(time.Minute))
	for name, previous := range map[string]ArtifactPrerequisite{
		"stale revision":       leaseArtifact(leaseStandby, 8, 13, 17, PreparedNonServing, "opaque-prepared-13", leaseNow.Add(time.Minute)),
		"replayed revision":    leaseArtifact(leaseStandby, 8, 12, 17, PreparedNonServing, "opaque-prepared-12", leaseNow.Add(time.Minute)),
		"conflicting revision": leaseArtifact(leaseStandby, 8, 12, 17, PreparedNonServing, "other-opaque-identity", leaseNow.Add(time.Minute)),
		"stale generation":     leaseArtifact(leaseStandby, 9, 11, 17, PreparedNonServing, "opaque-newer-generation", leaseNow.Add(time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			d := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Previous: &previous, Acknowledgement: preparedAck(expected, leaseNow.Add(-time.Second))})
			if d.Transition != OwnershipRefused {
				t.Fatalf("%s accepted: %+v", name, d)
			}
		})
	}
}

func TestEvaluatePreparedOwnershipEnforcesLeaseEpochOrder(t *testing.T) {
	expected := leaseArtifact(leaseStandby, 8, 12, 18, PreparedNonServing, "opaque-prepared-12", leaseNow.Add(time.Minute))
	for name, previous := range map[string]ArtifactPrerequisite{
		"same generation lower epoch":    leaseArtifact(leaseStandby, 8, 11, 19, PreparedNonServing, "opaque-prepared-11", leaseNow.Add(time.Minute)),
		"same epoch different expiry":    leaseArtifact(leaseStandby, 8, 11, 18, PreparedNonServing, "opaque-prepared-11", leaseNow.Add(2*time.Minute)),
		"advanced generation same epoch": leaseArtifact(leaseStandby, 7, 11, 18, PreparedNonServing, "opaque-prepared-11", leaseNow.Add(time.Minute)),
	} {
		t.Run(name, func(t *testing.T) {
			d := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Previous: &previous, Acknowledgement: preparedAck(expected, leaseNow.Add(-time.Second))})
			if d.Transition != OwnershipRefused {
				t.Fatalf("%s accepted: %+v", name, d)
			}
		})
	}
	previous := leaseArtifact(leaseStandby, 8, 11, 18, PreparedNonServing, "opaque-prepared-11", leaseNow.Add(time.Minute))
	if d := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Previous: &previous, Acknowledgement: preparedAck(expected, leaseNow.Add(-time.Second))}); d.Transition != OwnershipPrepared {
		t.Fatalf("same-generation revision advance may retain the same lease epoch: %+v", d)
	}
}

func TestEvaluatePreparedOwnershipRejectsWrongScopeConnectorAndReceipt(t *testing.T) {
	expected := leaseArtifact(leaseStandby, 8, 12, 18, PreparedNonServing, "opaque-prepared-12", leaseNow.Add(time.Minute))
	for name, mutate := range map[string]func(*ArtifactAcknowledgement){
		"wrong pool":      func(a *ArtifactAcknowledgement) { a.Artifact.Scope.PoolID = uuid.New() },
		"wrong cluster":   func(a *ArtifactAcknowledgement) { a.Artifact.Scope.ClusterID = uuid.New() },
		"wrong connector": func(a *ArtifactAcknowledgement) { a.Artifact.Scope.ConnectorID = leaseOtherNode },
		"future receipt":  func(a *ArtifactAcknowledgement) { a.ReceiptAt = leaseNow.Add(time.Second) },
		"expired receipt": func(a *ArtifactAcknowledgement) { a.ReceiptAt = leaseNow.Add(-time.Minute) },
		"old agent": func(a *ArtifactAcknowledgement) {
			a.Artifact.IdentityValidated = false
			a.ReceiptAt = time.Time{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ack := preparedAck(expected, leaseNow.Add(-time.Second))
			mutate(&ack)
			d := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Acknowledgement: ack})
			if d.Transition != OwnershipRefused {
				t.Fatalf("%s accepted: %+v", name, d)
			}
		})
	}
}

func TestEvaluatePreparedOwnershipRejectsNilUUIDScope(t *testing.T) {
	expected := leaseArtifact(leaseStandby, 8, 12, 18, PreparedNonServing, "opaque-prepared-12", leaseNow.Add(time.Minute))
	expected.Scope.PoolID = uuid.Nil
	d := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Acknowledgement: preparedAck(expected, leaseNow.Add(-time.Second))})
	if d.Transition != OwnershipRefused {
		t.Fatalf("nil UUID scope must fail closed: %+v", d)
	}
}

func TestEvaluatePreparedOwnershipDoesNotTrustAgentClock(t *testing.T) {
	expected := leaseArtifact(leaseStandby, 8, 12, 18, PreparedNonServing, "opaque-prepared-12", leaseNow.Add(time.Minute))
	ack := preparedAck(expected, leaseNow.Add(-time.Second))
	ack.AgentObservedAt = leaseNow.Add(200 * 365 * 24 * time.Hour)
	first := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Acknowledgement: ack})
	ack.AgentObservedAt = time.Time{}
	second := EvaluatePreparedOwnership(PreparedOwnershipInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Expected: expected, Acknowledgement: ack})
	if first.Transition != OwnershipPrepared || second != first {
		t.Fatalf("agent clock must be diagnostic only: first=%+v second=%+v", first, second)
	}
}

func servingInput(oldConnector, newConnector uuid.UUID, now time.Time) ServingOwnershipInput {
	old := leaseArtifact(oldConnector, 7, 10, 17, Serving, "opaque-old-serving", now.Add(time.Minute))
	prepared := leaseArtifact(newConnector, 8, 11, 18, PreparedNonServing, "opaque-new-prepared", now.Add(5*time.Minute))
	serving := leaseArtifact(newConnector, 8, 12, 18, Serving, "opaque-new-serving", now.Add(5*time.Minute))
	withdrawal := leaseArtifact(oldConnector, 8, 11, 18, PreparedNonServing, "opaque-old-withdrawal", now.Add(5*time.Minute))
	return ServingOwnershipInput{
		Now: now, MaxAckAge: time.Minute, ClockSkewMargin: 5 * time.Second,
		NewPrepared: prepared, NewServing: serving, PreparedAck: preparedAck(prepared, now.Add(-time.Second)),
		OldServing: old, OldWithdrawal: withdrawal,
	}
}

func TestEvaluateServingOwnershipRequiresWithdrawBeforeEnable(t *testing.T) {
	in := servingInput(leasePrimary, leaseStandby, leaseNow)
	if d := EvaluateServingOwnership(in); d.Transition != OwnershipRefused {
		t.Fatalf("unwithdrawn, unexpired old owner enabled a second server: %+v", d)
	}
	withdrawal := preparedAck(in.OldWithdrawal, leaseNow.Add(-time.Second))
	withdrawal.WithdrawalLeaseEpoch = in.OldServing.Lease.Epoch
	in.WithdrawalAck = &withdrawal
	if d := EvaluateServingOwnership(in); d.Transition != OwnershipEnableServing || d.LeaseExpiryFallback {
		t.Fatalf("fresh old-owner withdrawal must enable new owner: %+v", d)
	}
}

func TestEvaluateServingOwnershipRejectsDualServingAndBadWithdrawal(t *testing.T) {
	in := servingInput(leasePrimary, leaseStandby, leaseNow)
	in.PreparedAck.ServingAttested = true
	if d := EvaluateServingOwnership(in); d.Transition != OwnershipRefused {
		t.Fatalf("prepared candidate attesting serving must be refused: %+v", d)
	}
	in = servingInput(leasePrimary, leaseStandby, leaseNow)
	withdrawal := preparedAck(in.OldWithdrawal, leaseNow.Add(-time.Second))
	withdrawal.ServingAttested = true
	withdrawal.WithdrawalLeaseEpoch = in.OldServing.Lease.Epoch
	in.WithdrawalAck = &withdrawal
	if d := EvaluateServingOwnership(in); d.Transition != OwnershipRefused {
		t.Fatalf("old owner still serving must not authorize enable: %+v", d)
	}
}

func TestEvaluateServingOwnershipUsesConservativeLeaseExpiryFallback(t *testing.T) {
	now := leaseNow.Add(2 * time.Minute)
	in := servingInput(leasePrimary, leaseStandby, now)
	in.OldServing.Lease.ExpiresAt = now.Add(-6 * time.Second) // beyond the 5s skew margin
	if d := EvaluateServingOwnership(in); d.Transition != OwnershipEnableServing || !d.LeaseExpiryFallback {
		t.Fatalf("expired old lease must be the only no-ack fallback: %+v", d)
	}
	in = servingInput(leasePrimary, leaseStandby, now)
	in.OldServing.Lease.ExpiresAt = now.Add(-4 * time.Second) // still inside the skew margin
	if d := EvaluateServingOwnership(in); d.Transition != OwnershipRefused {
		t.Fatalf("old lease inside the skew margin must remain fenced: %+v", d)
	}
}

func TestEvaluateServingOwnershipIsSymmetricForFailback(t *testing.T) {
	for name, oldNew := range map[string][2]uuid.UUID{
		"promotion": {leasePrimary, leaseStandby},
		"failback":  {leaseStandby, leasePrimary},
	} {
		t.Run(name, func(t *testing.T) {
			in := servingInput(oldNew[0], oldNew[1], leaseNow)
			withdrawal := preparedAck(in.OldWithdrawal, leaseNow.Add(-time.Second))
			withdrawal.WithdrawalLeaseEpoch = in.OldServing.Lease.Epoch
			in.WithdrawalAck = &withdrawal
			if d := EvaluateServingOwnership(in); d.Transition != OwnershipEnableServing || d.LeaseExpiryFallback {
				t.Fatalf("%s must use the same withdrawal fence: %+v", name, d)
			}
		})
	}
}
