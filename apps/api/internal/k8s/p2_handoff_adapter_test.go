package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestP2HandoffAdapterIssuesDeterministicLeaderBoundDeliveries(t *testing.T) {
	plan := testP2DurableHandoffPlan(t)
	epoch := HandoffLeadershipEpoch{BackendPID: 7, LockKey: 9}
	issuer := &fakeP2HandoffIssuer{epoch: epoch, issued: map[uuid.UUID]P2HandoffDelivery{}}
	adapter := NewP2HandoffAdapter(issuer, nil)
	adapter.now = func() time.Time { return leaseNow }

	for _, tc := range []struct {
		name  string
		which P2HandoffArtifact
		role  P2HandoffRole
	}{
		{"old serving reference", P2OldServingArtifact, P2HandoffServing},
		{"candidate prepared", P2NewPreparedArtifact, P2HandoffPrepared},
		{"old withdrawal", P2OldWithdrawalArtifact, P2HandoffWithdrawal},
		{"candidate serving", P2NewServingArtifact, P2HandoffServing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first, err := P2HandoffDeliveryForPlanArtifact(plan, tc.which)
			if err != nil {
				t.Fatal(err)
			}
			second, err := P2HandoffDeliveryForPlanArtifact(plan, tc.which)
			if err != nil || first != second || first.Identity.Role != tc.role || first.Identity.OperationID != plan.Plan.OperationID {
				t.Fatalf("plan artifact mapping must be deterministic and operation-keyed: first=%+v second=%+v err=%v", first, second, err)
			}
			if first.Identity.ConnectorNodeID != first.Identity.TargetNodeID {
				t.Fatalf("P1 artifact must target only its exact connector: %+v", first.Identity)
			}
			if first.Identity.DeliveryPhase != p2HandoffDeliveryPhase(tc.role) {
				t.Fatalf("P2 phase must be derived from the explicit role: %+v", first.Identity)
			}
			if tc.which == P2OldWithdrawalArtifact && first.Identity.PriorLeaseEpoch != plan.Plan.OldServing.Lease.Epoch {
				t.Fatalf("withdrawal must retain prior serving lease: %+v", first.Identity)
			}
			if tc.role == P2HandoffServing {
				if !validP2Digest(first.Identity.ExpectedRouteDigest) || !validP2Digest(first.Identity.ExpectedVIPMapDigest) {
					t.Fatalf("serving identity lacks exact P2 digest prerequisites: %+v", first.Identity)
				}
			} else if first.Identity.ExpectedRouteDigest != P2HandoffCanonicalEmptyRouteDigest || first.Identity.ExpectedVIPMapDigest != "" {
				t.Fatalf("non-serving identity widened route/VIP evidence: %+v", first.Identity)
			}
		})
	}

	prepared := HandoffDelivery{OperationID: plan.Plan.OperationID, Scope: plan.Plan.Scope, Artifact: plan.Plan.NewPrepared, LeadershipEpoch: epoch, LeaderConn: &pgxpool.Conn{}}
	if err := adapter.PrepareCandidate(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	// Crash after issuance but before P1's phase CAS repeats the exact request;
	// the issuer's durable DeliveryID contract accepts it without widening.
	if err := adapter.PrepareCandidate(context.Background(), prepared); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
	if issuer.calls != 2 || len(issuer.issued) != 1 {
		t.Fatalf("retry must retain one exact delivery identity: calls=%d issued=%d", issuer.calls, len(issuer.issued))
	}

	withdrawal := HandoffDelivery{OperationID: plan.Plan.OperationID, Scope: plan.Plan.Scope, Artifact: plan.Plan.OldWithdrawal, PriorLeaseEpoch: plan.Plan.OldServing.Lease.Epoch, LeadershipEpoch: epoch, LeaderConn: prepared.LeaderConn}
	if err := adapter.WithdrawOld(context.Background(), withdrawal); err != nil {
		t.Fatal(err)
	}
	serving := HandoffDelivery{OperationID: plan.Plan.OperationID, Scope: plan.Plan.Scope, Artifact: plan.Plan.NewServing, LeadershipEpoch: epoch, LeaderConn: prepared.LeaderConn}
	if err := adapter.EnableNew(context.Background(), serving); err != nil {
		t.Fatal(err)
	}

	stale := prepared
	stale.LeadershipEpoch = HandoffLeadershipEpoch{BackendPID: 6, LockKey: epoch.LockKey}
	if err := adapter.PrepareCandidate(context.Background(), stale); err == nil {
		t.Fatal("stale leader epoch must not issue")
	}
	missingSession := prepared
	missingSession.LeaderConn = nil
	if err := adapter.PrepareCandidate(context.Background(), missingSession); !errors.Is(err, ErrP2HandoffLeaderUnavailable) {
		t.Fatalf("missing pinned leader session must refuse: %v", err)
	}
	if err := adapter.EnableNew(context.Background(), prepared); err == nil {
		t.Fatal("prepared artifact must not be issued as serving")
	}
	expired := prepared
	expired.Artifact.Lease.ExpiresAt = leaseNow
	if err := adapter.PrepareCandidate(context.Background(), expired); err == nil {
		t.Fatal("expired artifact must not be issued")
	}
}

func TestP2HandoffAdapterConvertsOnlyExactV2AppliedAttestations(t *testing.T) {
	plan := testP2DurableHandoffPlan(t)
	prepared, err := P2HandoffDeliveryForPlanArtifact(plan, P2NewPreparedArtifact)
	if err != nil {
		t.Fatal(err)
	}
	withdrawal, err := P2HandoffDeliveryForPlanArtifact(plan, P2OldWithdrawalArtifact)
	if err != nil {
		t.Fatal(err)
	}
	serving, err := P2HandoffDeliveryForPlanArtifact(plan, P2NewServingArtifact)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("exact applied attestations convert with CP receipt provenance", func(t *testing.T) {
		reader := &fakeP2HandoffReader{items: map[uuid.UUID]P2HandoffAppliedAttestation{
			prepared.Identity.DeliveryID:   testP2Attestation(prepared, leaseNow.Add(-time.Second)),
			withdrawal.Identity.DeliveryID: testP2Attestation(withdrawal, leaseNow.Add(-time.Second)),
			serving.Identity.DeliveryID:    testP2Attestation(serving, leaseNow.Add(-time.Second)),
		}}
		adapter := NewP2HandoffAdapter(nil, reader)
		acks, err := adapter.AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitPreparedAck, leaseNow, time.Minute)
		if err != nil || acks.Prepared == nil {
			t.Fatalf("exact v3 attestations must convert: acks=%+v err=%v", acks, err)
		}
		withdrawn, err := adapter.AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitWithdrawal, leaseNow, time.Minute)
		if err != nil {
			t.Fatalf("withdrawal acknowledgement: %v", err)
		}
		served, err := adapter.AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitServingAck, leaseNow, time.Minute)
		if err != nil {
			t.Fatalf("serving acknowledgement: %v", err)
		}
		acks.Withdrawal, acks.Serving = withdrawn.Withdrawal, served.Serving
		if acks.Withdrawal == nil || acks.Serving == nil {
			t.Fatalf("exact phase attestation conversion failed: acks=%+v", acks)
		}
		if !acks.Prepared.NonServingAttested || acks.Prepared.ServingAttested || !acks.Withdrawal.NonServingAttested || acks.Withdrawal.WithdrawalLeaseEpoch != plan.Plan.OldServing.Lease.Epoch || !acks.Serving.ServingAttested || acks.Serving.NonServingAttested {
			t.Fatalf("role-specific P1 acknowledgement projection is wrong: %+v", acks)
		}
	})

	for name, mutate := range map[string]func(*P2HandoffAppliedAttestation){
		"receipt-only v1":   func(v *P2HandoffAppliedAttestation) { v.Version = 1 },
		"digest-only v2":    func(v *P2HandoffAppliedAttestation) { v.Version = 2 },
		"wrong role":        func(v *P2HandoffAppliedAttestation) { v.AppliedRole = P2HandoffServing },
		"wrong scope":       func(v *P2HandoffAppliedAttestation) { v.Identity.PoolID = uuid.New() },
		"wrong connector":   func(v *P2HandoffAppliedAttestation) { v.Identity.ConnectorNodeID = uuid.New() },
		"wrong operation":   func(v *P2HandoffAppliedAttestation) { v.Identity.OperationID = uuid.New() },
		"replayed artifact": func(v *P2HandoffAppliedAttestation) { v.Identity.ManifestRevision++ },
		"wrong phase":       func(v *P2HandoffAppliedAttestation) { v.Identity.DeliveryPhase = "serve" },
		"stale receipt":     func(v *P2HandoffAppliedAttestation) { v.CPReceiptAt = leaseNow.Add(-time.Minute) },
		"extended lease":    func(v *P2HandoffAppliedAttestation) { v.DeliveryExpiresAt = v.DeliveryExpiresAt.Add(time.Minute) },
		"expired delivery":  func(v *P2HandoffAppliedAttestation) { v.DeliveryExpiresAt = leaseNow },
		"route digest mismatch": func(v *P2HandoffAppliedAttestation) {
			v.AppliedRouteDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"non-serving VIP digest": func(v *P2HandoffAppliedAttestation) {
			v.AppliedVIPMapDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := testP2Attestation(prepared, leaseNow.Add(-time.Second))
			mutate(&bad)
			reader := &fakeP2HandoffReader{items: map[uuid.UUID]P2HandoffAppliedAttestation{prepared.Identity.DeliveryID: bad}}
			if _, err := NewP2HandoffAdapter(nil, reader).AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitPreparedAck, leaseNow, time.Minute); !errors.Is(err, ErrP2HandoffAttestation) {
				t.Fatalf("invalid P2 value must refuse rather than become an ack: %v", err)
			}
		})
	}

	t.Run("withdrawal must attest the prior serving lease", func(t *testing.T) {
		bad := testP2Attestation(withdrawal, leaseNow.Add(-time.Second))
		bad.AppliedLeaseEpoch = withdrawal.Identity.LeaseEpoch
		reader := &fakeP2HandoffReader{items: map[uuid.UUID]P2HandoffAppliedAttestation{withdrawal.Identity.DeliveryID: bad}}
		if _, err := NewP2HandoffAdapter(nil, reader).AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitWithdrawal, leaseNow, time.Minute); !errors.Is(err, ErrP2HandoffAttestation) {
			t.Fatalf("withdrawal of the target rather than prior lease was accepted: %v", err)
		}
	})

	t.Run("serving requires exact nonempty route and VIP evidence", func(t *testing.T) {
		for name, mutate := range map[string]func(*P2HandoffAppliedAttestation){
			"route digest mismatch": func(v *P2HandoffAppliedAttestation) {
				v.AppliedRouteDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			"VIP digest mismatch": func(v *P2HandoffAppliedAttestation) {
				v.AppliedVIPMapDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			},
			"empty route evidence": func(v *P2HandoffAppliedAttestation) { v.AppliedRouteDigest = "" },
			"empty VIP evidence":   func(v *P2HandoffAppliedAttestation) { v.AppliedVIPMapDigest = "" },
		} {
			t.Run(name, func(t *testing.T) {
				bad := testP2Attestation(serving, leaseNow.Add(-time.Second))
				mutate(&bad)
				reader := &fakeP2HandoffReader{items: map[uuid.UUID]P2HandoffAppliedAttestation{serving.Identity.DeliveryID: bad}}
				if _, err := NewP2HandoffAdapter(nil, reader).AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitServingAck, leaseNow, time.Minute); !errors.Is(err, ErrP2HandoffAttestation) {
					t.Fatalf("serving applied evidence was accepted: %v", err)
				}
			})
		}
	})

	t.Run("prepared and withdrawal roles cannot substitute for each other", func(t *testing.T) {
		for name, tc := range map[string]struct {
			delivery    P2HandoffDelivery
			phase       HandoffPhase
			replacement P2HandoffRole
		}{
			"prepared as withdrawal": {prepared, HandoffAwaitPreparedAck, P2HandoffWithdrawal},
			"withdrawal as prepared": {withdrawal, HandoffAwaitWithdrawal, P2HandoffPrepared},
		} {
			t.Run(name, func(t *testing.T) {
				bad := testP2Attestation(tc.delivery, leaseNow.Add(-time.Second))
				bad.AppliedRole = tc.replacement
				reader := &fakeP2HandoffReader{items: map[uuid.UUID]P2HandoffAppliedAttestation{tc.delivery.Identity.DeliveryID: bad}}
				if _, err := NewP2HandoffAdapter(nil, reader).AcknowledgementsForPhase(context.Background(), plan, tc.phase, leaseNow, time.Minute); !errors.Is(err, ErrP2HandoffAttestation) {
					t.Fatalf("cross-role applied evidence was accepted: %v", err)
				}
			})
		}
	})

	t.Run("serving attestation cannot bypass withdrawal", func(t *testing.T) {
		reader := &fakeP2HandoffReader{items: map[uuid.UUID]P2HandoffAppliedAttestation{
			prepared.Identity.DeliveryID: testP2Attestation(prepared, leaseNow.Add(-time.Second)),
			serving.Identity.DeliveryID:  testP2Attestation(serving, leaseNow.Add(-time.Second)),
		}}
		adapter := NewP2HandoffAdapter(nil, reader)
		acks, err := adapter.AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitPreparedAck, leaseNow, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if acks.Serving != nil {
			t.Fatalf("pre-CAS phase must not surface serving attestation: %+v", acks.Serving)
		}
		progress := handoffProgress(plan.Plan, HandoffAwaitWithdrawal)
		progress.PreparedAck = acks.Prepared
		if decision := EvaluateHandoff(handoffInput(plan.Plan, progress)); decision.Action != HandoffRefuse {
			t.Fatalf("serving acknowledgement bypassed withdrawal proof: %+v", decision)
		}
		reader.items[withdrawal.Identity.DeliveryID] = testP2Attestation(withdrawal, leaseNow.Add(-time.Second))
		acks, err = adapter.AcknowledgementsForPhase(context.Background(), plan, HandoffAwaitWithdrawal, leaseNow, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		progress.WithdrawalAck = acks.Withdrawal
		progress.ServingAck = nil
		if decision := EvaluateHandoff(handoffInput(plan.Plan, progress)); decision.Action != HandoffRecordCASReady {
			t.Fatalf("exact withdrawal proof did not unlock CAS readiness: %+v", decision)
		}
	})
}

func TestP2HandoffAdapterLeaderBoundPhaseReadSurvivesRestartAndRejectsWrongPhase(t *testing.T) {
	plan := testP2DurableHandoffPlan(t)
	prepared, err := P2HandoffDeliveryForPlanArtifact(plan, P2NewPreparedArtifact)
	if err != nil {
		t.Fatal(err)
	}
	serving, err := P2HandoffDeliveryForPlanArtifact(plan, P2NewServingArtifact)
	if err != nil {
		t.Fatal(err)
	}
	epoch := HandoffLeadershipEpoch{BackendPID: 17, LockKey: 23}
	conn := &pgxpool.Conn{}
	reader := &fakeP2HandoffLeaderReader{
		epoch: epoch,
		conn:  conn,
		items: map[uuid.UUID]P2HandoffAppliedAttestation{
			prepared.Identity.DeliveryID: testP2Attestation(prepared, leaseNow.Add(-time.Second)),
			serving.Identity.DeliveryID:  testP2Attestation(serving, leaseNow.Add(-time.Second)),
		},
	}

	// Reconstructing the adapter models a scheduler restart: no process-local
	// token is needed because the exact applied row is read again.
	for restart := range 2 {
		adapter := NewP2HandoffAdapter(nil, reader)
		acks, err := adapter.AcknowledgementsForPhaseWithLeadership(context.Background(), plan, HandoffAwaitPreparedAck, leaseNow, time.Minute, epoch, conn)
		if err != nil || acks.Prepared == nil || acks.Withdrawal != nil || acks.Serving != nil {
			t.Fatalf("restart %d exact prepared read: acks=%+v err=%v", restart, acks, err)
		}
	}
	if reader.boundCalls != 2 || reader.unboundCalls != 0 {
		t.Fatalf("leader-bound read calls=%d generic=%d", reader.boundCalls, reader.unboundCalls)
	}

	acks, err := NewP2HandoffAdapter(nil, reader).AcknowledgementsForPhaseWithLeadership(context.Background(), plan, HandoffAwaitWithdrawal, leaseNow, time.Minute, epoch, conn)
	if err != nil || acks.Prepared != nil || acks.Withdrawal != nil || acks.Serving != nil {
		t.Fatalf("serving row substituted for withdrawal phase: acks=%+v err=%v", acks, err)
	}
	if reader.last.Role != P2HandoffWithdrawal || reader.last.DeliveryID == serving.Identity.DeliveryID {
		t.Fatalf("wrong phase identity was queried: %+v", reader.last)
	}

	if _, err := NewP2HandoffAdapter(nil, &fakeP2HandoffReader{}).AcknowledgementsForPhaseWithLeadership(context.Background(), plan, HandoffAwaitPreparedAck, leaseNow, time.Minute, epoch, conn); !errors.Is(err, ErrP2HandoffAttestation) {
		t.Fatalf("generic reader was accepted by leader-bound path: %v", err)
	}
}

func TestP2HandoffArtifactDigestPrerequisitesAreRoleSpecific(t *testing.T) {
	base := testP2DurableHandoffPlan(t)
	for name, mutate := range map[string]func(*DurableHandoffPlan){
		"serving route digest missing": func(plan *DurableHandoffPlan) {
			plan.Plan.NewServing.ExpectedRouteDigest = ""
		},
		"serving VIP digest missing": func(plan *DurableHandoffPlan) {
			plan.Plan.NewServing.ExpectedVIPMapDigest = ""
		},
		"prepared route digest is not canonical empty": func(plan *DurableHandoffPlan) {
			plan.Plan.NewPrepared.ExpectedRouteDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		},
		"prepared carries VIP digest": func(plan *DurableHandoffPlan) {
			plan.Plan.NewPrepared.ExpectedVIPMapDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"withdrawal carries VIP digest": func(plan *DurableHandoffPlan) {
			plan.Plan.OldWithdrawal.ExpectedVIPMapDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan := base
			mutate(&plan)
			if _, err := P2HandoffDeliveryForPlanArtifact(plan, P2NewServingArtifact); err == nil {
				t.Fatal("invalid P2 route/VIP prerequisite was accepted")
			}
		})
	}
}

func testP2DurableHandoffPlan(t *testing.T) DurableHandoffPlan {
	t.Helper()
	plan := handoffPlan(t, Promoted, leasePrimary, leaseStandby)
	return DurableHandoffPlan{Plan: plan, OldLeaseIdentity: "old-lease", TargetLeaseIdentity: "target-lease"}
}

func testP2Attestation(delivery P2HandoffDelivery, receipt time.Time) P2HandoffAppliedAttestation {
	return P2HandoffAppliedAttestation{Version: P2HandoffAttestationVersion, Identity: delivery.Identity, CPReceiptAt: receipt, DeliveryExpiresAt: delivery.LeaseExpiresAt,
		AppliedRole: delivery.Identity.Role, AppliedManifestIdentity: delivery.Identity.ManifestIdentity, AppliedPromotionGeneration: delivery.Identity.PromotionGeneration,
		AppliedManifestRevision: delivery.Identity.ManifestRevision, AppliedLeaseEpoch: expectedAppliedLeaseEpoch(delivery.Identity),
		AppliedRouteDigest: delivery.Identity.ExpectedRouteDigest, AppliedVIPMapDigest: delivery.Identity.ExpectedVIPMapDigest}
}

type fakeP2HandoffIssuer struct {
	epoch  HandoffLeadershipEpoch
	calls  int
	issued map[uuid.UUID]P2HandoffDelivery
}

func (f *fakeP2HandoffIssuer) IssueP2HandoffDelivery(_ context.Context, epoch HandoffLeadershipEpoch, conn *pgxpool.Conn, delivery P2HandoffDelivery) error {
	if epoch != f.epoch {
		return errors.New("stale leader session")
	}
	if conn == nil {
		return errors.New("missing leader session")
	}
	f.calls++
	if prior, found := f.issued[delivery.Identity.DeliveryID]; found && prior != delivery {
		return errors.New("delivery retry changed immutable identity")
	}
	f.issued[delivery.Identity.DeliveryID] = delivery
	return nil
}

type fakeP2HandoffReader struct {
	items map[uuid.UUID]P2HandoffAppliedAttestation
}

type fakeP2HandoffLeaderReader struct {
	epoch        HandoffLeadershipEpoch
	conn         *pgxpool.Conn
	items        map[uuid.UUID]P2HandoffAppliedAttestation
	last         P2HandoffDeliveryIdentity
	boundCalls   int
	unboundCalls int
}

func (f *fakeP2HandoffLeaderReader) LoadP2HandoffAppliedAttestation(_ context.Context, identity P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error) {
	f.unboundCalls++
	v, ok := f.items[identity.DeliveryID]
	return v, ok, nil
}

func (f *fakeP2HandoffLeaderReader) LoadP2HandoffAppliedAttestationWithLeadership(_ context.Context, epoch HandoffLeadershipEpoch, conn *pgxpool.Conn, identity P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error) {
	if epoch != f.epoch || conn != f.conn {
		return P2HandoffAppliedAttestation{}, false, ErrHandoffLeadershipUnavailable
	}
	f.boundCalls++
	f.last = identity
	v, ok := f.items[identity.DeliveryID]
	return v, ok, nil
}

func (f *fakeP2HandoffReader) LoadP2HandoffAppliedAttestation(_ context.Context, identity P2HandoffDeliveryIdentity) (P2HandoffAppliedAttestation, bool, error) {
	v, ok := f.items[identity.DeliveryID]
	return v, ok, nil
}
