package k8s

import (
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
)

func handoffPlan(t *testing.T, transition Transition, oldID, newID uuid.UUID) HandoffPlan {
	t.Helper()
	op := uuid.MustParse("00000000-0000-0000-0000-000000000008")
	now := leaseNow
	old := leaseArtifact(oldID, 7, 10, 17, Serving, "opaque-old-serving", now.Add(time.Minute))
	prepared := leaseArtifact(newID, 8, 11, 18, PreparedNonServing, "opaque-new-prepared", now.Add(5*time.Minute))
	serving := leaseArtifact(newID, 8, 12, 18, Serving, "opaque-new-serving", now.Add(5*time.Minute))
	withdrawal := leaseArtifact(oldID, 8, 11, 18, PreparedNonServing, "opaque-old-withdrawal", now.Add(5*time.Minute))
	return HandoffPlan{
		OperationID: op, Scope: HandoffPoolScope{OrgID: leaseOrg, SiteID: leaseSite, PoolID: leasePool, ClusterID: leaseCluster},
		ExpectedActiveID: oldID, CandidateID: newID, ExpectedGeneration: 7, TargetGeneration: 8,
		Decision:    Decision{Transition: transition, FromID: oldID.String(), ToID: newID.String(), Pool: ConnectorPool{ActiveID: newID.String(), Generation: 8}},
		NewPrepared: prepared, NewServing: serving, OldServing: old, OldWithdrawal: withdrawal,
	}
}

func handoffProgress(plan HandoffPlan, phase HandoffPhase) HandoffProgress {
	return HandoffProgress{
		Record: HandoffOperationRecord{OperationID: plan.OperationID, Phase: phase},
		Pool:   HandoffPoolSnapshot{Scope: plan.Scope, ActiveID: plan.ExpectedActiveID, Generation: plan.ExpectedGeneration, Members: map[uuid.UUID]bool{plan.ExpectedActiveID: true, plan.CandidateID: true}},
	}
}

func TestValidateDurableHandoffPlanRefusesBigintOverflow(t *testing.T) {
	base := DurableHandoffPlan{Plan: handoffPlan(t, Promoted, leasePrimary, leaseStandby), OldLeaseIdentity: "old", TargetLeaseIdentity: "target"}
	for name, mutate := range map[string]func(*DurableHandoffPlan){
		"generation target overflows durable bigint": func(p *DurableHandoffPlan) {
			p.Plan.ExpectedGeneration, p.Plan.TargetGeneration = uint64(math.MaxInt64), uint64(math.MaxInt64)+1
			p.Plan.Decision.Pool.Generation = p.Plan.TargetGeneration
			p.Plan.OldServing.PromotionGeneration = p.Plan.ExpectedGeneration
			p.Plan.NewPrepared.PromotionGeneration = p.Plan.TargetGeneration
			p.Plan.OldWithdrawal.PromotionGeneration = p.Plan.TargetGeneration
			p.Plan.NewServing.PromotionGeneration = p.Plan.TargetGeneration
		},
		"manifest revision overflows durable bigint": func(p *DurableHandoffPlan) {
			p.Plan.NewServing.ManifestRevision = uint64(math.MaxInt64) + 1
		},
		"lease epoch overflows durable bigint": func(p *DurableHandoffPlan) {
			p.Plan.NewPrepared.Lease.Epoch = uint64(math.MaxInt64) + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := ValidateDurableHandoffPlan(candidate); err == nil {
				t.Fatal("overflowing durable handoff plan was accepted")
			}
		})
	}
}

func TestValidateDurableHandoffPlanRefusesServingSnapshotOrTargetLeaseDrift(t *testing.T) {
	base := DurableHandoffPlan{Plan: handoffPlan(t, Promoted, leasePrimary, leaseStandby), OldLeaseIdentity: "old", TargetLeaseIdentity: "target"}
	for name, mutate := range map[string]func(*DurableHandoffPlan){
		"serving route digest differs": func(p *DurableHandoffPlan) {
			p.Plan.NewServing.ExpectedRouteDigest = "3333333333333333333333333333333333333333333333333333333333333333"
		},
		"serving VIP digest differs": func(p *DurableHandoffPlan) {
			p.Plan.NewServing.ExpectedVIPMapDigest = "4444444444444444444444444444444444444444444444444444444444444444"
		},
		"prepared target lease differs": func(p *DurableHandoffPlan) { p.Plan.NewPrepared.Lease.Epoch++ },
		"withdrawal target expiry differs": func(p *DurableHandoffPlan) {
			p.Plan.OldWithdrawal.Lease.ExpiresAt = p.Plan.OldWithdrawal.Lease.ExpiresAt.Add(time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := ValidateDurableHandoffPlan(candidate); err == nil {
				t.Fatal("inconsistent serving snapshot or target lease was accepted")
			}
		})
	}
}

func handoffInput(plan HandoffPlan, progress HandoffProgress) HandoffInput {
	return HandoffInput{Now: leaseNow, MaxAckAge: time.Minute, ClockSkewMargin: time.Second, Plan: plan, Progress: progress}
}

func withdrawalAck(plan HandoffPlan) *ArtifactAcknowledgement {
	ack := preparedAck(plan.OldWithdrawal, leaseNow.Add(-time.Second))
	ack.WithdrawalLeaseEpoch = plan.OldServing.Lease.Epoch
	return &ack
}

func casReceipt(plan HandoffPlan) *HandoffCASReceipt {
	return &HandoffCASReceipt{OperationID: plan.OperationID, Scope: plan.Scope, FromID: plan.ExpectedActiveID, ToID: plan.CandidateID, Generation: plan.TargetGeneration, AuditAppended: true}
}

func TestEvaluateHandoffPhasesAreOrderedAndIdempotent(t *testing.T) {
	plan := handoffPlan(t, Promoted, leasePrimary, leaseStandby)
	progress := handoffProgress(plan, HandoffPrepareCandidate)
	assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffDeliverPrepared, HandoffAwaitPreparedAck)

	progress.Record.Phase = HandoffAwaitPreparedAck
	prepared := preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
	progress.PreparedAck = &prepared
	firstWithdrawal := EvaluateHandoff(handoffInput(plan, progress))
	secondWithdrawal := EvaluateHandoff(handoffInput(plan, progress))
	assertHandoffAction(t, firstWithdrawal, HandoffDeliverWithdrawal, HandoffAwaitWithdrawal)
	if secondWithdrawal != firstWithdrawal {
		t.Fatalf("withdrawal delivery retry must repeat only the same operation-keyed request: first=%+v second=%+v", firstWithdrawal, secondWithdrawal)
	}

	progress.Record.Phase = HandoffAwaitWithdrawal
	progress.WithdrawalAck = withdrawalAck(plan)
	assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffRecordCASReady, HandoffCASActive)

	progress.Record.Phase = HandoffCASActive
	first := EvaluateHandoff(handoffInput(plan, progress))
	second := EvaluateHandoff(handoffInput(plan, progress))
	assertHandoffAction(t, first, HandoffApplyCAS, HandoffEnableServing)
	if second != first {
		t.Fatalf("CAS retry must repeat only the same idempotency-keyed request: first=%+v second=%+v", first, second)
	}

	progress.Record.Phase = HandoffEnableServing
	progress.Pool.ActiveID, progress.Pool.Generation = plan.CandidateID, plan.TargetGeneration
	progress.CASReceipt = casReceipt(plan)
	assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffDeliverServing, HandoffAwaitServingAck)

	progress.Record.Phase = HandoffAwaitServingAck
	serving := ArtifactAcknowledgement{Artifact: plan.NewServing, ReceiptAt: leaseNow.Add(-time.Second), ServingAttested: true}
	progress.ServingAck = &serving
	assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffFinalizeSuccess, HandoffFinalize)

	progress.Record.Phase = HandoffFinalize
	assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffFinalizeSuccess, HandoffComplete)
	progress.Record.Phase = HandoffComplete
	assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffAlreadyComplete, HandoffComplete)
}

func TestEvaluateHandoffRefusesConflictsAndStalePhases(t *testing.T) {
	plan := handoffPlan(t, Promoted, leasePrimary, leaseStandby)
	for name, mutate := range map[string]func(*HandoffProgress){
		"conflicting operation": func(p *HandoffProgress) { p.Record.OperationID = uuid.New() },
		"changed active":        func(p *HandoffProgress) { p.Pool.ActiveID = leaseOtherNode },
		"changed generation":    func(p *HandoffProgress) { p.Pool.Generation++ },
		"candidate left pool":   func(p *HandoffProgress) { delete(p.Pool.Members, plan.CandidateID) },
		"replayed prepare after CAS": func(p *HandoffProgress) {
			p.CASReceipt = casReceipt(plan)
		},
	} {
		t.Run(name, func(t *testing.T) {
			progress := handoffProgress(plan, HandoffPrepareCandidate)
			mutate(&progress)
			if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
				t.Fatalf("%s was accepted: %+v", name, d)
			}
		})
	}
}

func TestEvaluateHandoffFailsClosedOnMissingOldAgentAndAmbiguousCAS(t *testing.T) {
	plan := handoffPlan(t, Promoted, leasePrimary, leaseStandby)
	progress := handoffProgress(plan, HandoffAwaitPreparedAck)
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
		t.Fatalf("missing prepared acknowledgement accepted: %+v", d)
	}
	prepared := preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
	prepared.Artifact.IdentityValidated = false // old/partial agent data never gains CP provenance
	progress.PreparedAck = &prepared
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
		t.Fatalf("old-agent acknowledgement accepted: %+v", d)
	}

	progress = handoffProgress(plan, HandoffCASActive)
	prepared = preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
	progress.PreparedAck, progress.WithdrawalAck = &prepared, withdrawalAck(plan)
	progress.CASReceipt = casReceipt(plan) // CAS happened but phase was not advanced atomically
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
		t.Fatalf("ambiguous post-CAS retry must refuse, not repeat CAS/audit: %+v", d)
	}
}

func TestEvaluateHandoffRequiresCausalExactWithdrawalOrExpiry(t *testing.T) {
	plan := handoffPlan(t, Promoted, leasePrimary, leaseStandby)
	progress := handoffProgress(plan, HandoffAwaitPreparedAck)
	prepared := preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
	progress.PreparedAck, progress.WithdrawalAck = &prepared, withdrawalAck(plan)
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
		t.Fatalf("spontaneous withdrawal acknowledgement before delivery was accepted: %+v", d)
	}

	for name, mutate := range map[string]func(*ArtifactAcknowledgement){
		"wrong withdrawal artifact":  func(a *ArtifactAcknowledgement) { a.Artifact.ManifestIdentity = "wrong-opaque-withdrawal" },
		"wrong artifact lease epoch": func(a *ArtifactAcknowledgement) { a.Artifact.Lease.Epoch++ },
		"wrong claimed lease epoch":  func(a *ArtifactAcknowledgement) { a.WithdrawalLeaseEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			progress := handoffProgress(plan, HandoffAwaitWithdrawal)
			prepared := preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
			ack := withdrawalAck(plan)
			mutate(ack)
			progress.PreparedAck, progress.WithdrawalAck = &prepared, ack
			if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
				t.Fatalf("%s was accepted: %+v", name, d)
			}
		})
	}

	progress = handoffProgress(plan, HandoffAwaitWithdrawal)
	prepared = preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
	progress.PreparedAck = &prepared
	plan.OldServing.Lease.ExpiresAt = leaseNow.Add(-2 * time.Second) // past the one-second skew margin
	d := EvaluateHandoff(handoffInput(plan, progress))
	assertHandoffAction(t, d, HandoffRecordCASReady, HandoffCASActive)
	if !d.LeaseExpiryFallback || d.Reason != "conservative old-lease expiry permits one CAS attempt" {
		t.Fatalf("lease-expiry fallback must be explicit: %+v", d)
	}
}

func TestEvaluateHandoffNeverEnablesServingBeforeWithdrawAndCAS(t *testing.T) {
	plan := handoffPlan(t, Promoted, leasePrimary, leaseStandby)
	progress := handoffProgress(plan, HandoffAwaitWithdrawal)
	prepared := preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
	progress.PreparedAck = &prepared
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
		t.Fatalf("unwithdrawn old owner must not reach CAS or serving: %+v", d)
	}
	progress.WithdrawalAck = withdrawalAck(plan)
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRecordCASReady {
		t.Fatalf("withdrawn owner must enter CAS phase, never serving directly: %+v", d)
	}

	progress.Record.Phase = HandoffEnableServing
	progress.Pool.ActiveID, progress.Pool.Generation = plan.CandidateID, plan.TargetGeneration
	if d := EvaluateHandoff(handoffInput(plan, progress)); d.Action != HandoffRefuse {
		t.Fatalf("post-CAS phase without receipt must not enable serving: %+v", d)
	}
}

func TestEvaluateHandoffUsesSamePhasesForFailback(t *testing.T) {
	for name, ids := range map[string][2]uuid.UUID{
		"promotion": {leasePrimary, leaseStandby},
		"failback":  {leaseStandby, leasePrimary},
	} {
		t.Run(name, func(t *testing.T) {
			transition := Promoted
			if name == "failback" {
				transition = FailedBack
			}
			plan := handoffPlan(t, transition, ids[0], ids[1])
			progress := handoffProgress(plan, HandoffAwaitPreparedAck)
			prepared := preparedAck(plan.NewPrepared, leaseNow.Add(-time.Second))
			progress.PreparedAck = &prepared
			assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffDeliverWithdrawal, HandoffAwaitWithdrawal)
			progress.Record.Phase = HandoffAwaitWithdrawal
			progress.WithdrawalAck = withdrawalAck(plan)
			assertHandoffAction(t, EvaluateHandoff(handoffInput(plan, progress)), HandoffRecordCASReady, HandoffCASActive)
		})
	}
}

func assertHandoffAction(t *testing.T, got HandoffDecision, want HandoffAction, phase HandoffPhase) {
	t.Helper()
	if got.Action != want || got.NextPhase != phase {
		t.Fatalf("action=%+v, want action=%q phase=%q", got, want, phase)
	}
}
