package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

func TestBuildFreshHandoffClaimDerivesMonotonicRoleCorrectArtifacts(t *testing.T) {
	now := time.Date(2026, 8, 29, 15, 0, 1, 0, time.UTC)
	old, _ := ownershipDeliveryV3(t)
	active := uuid.MustParse(old.ConnectorNodeID)
	candidate := uuid.MustParse("00000000-0000-4000-8000-000000000009")
	operation := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	old.TargetNodeID = active.String()
	old.Manifest.ConnectorNodeID = active.String()
	old.PromotionGeneration, old.Manifest.PromotionGeneration = 7, 7
	old.ManifestRevision, old.Manifest.ManifestRevision = 11, 11
	old.LeaseEpoch, old.Manifest.LeaseEpoch = 13, 13
	old.ExpiresAt, old.Manifest.LeaseExpiresAt = now.Add(2*time.Minute), now.Add(2*time.Minute)
	refreshFreshHandoffV3Identity(t, &old)

	scope := k8s.HandoffPoolScope{
		OrgID: uuid.MustParse(old.OrgID), SiteID: uuid.MustParse(old.SiteID),
		ClusterID: uuid.MustParse(old.ClusterID), PoolID: uuid.MustParse(old.PoolID),
	}
	epoch := uint64(4)
	intent := HandoffTickIntent{
		OperationID: operation, Scope: scope, ObservedMembershipEpoch: &epoch,
		ExpectedActiveID: active, CandidateID: candidate, ExpectedGeneration: 7, TargetGeneration: 8,
		Decision: k8s.Decision{
			Transition: k8s.Promoted, FromID: active.String(), ToID: candidate.String(),
			Pool: k8s.ConnectorPool{ActiveID: candidate.String(), Generation: 8},
		},
		OrderedCandidateIDs: []uuid.UUID{active, candidate},
	}
	topology := handoffBootstrapTopology{
		Scope: scope, Generation: 7, ActiveNodeID: active,
		Members:  []handoffBootstrapMember{{NodeID: active}, {NodeID: candidate}},
		Services: []handoffBootstrapService{{Namespace: "default", Name: "api", UID: "uid-api", ObservationRevision: 9}},
	}
	tx := &freshClaimReadTx{
		old: old,
		counters: map[uuid.UUID]handoffBootstrapCounter{
			active:    {ManifestRevision: 11, LeaseEpoch: 13},
			candidate: {ManifestRevision: 20, LeaseEpoch: 21},
		},
	}

	claim, err := buildFreshHandoffClaim(t.Context(), tx, now, topology, intent)
	if err != nil {
		t.Fatalf("build fresh claim: %v", err)
	}
	if err := k8s.ValidateDurableHandoffPlan(claim.Plan); err != nil {
		t.Fatalf("fresh durable plan invalid: %v", err)
	}
	p := claim.Plan.Plan
	if p.ExpectedGeneration != 7 || p.TargetGeneration != 8 || p.OldServing.ManifestRevision != 11 ||
		p.OldWithdrawal.ManifestRevision != 12 || p.NewPrepared.ManifestRevision != 21 || p.NewServing.ManifestRevision != 22 {
		t.Fatalf("generation/revision topology=%+v", p)
	}
	if p.NewPrepared.Lease.Epoch != 22 || p.OldWithdrawal.Lease.Epoch != 22 || p.NewServing.Lease.Epoch != 22 {
		t.Fatalf("target lease epoch must be max prior epoch + 1: prepared=%d withdrawal=%d serving=%d",
			p.NewPrepared.Lease.Epoch, p.OldWithdrawal.Lease.Epoch, p.NewServing.Lease.Epoch)
	}
	if len(claim.Artifacts) != 4 {
		t.Fatalf("artifact count=%d, want 4", len(claim.Artifacts))
	}
	roles := map[k8s.P2HandoffArtifact]string{}
	for _, artifact := range claim.Artifacts {
		roles[artifact.Which] = artifact.Envelope.Role
		if err := ValidatePoolVIPOwnershipDeliveryEnvelopeV3(artifact.Envelope); err != nil {
			t.Fatalf("%s envelope invalid: %v", artifact.Which, err)
		}
	}
	for _, which := range []k8s.P2HandoffArtifact{k8s.P2NewPreparedArtifact, k8s.P2OldWithdrawalArtifact} {
		for _, artifact := range claim.Artifacts {
			if artifact.Which == which && artifact.Envelope.Manifest.WGPeers == nil {
				t.Fatalf("%s must encode canonical empty wg_peers array, not null", which)
			}
		}
	}
	if roles[k8s.P2OldServingArtifact] != policyspec.PoolVIPOwnershipServing ||
		roles[k8s.P2NewPreparedArtifact] != policyspec.PoolVIPOwnershipPreparedNonServing ||
		roles[k8s.P2OldWithdrawalArtifact] != policyspec.PoolVIPOwnershipWithdrawal ||
		roles[k8s.P2NewServingArtifact] != policyspec.PoolVIPOwnershipServing {
		t.Fatalf("artifact roles=%v", roles)
	}
	if len(claim.ServiceUIDs) != 1 || claim.ServiceUIDs[0].ActiveNodeID != active || claim.ServiceUIDs[0].PromotionGeneration != 7 {
		t.Fatalf("service UID provenance=%+v", claim.ServiceUIDs)
	}
}

func TestClonePoolVIPOwnershipDeliveryEnvelopeV3PreservesCanonicalEmptyWGPeers(t *testing.T) {
	in := PoolVIPOwnershipDeliveryEnvelopeV3{Manifest: PoolVIPOwnershipManifestV3{WGPeers: []PoolVIPOwnershipWGPeerV3{}}}
	got := clonePoolVIPOwnershipDeliveryEnvelopeV3(in)
	if got.Manifest.WGPeers == nil || len(got.Manifest.WGPeers) != 0 {
		t.Fatalf("canonical empty wg_peers became null: %#v", got.Manifest.WGPeers)
	}
}

func TestHandoffFencedLeaseRenewalReissuesOwnerAndEveryStandby(t *testing.T) {
	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	plan := handoffBootstrapPlan(t, now)
	fake := &handoffBootstrapFake{plan: plan, found: true}
	runtime := &HandoffHAActivationRuntime{source: fake, issuer: fake}
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 51, LockKey: leader.SchedulerLockKey}
	conn := &pgxpool.Conn{}

	if err := runtime.reconcileFencedLease(t.Context(), now, epoch, conn, plan.Scope); err != nil {
		t.Fatalf("renew fenced lease: %v", err)
	}
	want := 1 + len(plan.StandbyEnvelopes)
	if fake.issueCalls != want || len(fake.issued) != want {
		t.Fatalf("issued=%d/%d, want owner plus every standby (%d)", fake.issueCalls, len(fake.issued), want)
	}
	if !reflect.DeepEqual(fake.issued[:len(plan.StandbyEnvelopes)], plan.StandbyEnvelopes) || !reflect.DeepEqual(fake.issued[len(fake.issued)-1], plan.CurrentOwnerEnvelope) {
		t.Fatal("renewal must issue exact prepared standbys before refreshing serving authority")
	}
	if fake.lastEpoch != epoch || fake.lastConn != conn {
		t.Fatalf("renewal escaped exact leader session: epoch=%+v conn=%p", fake.lastEpoch, fake.lastConn)
	}
}

func TestHandoffFencedLeaseRenewalMissingPlanIsInertAndIssueFailureStops(t *testing.T) {
	now := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)
	epoch := k8s.HandoffLeadershipEpoch{BackendPID: 52, LockKey: leader.SchedulerLockKey}
	conn := &pgxpool.Conn{}
	scope := handoffBootstrapPlan(t, now).Scope

	missing := &handoffBootstrapFake{}
	if err := (&HandoffHAActivationRuntime{source: missing, issuer: missing}).reconcileFencedLease(t.Context(), now, epoch, conn, scope); err != nil || missing.issueCalls != 0 {
		t.Fatalf("missing source plan must be inert: err=%v issues=%d", err, missing.issueCalls)
	}

	plan := handoffBootstrapPlan(t, now)
	failing := &handoffBootstrapFake{plan: plan, found: true, issueFailAt: 2}
	err := (&HandoffHAActivationRuntime{source: failing, issuer: failing}).reconcileFencedLease(t.Context(), now, epoch, conn, scope)
	if !errors.Is(err, ErrHandoffBootstrapLeaderSession) || failing.issueCalls != 2 {
		t.Fatalf("issue failure must stop the renewal batch: err=%v issues=%d", err, failing.issueCalls)
	}
	for _, issued := range failing.issued {
		if issued.Role == policyspec.PoolVIPOwnershipServing {
			t.Fatal("partial standby renewal must never refresh serving authority")
		}
	}
}

func TestHandoffBootstrapIDsBindEveryDataplaneTopologyInput(t *testing.T) {
	base, expires := handoffBootstrapTopologyForTest()
	want, err := buildHandoffBootstrapPlan(base, expires)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*handoffBootstrapTopology){
		"service VIP": func(v *handoffBootstrapTopology) { v.Services[0].VIP = "100.64.0.11" },
		"service port": func(v *handoffBootstrapTopology) {
			port := int32(8443)
			v.Services[0].PortLow, v.Services[0].PortHigh = &port, &port
		},
		"service protocol": func(v *handoffBootstrapTopology) { v.Services[0].Protocol = "udp" },
		"DNS VIP":          func(v *handoffBootstrapTopology) { v.DNSVIP = "100.64.0.3" },
		"DNS zone":         func(v *handoffBootstrapTopology) { v.DNSZone = "new.k8s.example" },
		"member endpoint":  func(v *handoffBootstrapTopology) { v.Members[1].Endpoint = "10.0.0.22:51820" },
		"member WG key": func(v *handoffBootstrapTopology) {
			v.Members[1].WGPublicKey = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cloneHandoffBootstrapTopology(base)
			mutate(&candidate)
			got, err := buildHandoffBootstrapPlan(candidate, expires)
			if err != nil {
				t.Fatalf("build changed topology: %v", err)
			}
			if got.CurrentOwnerEnvelope.OperationID == want.CurrentOwnerEnvelope.OperationID {
				t.Fatal("bootstrap operation ID did not bind the changed topology")
			}
			wantDeliveries := bootstrapDeliveryIDsByNode(want)
			gotDeliveries := bootstrapDeliveryIDsByNode(got)
			if len(gotDeliveries) != len(wantDeliveries) {
				t.Fatalf("delivery membership changed: got=%v want=%v", gotDeliveries, wantDeliveries)
			}
			for node, wantID := range wantDeliveries {
				if gotDeliveries[node] == wantID {
					t.Fatalf("delivery ID for node %s did not bind the changed topology", node)
				}
			}
		})
	}
}

func TestHandoffBootstrapIDsIgnoreObservationRevisionButBindServiceUID(t *testing.T) {
	base, expires := handoffBootstrapTopologyForTest()
	want, err := buildHandoffBootstrapPlan(base, expires)
	if err != nil {
		t.Fatal(err)
	}

	reobserved := cloneHandoffBootstrapTopology(base)
	reobserved.Services[0].ObservationRevision++
	stable, err := buildHandoffBootstrapPlan(reobserved, expires)
	if err != nil {
		t.Fatalf("build identical re-observation: %v", err)
	}
	if stable.CurrentOwnerEnvelope.OperationID != want.CurrentOwnerEnvelope.OperationID ||
		!reflect.DeepEqual(bootstrapDeliveryIDsByNode(stable), bootstrapDeliveryIDsByNode(want)) {
		t.Fatalf("observation cursor churned authority IDs: operation=%s/%s deliveries=%v/%v",
			stable.CurrentOwnerEnvelope.OperationID, want.CurrentOwnerEnvelope.OperationID,
			bootstrapDeliveryIDsByNode(stable), bootstrapDeliveryIDsByNode(want))
	}

	recreated := cloneHandoffBootstrapTopology(base)
	recreated.Services[0].UID = "uid-api-v2"
	changed, err := buildHandoffBootstrapPlan(recreated, expires)
	if err != nil {
		t.Fatalf("build recreated Service: %v", err)
	}
	if changed.CurrentOwnerEnvelope.OperationID == want.CurrentOwnerEnvelope.OperationID {
		t.Fatal("Service UID incarnation did not rotate the bootstrap operation ID")
	}
	wantDeliveries := bootstrapDeliveryIDsByNode(want)
	for node, gotID := range bootstrapDeliveryIDsByNode(changed) {
		if gotID == wantDeliveries[node] {
			t.Fatalf("Service UID incarnation did not rotate delivery ID for node %s", node)
		}
	}
}

func bootstrapDeliveryIDsByNode(plan HandoffBootstrapPlan) map[string]string {
	out := map[string]string{plan.CurrentOwnerEnvelope.TargetNodeID: plan.CurrentOwnerEnvelope.DeliveryID}
	for _, envelope := range plan.StandbyEnvelopes {
		out[envelope.TargetNodeID] = envelope.DeliveryID
	}
	return out
}

type freshClaimReadTx struct {
	old      PoolVIPOwnershipDeliveryEnvelopeV3
	counters map[uuid.UUID]handoffBootstrapCounter
}

func (tx *freshClaimReadTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if len(args) == 6 {
		raw, _ := json.Marshal(tx.old.Manifest)
		return reflectionRow{values: []any{
			uuid.New(), tx.old.Version, tx.old.OrgID, tx.old.SiteID, tx.old.ClusterID, tx.old.PoolID,
			tx.old.ConnectorNodeID, tx.old.TargetNodeID, tx.old.OperationID, tx.old.ManifestIdentity, tx.old.Role,
			int64(tx.old.PromotionGeneration), int64(tx.old.ManifestRevision), int64(tx.old.LeaseEpoch), tx.old.DeliveryPhase,
			tx.old.DeliveryID, tx.old.DeliveryNonce, tx.old.ExpectedRouteDigest, tx.old.ExpectedVIPMapDigest,
			int64(tx.old.PriorLeaseEpoch), tx.old.ExpiresAt, raw,
		}}
	}
	if len(args) == 5 {
		node, _ := args[4].(uuid.UUID)
		counter, ok := tx.counters[node]
		if !ok {
			return reflectionRow{err: pgx.ErrNoRows}
		}
		return reflectionRow{values: []any{int64(counter.ManifestRevision), int64(counter.LeaseEpoch)}}
	}
	return reflectionRow{err: errors.New("unexpected fresh-claim query: " + sql)}
}

func (tx *freshClaimReadTx) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("unexpected Begin")
}
func (tx *freshClaimReadTx) Commit(context.Context) error   { return errors.New("unexpected Commit") }
func (tx *freshClaimReadTx) Rollback(context.Context) error { return errors.New("unexpected Rollback") }
func (tx *freshClaimReadTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("unexpected CopyFrom")
}
func (tx *freshClaimReadTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { return nil }
func (tx *freshClaimReadTx) LargeObjects() pgx.LargeObjects                         { return pgx.LargeObjects{} }
func (tx *freshClaimReadTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("unexpected Prepare")
}
func (tx *freshClaimReadTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec")
}
func (tx *freshClaimReadTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}
func (tx *freshClaimReadTx) Conn() *pgx.Conn { return nil }

type reflectionRow struct {
	values []any
	err    error
}

func (r reflectionRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return errors.New("unexpected scan width")
	}
	for i := range dest {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(r.values[i]))
	}
	return nil
}
