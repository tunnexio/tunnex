package nodes

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

func TestRetiredOwnerServingExpiryRequiresEveryIssuedLeaseAndMargin(t *testing.T) {
	now := time.Date(2026, 9, 6, 4, 0, 0, 0, time.UTC)
	boundary, tooRecent, live, zero := now.Add(-time.Second), now.Add(-time.Second+time.Nanosecond), now.Add(time.Second), time.Time{}
	for _, tc := range []struct {
		name   string
		expiry *time.Time
		margin time.Duration
		want   bool
	}{
		{"exact expiry plus margin", &boundary, time.Second, true},
		{"within skew", &tooRecent, time.Second, false},
		{"unexpired issuance", &live, time.Second, false},
		{"no issued serving evidence", nil, time.Second, false},
		{"zero expiry", &zero, time.Second, false},
		{"missing configured margin", &boundary, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retiredOwnerServingAuthorityExpired(tc.expiry, now, tc.margin); got != tc.want {
				t.Fatalf("expired=%t want=%t", got, tc.want)
			}
		})
	}
}

func TestRetiredOwnerCandidateRequiresExactCompleteOrdinaryAcceptance(t *testing.T) {
	scope := k8s.HandoffPoolScope{OrgID: uuid.New(), SiteID: uuid.New(), ClusterID: uuid.New(), PoolID: uuid.MustParse("11111111-1111-4111-8111-111111111111")}
	plan := k8s.HandoffPlan{Scope: scope, CandidateID: uuid.New(), ExpectedActiveID: uuid.New(), ExpectedGeneration: 4}
	wantScope := KubernetesOwnershipPoolScope{OrgID: scope.OrgID.String(), SiteID: scope.SiteID.String(), ClusterID: scope.ClusterID.String(), PoolID: scope.PoolID.String()}
	otherScope := wantScope
	otherScope.PoolID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	fixture := func() loadedKubernetesOwnershipIssueReplay {
		return loadedKubernetesOwnershipIssueReplay{AuthorityKind: "ordinary_base", Acknowledged: true,
			KubernetesOwnershipBaseAuthorityIssueResult: KubernetesOwnershipBaseAuthorityIssueResult{DeliveryID: uuid.New(), Authority: KubernetesOwnershipBaseAuthority{
				WireVersion: 1, AuthorityRevision: 9, NodeID: plan.CandidateID.String(), OrgID: scope.OrgID.String(), SiteID: scope.SiteID.String(), BaseVersion: 20,
				BaseHash: "1111111111111111111111111111111111111111111111111111111111111111",
				Classifications: []KubernetesOwnershipPoolClassification{
					{Scope: wantScope, Disposition: KubernetesOwnershipPoolDispositionMaintainFence, Fields: validKubernetesOwnershipAuthorityFixture().Classifications[0].Fields},
					{Scope: otherScope, Disposition: KubernetesOwnershipPoolDispositionMaintainFence, Fields: validKubernetesOwnershipAuthorityFixture().Classifications[0].Fields},
				},
			}}, Pools: []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: wantScope, PromotionGeneration: 4}, {Scope: otherScope, PromotionGeneration: 2}}}
	}
	for _, name := range []string{"accepted", "pending", "transition", "wrong node", "wrong org", "wrong site", "wrong generation", "missing scope", "later arm classification", "stale accepted revision", "wrong accepted digest"} {
		t.Run(name, func(t *testing.T) {
			value := fixture()
			switch name {
			case "pending":
				value.Acknowledged = false
			case "transition":
				value.AuthorityKind = "transition"
			case "wrong node":
				value.Authority.NodeID = uuid.NewString()
			case "wrong org":
				value.Authority.OrgID = uuid.NewString()
			case "wrong site":
				value.Authority.SiteID = uuid.NewString()
			case "wrong generation":
				value.Pools[0].PromotionGeneration++
			case "missing scope":
				value.Authority.Classifications = value.Authority.Classifications[1:]
				value.Pools = value.Pools[1:]
			case "later arm classification":
				value.Authority.Classifications[1].Disposition = KubernetesOwnershipPoolDispositionArmFence
			}
			_, digest, err := CanonicalKubernetesOwnershipBaseAuthority(value.Authority)
			if err != nil && name != "wrong org" && name != "wrong site" {
				t.Fatal(err)
			}
			value.PayloadDigest = digest
			acceptedRevision, acceptedDigest := int64(9), digest
			if name == "stale accepted revision" {
				acceptedRevision--
			}
			if name == "wrong accepted digest" {
				acceptedDigest = "different"
			}
			if got := retiredOwnerCandidateBaseAccepted(value, plan, acceptedRevision, &acceptedDigest); got != (name == "accepted") {
				t.Fatalf("candidate base accepted=%t", got)
			}
		})
	}
}

func TestRetiredOwnerRenewalProofPostgres(t *testing.T) {
	f, _, completedAt := newCompletedOwnerRenewalFixture(t)
	plan, found, err := f.runtime.source.LoadHandoffBootstrapPlanWithLeadership(f.ctx, completedAt, f.fixture.scope, f.epoch, f.conn)
	if err != nil || !found {
		t.Fatalf("current completed-handoff plan found=%t err=%v", found, err)
	}
	for _, name := range []string{"exact complete proof", "within skew", "zero configured margin", "stale generation", "wrong current owner", "membership changed", "live unACKed serving issuance"} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.conn.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx) //nolint:errcheck
			probe, at, margin := plan, completedAt, time.Second
			switch name {
			case "within skew":
				at = at.Add(-time.Nanosecond)
			case "zero configured margin":
				margin = 0
			case "stale generation":
				probe.Generation--
			case "wrong current owner":
				probe.ActiveNodeID = f.fixture.active
			case "membership changed":
				if _, err := tx.Exec(f.ctx, `UPDATE k8s_connector_pool_health_states SET membership_epoch=membership_epoch+1 WHERE org_id=$1 AND pool_id=$2`, f.fixture.scope.OrgID, f.fixture.scope.PoolID); err != nil {
					t.Fatal(err)
				}
			case "live unACKed serving issuance":
				_, envelope, err := scanPoolVIPOwnershipDeliveryV3(tx.QueryRow(f.ctx, poolVIPOwnershipDeliveryV3Select+` WHERE org_id=$1 AND pool_id=$2 AND target_node_id=$3 AND role='serving' ORDER BY manifest_revision DESC LIMIT 1`, f.fixture.scope.OrgID, f.fixture.scope.PoolID, f.fixture.active))
				if err != nil {
					t.Fatal(err)
				}
				envelope.ExpiresAt = completedAt.Add(time.Minute)
				envelope.Manifest.LeaseExpiresAt = envelope.ExpiresAt
				envelope.ManifestRevision += 100
				envelope.Manifest.ManifestRevision = envelope.ManifestRevision
				deliveryID := uuid.New()
				envelope.DeliveryID, envelope.DeliveryNonce = deliveryID.String(), handoffBootstrapNonce(deliveryID)
				artifact, err := freshArtifactForManifest(envelope.Manifest, k8s.Serving)
				if err != nil {
					t.Fatal(err)
				}
				envelope.ManifestIdentity = artifact.ManifestIdentity
				input, err := preparePoolVIPOwnershipDeliveryV3Issue(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if err := insertPoolVIPOwnershipDeliveryV3Tx(f.ctx, tx, input); err != nil {
					t.Fatalf("valid unACKed issued serving lease: %v", err)
				}
			}
			retired, exempt, err := loadHandoffRetiredOwnerRenewalExemptionTx(f.ctx, tx, probe, at, margin)
			want := name == "exact complete proof"
			if err != nil || exempt != want || (want && retired != f.fixture.active) || (!want && retired != uuid.Nil) {
				t.Fatalf("retired=%s exempt=%t want=%t err=%v", retired, exempt, want, err)
			}
		})
	}
}

func TestRetiredOwnerCandidateRefusesOlderPreparedReceiptPostgres(t *testing.T) {
	f, _, completedAt := newCompletedOwnerRenewalFixture(t)
	plan, found, err := f.runtime.source.LoadHandoffBootstrapPlanWithLeadership(f.ctx, completedAt, f.fixture.scope, f.epoch, f.conn)
	if err != nil || !found {
		t.Fatalf("current plan found=%t err=%v", found, err)
	}
	classification, err := bootstrapBaseClassification(plan)
	if err != nil {
		t.Fatal(err)
	}
	classification.Disposition = KubernetesOwnershipPoolDispositionMaintainFence
	base := f.baseFor(f.fixture.active)
	base.Version++
	issue := func() {
		t.Helper()
		hash, err := KubernetesOwnershipBaseStateHash(base)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.store.IssueKubernetesOwnershipBaseAuthority(f.ctx, KubernetesOwnershipBaseAuthorityIssue{
			Authority: KubernetesOwnershipBaseAuthority{WireVersion: 1, NodeID: base.NodeID, OrgID: f.fixture.scope.OrgID.String(), SiteID: f.fixture.scope.SiteID.String(), BaseVersion: base.Version, BaseHash: hash,
				Classifications: []KubernetesOwnershipPoolClassification{classification}}, OrdinaryBaseUpdate: true,
			Pools: []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: classification.Scope, PromotionGeneration: plan.Generation}}, ExpiresAt: completedAt.Add(5 * time.Minute).UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	reverse := k8s.HandoffPlan{Scope: plan.Scope, ExpectedActiveID: plan.ActiveNodeID, CandidateID: f.fixture.active, ExpectedGeneration: plan.Generation}
	check := func(want bool) {
		t.Helper()
		tx, err := f.conn.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx) //nolint:errcheck
		err = requireRetiredOwnerCandidateBaseTx(f.ctx, tx, reverse)
		if (err == nil) != want || (err != nil && !errors.Is(err, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)) {
			t.Fatalf("candidate admission want=%t err=%v", want, err)
		}
	}
	check(false) // old-generation ordinary ACK is insufficient
	issue()
	check(false)
	f.ackPending(t, f.fixture.active)
	check(true)
	store := NewPostgresPoolVIPOwnershipDeliveryStore(f.pool)
	for _, envelope := range plan.StandbyEnvelopes {
		if envelope.TargetNodeID == f.fixture.active.String() {
			if err := store.IssueHandoffBootstrapEnvelopeWithLeadership(f.ctx, f.epoch, f.conn, envelope); err != nil {
				t.Fatal(err)
			}
			agent := PoolVIPOwnershipAgentIdentity{NodeID: f.fixture.active, OrgID: f.fixture.scope.OrgID}
			ack := ownershipAckV3(envelope)
			if _, err := store.UpdatePoolVIPOwnershipAckV3(f.ctx, agent, ack, f.now, validateOwnershipDeliveryAckV3(agent, ack, f.now)); err != nil {
				t.Fatalf("returned owner accepts exact current-generation preparation: %v", err)
			}
		}
	}
	base.Version++
	base.MTU--
	issue()
	check(false) // still-live current-generation prepared ACK cannot replace this base
	for _, name := range []string{"achieved legacy", "missing transition", "draining", "post CAS"} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.conn.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx) //nolint:errcheck
			switch name {
			case "achieved legacy":
				_, err = tx.Exec(f.ctx, `UPDATE k8s_connector_pool_ha_transitions SET actual_mode='legacy',requested_mode='legacy' WHERE org_id=$1 AND pool_id=$2`, plan.Scope.OrgID, plan.Scope.PoolID)
			case "missing transition":
				_, err = tx.Exec(f.ctx, `DELETE FROM k8s_connector_pool_ha_transitions WHERE org_id=$1 AND pool_id=$2`, plan.Scope.OrgID, plan.Scope.PoolID)
			case "draining":
				_, err = tx.Exec(f.ctx, `UPDATE k8s_connector_pool_ha_transitions SET actual_mode='drain_pending',requested_mode='legacy',achieved_at=NULL WHERE org_id=$1 AND pool_id=$2`, plan.Scope.OrgID, plan.Scope.PoolID)
			case "post CAS":
				// Model the caller's post-CAS snapshot, without inventing any
				// new handoff/ACK proof. The immutable plan still names its
				// pre-CAS owner/generation and the latest base is still pending.
				_, err = tx.Exec(f.ctx, `UPDATE k8s_connector_pools SET active_node_id=$3,generation=generation+1 WHERE org_id=$1 AND id=$2`, plan.Scope.OrgID, plan.Scope.PoolID, reverse.CandidateID)
				if err == nil {
					_, err = tx.Exec(f.ctx, `UPDATE k8s_connector_pool_ha_transitions SET active_node_id=$3,promotion_generation=promotion_generation+1 WHERE org_id=$1 AND pool_id=$2`, plan.Scope.OrgID, plan.Scope.PoolID, reverse.CandidateID)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			err = requireRetiredOwnerCandidateBaseTx(f.ctx, tx, reverse)
			wantAccepted := name == "achieved legacy" || name == "missing transition"
			if (err == nil) != wantAccepted || (err != nil && !errors.Is(err, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused)) {
				t.Fatalf("candidate guard accepted=%t want=%t err=%v", err == nil, wantAccepted, err)
			}
		})
	}
	tx, err := f.conn.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadPoolVIPOwnershipFreshHandoffCapabilities(f.ctx, tx, reverse)
	if !errors.Is(err, ErrPoolVIPOwnershipFreshHandoffProvenanceRefused) {
		t.Fatalf("capability load bypassed pending full base: %v", err)
	}
	if err := tx.Rollback(f.ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Fatal(err)
	}
	f.ackPending(t, f.fixture.active)
	check(true)
}
