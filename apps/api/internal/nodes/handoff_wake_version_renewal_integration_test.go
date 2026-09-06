package nodes

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

const wakeVersionRenewalLeaseTTL = time.Minute

// This is the acceptance regression, not a claim that a missing initial ACK
// is safe. Every member first accepts the exact armed and ordinary full base.
// Only then does one standby stop acknowledging while notification versions
// advance. Real PostgreSQL maintenance, authority issuance and lease issuance
// run here; the source seam controls only the ordinary base and wake cursor.
func TestHandoffWakeVersionChurnPreservesServingRenewal(t *testing.T) {
	f := newWakeVersionRenewalFixture(t)
	beforeHash, err := KubernetesOwnershipBaseStateHash(f.baseFor(f.fixture.active))
	if err != nil {
		t.Fatal(err)
	}
	beforeAuthorities := f.authorityCount(t)
	beforeLease := f.servingExpiry(t)
	for wake := 1; wake <= 3; wake++ {
		f.base.Version++
		hash, err := KubernetesOwnershipBaseStateHash(f.baseFor(f.fixture.active))
		if err != nil || hash != beforeHash {
			t.Fatalf("wake-only fixture changed canonical base: hash=%q err=%v", hash, err)
		}
		// The plan source buckets lease expiry by TTL. Cross a complete bucket
		// per wake so a real renewal is observable without sleeping.
		f.reconcile(t, f.now.Add(time.Duration(wake)*wakeVersionRenewalLeaseTTL))
		// The absent standby never ACKs again. The active and remaining standby
		// still respond normally, so the only missing proof is of unchanged bytes.
		f.ackPending(t, f.fixture.active, f.fixture.standbyB)
		if got := f.authorityCount(t); got != beforeAuthorities {
			t.Errorf("wake %d minted full-base authority for unchanged bytes: before=%d after=%d", wake, beforeAuthorities, got)
		}
		if got := f.servingExpiry(t); !got.After(beforeLease) {
			t.Errorf("wake %d suppressed serving renewal with only an unchanged-base standby ACK missing: expiry=%s initial=%s", wake, got.Format(time.RFC3339Nano), beforeLease.Format(time.RFC3339Nano))
		} else {
			beforeLease = got
		}
	}
}

// A content change is deliberately not equivalent to a wake. One absent
// standby must still hold the scope-complete barrier even after the owner and
// every other standby ACK, and its eventual exact ACK must release that barrier.
func TestHandoffChangedBaseStillRequiresEveryMemberACK(t *testing.T) {
	f := newWakeVersionRenewalFixture(t)
	// Even with retired-owner proof enabled, an ordinary missing standby ACK
	// without a completed handoff must retain the full-member barrier.
	f.runtime.transition.(*PostgresHandoffOwnershipModeTransition).config.ClockSkewMargin = time.Second
	beforeHash, err := KubernetesOwnershipBaseStateHash(f.baseFor(f.fixture.active))
	if err != nil {
		t.Fatal(err)
	}
	beforeAuthorities := f.authorityCount(t)
	beforeLease := f.servingExpiry(t)
	f.base.Version++
	f.base.MTU--
	changedHash, err := KubernetesOwnershipBaseStateHash(f.baseFor(f.fixture.active))
	if err != nil || changedHash == beforeHash {
		t.Fatalf("content-change fixture did not change canonical base: hash=%q err=%v", changedHash, err)
	}
	f.reconcile(t, f.now.Add(wakeVersionRenewalLeaseTTL))
	if got := f.authorityCount(t); got != beforeAuthorities+3 {
		t.Fatalf("changed full base did not issue an exact authority per member: before=%d after=%d", beforeAuthorities, got)
	}
	f.ackPending(t, f.fixture.active, f.fixture.standbyB)
	f.reconcile(t, f.now.Add(2*wakeVersionRenewalLeaseTTL))
	if got := f.servingExpiry(t); !got.Equal(beforeLease) {
		t.Fatalf("one unACKed member failed to gate changed-base serving renewal: before=%s after=%s", beforeLease, got)
	}
	if got := f.authorityCount(t); got != beforeAuthorities+3 {
		t.Fatalf("same changed base was not replayed while waiting for exact ACK: authorities=%d", got)
	}
	f.ackPending(t, f.fixture.standbyA)
	f.reconcile(t, f.now.Add(3*wakeVersionRenewalLeaseTTL))
	if got := f.servingExpiry(t); !got.After(beforeLease) {
		t.Fatalf("every exact changed-base ACK did not release serving renewal: before=%s after=%s", beforeLease, got)
	}
}

func TestHandoffAcknowledgedBaseReuseStoreBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name          string
		latestKind    string
		mutate        func(*KubernetesOwnershipBaseAuthorityIssue)
		wantDuplicate bool
		wantConflict  bool
	}{
		{name: "ACKed ordinary wake only", wantDuplicate: true},
		{name: "different full base hash", mutate: func(issue *KubernetesOwnershipBaseAuthorityIssue) {
			issue.Authority.BaseHash = strings.Repeat("b", 64)
		}},
		{name: "different classification fields", mutate: func(issue *KubernetesOwnershipBaseAuthorityIssue) {
			issue.Authority.Classifications[0].Fields.VIPMappings[0].PortLow++
			issue.Authority.Classifications[0].Fields.VIPMappings[0].PortHigh++
		}},
		{name: "different pool promotion generation", mutate: func(issue *KubernetesOwnershipBaseAuthorityIssue) {
			issue.Pools[0].PromotionGeneration++
		}},
		{name: "unACKed ordinary wake remains exact", latestKind: "pending"},
		{name: "older ACK behind pending delivery is not reused", latestKind: "pending", mutate: func(issue *KubernetesOwnershipBaseAuthorityIssue) {
			// Restore the original accepted bytes, not the latest pending bytes.
			base := DesiredState{ProtocolVersion: 9, NodeID: issue.Authority.NodeID, InterfaceAddress: "10.44.0.1/16", MTU: 1420, ListenPort: 51820, Peers: []Peer{}}
			issue.Authority.BaseHash, _ = KubernetesOwnershipBaseStateHash(base)
		}},
		{name: "ACKed transition replay remains exact", latestKind: "transition", wantConflict: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Each case owns a distinct database and genuinely accepted baseline;
			// no earlier table case can supply a historical receipt accidentally.
			f := newWakeVersionRenewalFixture(t)
			var payload []byte
			var first KubernetesOwnershipBaseAuthorityIssueResult
			var expires time.Time
			if err := f.pool.QueryRow(f.ctx, `SELECT id,payload,payload_digest,expires_at
				FROM k8s_base_authority_deliveries WHERE org_id=$1 AND node_id=$2
				ORDER BY authority_revision DESC LIMIT 1`, f.fixture.scope.OrgID, f.fixture.active).
				Scan(&first.DeliveryID, &payload, &first.PayloadDigest, &expires); err != nil {
				t.Fatal(err)
			}
			var err error
			first.Authority, _, err = decodeKubernetesOwnershipBaseAuthorityPayload(payload)
			if err != nil {
				t.Fatal(err)
			}
			issue := KubernetesOwnershipBaseAuthorityIssue{Authority: first.Authority, OrdinaryBaseUpdate: true, ExpiresAt: expires.UTC(),
				Pools: []KubernetesOwnershipBaseAuthorityPoolGeneration{{Scope: first.Authority.Classifications[0].Scope, PromotionGeneration: 1}}}
			issue.Authority.AuthorityRevision = 0
			if tc.latestKind == "pending" {
				issue.Authority.BaseVersion++
				issue.Authority.BaseHash = strings.Repeat("c", 64)
				first, err = f.store.IssueKubernetesOwnershipBaseAuthority(f.ctx, issue)
			} else if tc.latestKind == "transition" {
				issue.OrdinaryBaseUpdate, issue.TransitionRevision = false, 2
				first, err = f.store.IssueKubernetesOwnershipBaseAuthority(f.ctx, issue)
				if err == nil {
					f.ackPending(t, f.fixture.active)
				}
			}
			if err != nil {
				t.Fatalf("establish exact latest authority: %v", err)
			}
			var actualKind string
			var acknowledged bool
			if err := f.pool.QueryRow(f.ctx, `SELECT d.authority_kind,r.delivery_id IS NOT NULL
				FROM k8s_base_authority_deliveries d LEFT JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id
				WHERE d.id=$1 AND d.org_id=$2`, first.DeliveryID, f.fixture.scope.OrgID).Scan(&actualKind, &acknowledged); err != nil {
				t.Fatal(err)
			}
			wantKind := "ordinary_base"
			if tc.latestKind == "transition" {
				wantKind = "transition"
			}
			if actualKind != wantKind || acknowledged != (tc.latestKind != "pending") {
				t.Fatalf("incorrect latest-authority fixture: kind=%q acknowledged=%t", actualKind, acknowledged)
			}
			beforeCount := f.authorityCount(t)
			beforeEvidence := f.authorityEvidence(t, first.DeliveryID)
			issue.Authority.BaseVersion++
			if tc.mutate != nil {
				tc.mutate(&issue)
			}
			got, err := f.store.IssueKubernetesOwnershipBaseAuthority(f.ctx, issue)
			if tc.wantConflict {
				if !errors.Is(err, ErrKubernetesOwnershipBaseAuthorityConflict) || got.DeliveryID != uuid.Nil || f.authorityCount(t) != beforeCount {
					t.Fatalf("transition version mismatch must conflict without a write: result=%+v err=%v", got, err)
				}
			} else if err != nil {
				t.Fatalf("ordinary authority issue: %v", err)
			} else if tc.wantDuplicate {
				if !got.Duplicate || got.DeliveryID != first.DeliveryID || got.PayloadDigest != first.PayloadDigest ||
					got.Authority.AuthorityRevision != first.Authority.AuthorityRevision || got.Authority.BaseVersion != first.Authority.BaseVersion ||
					f.authorityCount(t) != beforeCount {
					t.Fatalf("wake-only replay did not preserve immutable authority: first=%+v got=%+v", first, got)
				}
			} else if got.Duplicate || got.DeliveryID == first.DeliveryID || got.PayloadDigest == first.PayloadDigest ||
				got.Authority.AuthorityRevision != first.Authority.AuthorityRevision+1 || got.Authority.BaseVersion != issue.Authority.BaseVersion ||
				f.authorityCount(t) != beforeCount+1 {
				t.Fatalf("changed or unACKed authority incorrectly reused a receipt: first=%+v got=%+v", first, got)
			}
			if after := f.authorityEvidence(t, first.DeliveryID); after != beforeEvidence {
				t.Fatal("issuing or reusing authority rewrote the prior delivery/receipt evidence")
			}
		})
	}
}

type wakeVersionRenewalFixture struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	conn    *pgxpool.Conn
	epoch   k8s.HandoffLeadershipEpoch
	fixture handoffBootstrapIntegrationFixture
	base    DesiredState
	now     time.Time
	store   *PostgresKubernetesOwnershipBaseAuthorityStore
	runtime *HandoffHAActivationRuntime
}

func newWakeVersionRenewalFixture(t *testing.T) *wakeVersionRenewalFixture {
	t.Helper()
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run the wake-version renewal PostgreSQL regression")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	pool := newHandoffEndToEndTestDB(t, ctx, admin)
	fixture := seedHandoffBootstrapIntegration(t, ctx, pool)
	if err := db.Up(pool.Config().ConnString()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO k8s_connector_pool_health_states
			(org_id,site_id,cluster_id,pool_id,membership_epoch,observed_active_node_id,observed_generation)
			VALUES($1,$2,$3,$4,0,$5,1)`, []any{fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.scope.PoolID, fixture.active}},
		{`INSERT INTO k8s_ha_settings(org_id,enabled,actor_system,cause)
			VALUES($1,true,'test','wake-only renewal regression')`, []any{fixture.scope.OrgID}},
		{`INSERT INTO k8s_connector_pool_ha_transitions
			(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,actor_system,cause)
			VALUES($1,$2,$3,$4,'fenced_ha','bootstrap_pending',$5,1,0,'test','wake-only renewal regression')`,
			[]any{fixture.scope.PoolID, fixture.scope.OrgID, fixture.scope.SiteID, fixture.scope.ClusterID, fixture.active}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Release)
	var pid int32
	var granted bool
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid(),pg_try_advisory_lock($1)`, leader.SchedulerLockKey).Scan(&pid, &granted); err != nil || !granted {
		t.Fatalf("exact leader session granted=%t err=%v", granted, err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, leader.SchedulerLockKey); err != nil {
			t.Errorf("release fixture leader lock: %v", err)
		}
	})
	f := &wakeVersionRenewalFixture{ctx: ctx, pool: pool, conn: conn, fixture: fixture,
		epoch: k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: leader.SchedulerLockKey},
		now:   time.Now().UTC().Truncate(time.Microsecond),
		base:  DesiredState{ProtocolVersion: 9, InterfaceAddress: "10.44.0.1/16", MTU: 1420, ListenPort: 51820, Version: 17, Peers: []Peer{}},
		store: NewPostgresKubernetesOwnershipBaseAuthorityStore(pool)}
	base := HandoffBaseStateSourceFunc(func(_ context.Context, orgID, nodeID uuid.UUID) (DesiredState, error) {
		if orgID != fixture.scope.OrgID {
			t.Fatal("base compiler escaped fixture organization")
		}
		return f.baseFor(nodeID), nil
	})
	transition, err := NewPostgresHandoffOwnershipModeTransition(pool, base, f.store, HandoffHATransitionConfig{MaxAckAge: time.Minute, AuthorityTTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	source := NewPostgresHandoffBootstrapPlanSource(pool, HandoffBootstrapPlanSourceConfig{LeaseTTL: wakeVersionRenewalLeaseTTL})
	plan, found, err := source.LoadHandoffBootstrapPlanWithLeadership(ctx, f.now, fixture.scope, f.epoch, conn)
	if err != nil || !found {
		t.Fatalf("bootstrap plan found=%t err=%v", found, err)
	}
	snapshot, ready, err := transition.ArmHandoffOwnershipBaseWithLeadership(ctx, f.now, f.epoch, conn, plan)
	if err != nil || ready || len(snapshot.Members) != 3 {
		t.Fatalf("initial arm ready=%t members=%d err=%v", ready, len(snapshot.Members), err)
	}
	f.ackPending(t, fixture.active, fixture.standbyA, fixture.standbyB)
	snapshot, ready, err = transition.ArmHandoffOwnershipBaseWithLeadership(ctx, f.now, f.epoch, conn, plan)
	if err != nil || !ready {
		t.Fatalf("arm exact ACK barrier ready=%t err=%v", ready, err)
	}
	deliveryStore := NewPostgresPoolVIPOwnershipDeliveryStore(pool)
	for _, envelope := range append([]PoolVIPOwnershipDeliveryEnvelopeV3{plan.CurrentOwnerEnvelope}, plan.StandbyEnvelopes...) {
		if err := deliveryStore.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, f.epoch, conn, envelope); err != nil {
			t.Fatal(err)
		}
		agent := PoolVIPOwnershipAgentIdentity{NodeID: uuid.MustParse(envelope.TargetNodeID), OrgID: fixture.scope.OrgID}
		ack := ownershipAckV3(envelope)
		if _, err := deliveryStore.UpdatePoolVIPOwnershipAckV3(ctx, agent, ack, f.now, validateOwnershipDeliveryAckV3(agent, ack, f.now)); err != nil {
			t.Fatal(err)
		}
	}
	if prerequisite, err := transition.ConfirmHandoffOwnershipModeTransitionWithLeadership(ctx, f.now, f.epoch, conn, plan, snapshot); err != nil || prerequisite != HandoffFencedBaseReady {
		t.Fatalf("activate exact fenced base prerequisite=%q err=%v", prerequisite, err)
	}
	f.runtime = &HandoffHAActivationRuntime{source: source, issuer: deliveryStore, transition: transition}
	// Bootstrap arm -> steady maintain_fence is a genuine authority change.
	// Complete it before silencing a standby; this regression never skips it.
	f.reconcile(t, f.now)
	f.ackPending(t, fixture.active, fixture.standbyA, fixture.standbyB)
	f.reconcile(t, f.now)
	return f
}

func (f *wakeVersionRenewalFixture) baseFor(nodeID uuid.UUID) DesiredState {
	base := f.base
	base.NodeID = nodeID.String()
	return base
}

func (f *wakeVersionRenewalFixture) reconcile(t *testing.T, now time.Time) {
	t.Helper()
	if err := f.runtime.reconcileFencedPools(f.ctx, now, f.epoch, f.conn, []k8s.HandoffPoolScope{f.fixture.scope}); err != nil {
		t.Fatalf("fenced renewal: %v", err)
	}
}

func (f *wakeVersionRenewalFixture) ackPending(t *testing.T, nodes ...uuid.UUID) {
	t.Helper()
	for _, nodeID := range nodes {
		agent := KubernetesOwnershipBaseAuthorityAgentIdentity{NodeID: nodeID, OrgID: f.fixture.scope.OrgID, SiteID: f.fixture.scope.SiteID}
		pending, found, err := f.store.LoadPendingKubernetesOwnershipBaseAuthority(f.ctx, agent)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			continue
		}
		_, digest, err := CanonicalKubernetesOwnershipBaseAuthority(pending)
		if err != nil {
			t.Fatal(err)
		}
		ack := KubernetesOwnershipBaseAuthorityAck{WireVersion: 1, AuthorityRevision: pending.AuthorityRevision,
			NodeID: pending.NodeID, OrgID: pending.OrgID, SiteID: pending.SiteID, BaseVersion: pending.BaseVersion,
			BaseHash: pending.BaseHash, AuthorityDigest: digest, AppliedAt: f.now.Format(time.RFC3339Nano)}
		if _, err := f.store.AcknowledgeKubernetesOwnershipBaseAuthority(f.ctx, agent, ack, f.now); err != nil {
			t.Fatalf("exact full-base ACK: %v", err)
		}
	}
}

func (f *wakeVersionRenewalFixture) authorityCount(t *testing.T) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM k8s_base_authority_deliveries WHERE org_id=$1`, f.fixture.scope.OrgID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func (f *wakeVersionRenewalFixture) authorityEvidence(t *testing.T, deliveryID uuid.UUID) string {
	t.Helper()
	var evidence string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('delivery',to_jsonb(d),'receipt',to_jsonb(r))::text
		FROM k8s_base_authority_deliveries d LEFT JOIN k8s_base_authority_ack_receipts r ON r.delivery_id=d.id
		WHERE d.org_id=$1 AND d.id=$2`, f.fixture.scope.OrgID, deliveryID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func (f *wakeVersionRenewalFixture) servingExpiry(t *testing.T) time.Time {
	t.Helper()
	var expires time.Time
	if err := f.pool.QueryRow(f.ctx, `SELECT max(expires_at) FROM pool_vip_ownership_deliveries
		WHERE org_id=$1 AND pool_id=$2 AND target_node_id=$3 AND wire_version=3 AND role='serving'`, f.fixture.scope.OrgID, f.fixture.scope.PoolID, f.fixture.active).Scan(&expires); err != nil {
		t.Fatal(err)
	}
	return expires
}
