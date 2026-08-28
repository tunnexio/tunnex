package nodes

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
)

// TestHandoffSchedulerEndToEndPostgresHarness is an unregistered, test-only
// composition of the production-shaped read/observe/coordinator seams. The
// P2 store is deliberately in memory: it models exact durable identities and
// v3 applied attestations but does not copy, call, or register P2 transport.
func TestHandoffSchedulerEndToEndPostgresHarness(t *testing.T) {
	admin := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run PostgreSQL end-to-end handoff scheduler proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p := newHandoffProductionSchedulerTestDB(t, ctx, admin)

	t.Run("complete failover resumes every durable phase with exact P2 identities", func(t *testing.T) {
		h := newHandoffEndToEndHarness(t, ctx, p, "complete", false)
		h.p2.failAfterRecord[k8s.P2HandoffPrepared] = 1
		for tick := 0; tick < k8s.PromoteAfterStaleTicks; tick++ {
			result := h.tick(ctx)
			if tick < k8s.PromoteAfterStaleTicks-1 && (result.Attempted != 0 || result.RunnerError != nil) {
				t.Fatalf("pre-threshold tick=%d result=%+v", tick+1, result)
			}
		}
		h.phase(t, ctx, k8s.HandoffPrepareCandidate)
		h.assertPoolAudit(t, ctx, h.fixture.active, 1, 0)
		prepared := h.p2.only(k8s.P2HandoffPrepared)

		// Crash after delivery before its expected-phase CAS: a fresh scheduler
		// replays the same operation-keyed identity and only then advances.
		h.restart()
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffAwaitPreparedAck)
		h.p2.assertExactOnly(t, k8s.P2HandoffPrepared, prepared)
		h.restart()
		h.tickOK(t, ctx) // checkpoint at await_prepared_ack: no acknowledgement, no work.
		h.phase(t, ctx, k8s.HandoffAwaitPreparedAck)

		h.p2.attest(t, prepared, time.Now().UTC())
		h.p2.failAfterRecord[k8s.P2HandoffWithdrawal] = 1
		if result := h.tick(ctx); result.RunnerError == nil {
			t.Fatalf("withdrawal delivery crash was hidden: %+v", result)
		}
		h.phase(t, ctx, k8s.HandoffAwaitPreparedAck)
		withdrawal := h.p2.only(k8s.P2HandoffWithdrawal)
		h.restart()
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffAwaitWithdrawal)
		h.p2.assertExactOnly(t, k8s.P2HandoffWithdrawal, withdrawal)
		h.restart()
		h.tickOK(t, ctx) // checkpoint at await_withdrawal: no old-owner proof yet.
		h.phase(t, ctx, k8s.HandoffAwaitWithdrawal)

		h.p2.attest(t, withdrawal, time.Now().UTC())
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffCASActive)
		h.assertPoolAudit(t, ctx, h.fixture.active, 1, 0)

		h.restart()
		h.tickOK(t, ctx) // checkpoint at cas_active: one atomic pool CAS + audit.
		h.phase(t, ctx, k8s.HandoffEnableServing)
		h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)

		h.p2.failAfterRecord[k8s.P2HandoffServing] = 1
		if result := h.tick(ctx); result.RunnerError == nil {
			t.Fatalf("serving delivery crash was hidden: %+v", result)
		}
		h.phase(t, ctx, k8s.HandoffEnableServing)
		serving := h.p2.only(k8s.P2HandoffServing)
		h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
		h.restart()
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffAwaitServingAck)
		h.p2.assertExactOnly(t, k8s.P2HandoffServing, serving)
		h.restart()
		h.tickOK(t, ctx) // checkpoint at await_serving_ack: no serving attestation, no finalize.
		h.phase(t, ctx, k8s.HandoffAwaitServingAck)

		h.p2.attest(t, serving, time.Now().UTC())
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffFinalize)
		h.restart()
		h.tickOK(t, ctx) // checkpoint at finalize completes without another CAS/audit.
		h.phase(t, ctx, k8s.HandoffComplete)
		h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
		if got := h.p2.uniqueCount(); got != 3 {
			t.Fatalf("unique P2 delivery identities=%d, want prepare/withdraw/serve", got)
		}

		h.restart()
		h.tickOK(t, ctx) // terminal operation never reopens or reissues delivery.
		if got := h.p2.uniqueCount(); got != 3 {
			t.Fatalf("terminal restart created a delivery: %d", got)
		}
	})

	t.Run("conservative old-lease expiry is explicit and never fabricates a withdrawal ACK", func(t *testing.T) {
		h := newHandoffEndToEndHarness(t, ctx, p, "expiry", true)
		h.warmAndPrepare(t, ctx)
		prepared := h.p2.only(k8s.P2HandoffPrepared)
		h.p2.attest(t, prepared, time.Now().UTC())
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffAwaitWithdrawal)
		if h.p2.count(k8s.P2HandoffWithdrawal) != 1 {
			t.Fatal("prepared acknowledgement did not issue old withdrawal")
		}
		h.tickOK(t, ctx) // no withdrawal attestation; old lease has conservatively expired.
		op := h.operation(t, ctx)
		if op.Phase != string(k8s.HandoffCASActive) || !op.WithdrawalExpiryReceivedAt.Valid || op.WithdrawalAckReceivedAt.Valid {
			t.Fatalf("expiry fallback was not explicit: %+v", op)
		}
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffEnableServing)
		h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
	})

	t.Run("follower performs zero observer, source, P2, or DB work", func(t *testing.T) {
		h := newHandoffEndToEndHarness(t, ctx, p, "follower", false)
		h.fence.follower = true
		result := h.tick(ctx)
		if !result.Follower || h.source.reads() != 0 || h.p2.attemptCount() != 0 || h.operationCount(t, ctx) != 0 {
			t.Fatalf("follower did work: result=%+v reads=%d p2=%d operations=%d", result, h.source.reads(), h.p2.attemptCount(), h.operationCount(t, ctx))
		}
	})

	t.Run("leader loss after source receipt but before each fenced phase mutation leaves durable state unchanged", func(t *testing.T) {
		for _, phase := range []k8s.HandoffPhase{
			k8s.HandoffPrepareCandidate,
			k8s.HandoffAwaitPreparedAck,
			k8s.HandoffAwaitWithdrawal,
			k8s.HandoffCASActive,
			k8s.HandoffEnableServing,
			k8s.HandoffAwaitServingAck,
			k8s.HandoffFinalize,
		} {
			t.Run(string(phase), func(t *testing.T) {
				h := newHandoffEndToEndHarness(t, ctx, p, "leader-loss-"+string(phase), false)
				switch phase {
				case k8s.HandoffPrepareCandidate:
					h.warmHealth(t, ctx, k8s.PromoteAfterStaleTicks-1)
				case k8s.HandoffAwaitPreparedAck:
					h.warmAndPrepare(t, ctx)
					h.p2.attest(t, h.p2.only(k8s.P2HandoffPrepared), time.Now().UTC())
				case k8s.HandoffAwaitWithdrawal:
					h.warmAndPrepare(t, ctx)
					h.p2.attest(t, h.p2.only(k8s.P2HandoffPrepared), time.Now().UTC())
					h.tickOK(t, ctx)
				case k8s.HandoffCASActive:
					h.toCASReady(t, ctx)
				case k8s.HandoffEnableServing:
					h.toCASReady(t, ctx)
					h.tickOK(t, ctx)
				case k8s.HandoffAwaitServingAck:
					h.toCASReady(t, ctx)
					h.tickOK(t, ctx) // atomic CAS -> enable_serving
					h.tickOK(t, ctx) // exact serving delivery -> await_serving_ack
					h.p2.attest(t, h.p2.only(k8s.P2HandoffServing), time.Now().UTC())
				case k8s.HandoffFinalize:
					h.toCASReady(t, ctx)
					h.tickOK(t, ctx) // atomic CAS -> enable_serving
					h.tickOK(t, ctx) // exact serving delivery -> await_serving_ack
					h.p2.attest(t, h.p2.only(k8s.P2HandoffServing), time.Now().UTC())
					h.tickOK(t, ctx) // serving receipt -> finalize
				}
				if phase != k8s.HandoffPrepareCandidate {
					h.phase(t, ctx, phase)
				}
				before := h.snapshot(t, ctx)
				p2Calls := h.p2.attemptCount()
				h.source.afterRead = func() { h.fence.drop(ctx) }
				result := h.tick(ctx)
				if !result.Follower || h.p2.attemptCount() != p2Calls || h.snapshot(t, ctx) != before {
					t.Fatalf("lost leader mutated phase=%s result=%+v before=%+v after=%+v p2=%d/%d", phase, result, before, h.snapshot(t, ctx), p2Calls, h.p2.attemptCount())
				}
			})
		}
	})

	t.Run("lost and duplicate exact receipts advance each wait phase at most once across restart", func(t *testing.T) {
		cases := []struct {
			name         string
			waiting      k8s.HandoffPhase
			next         k8s.HandoffPhase
			setup        func(*handoffEndToEndHarness)
			delivery     func(*handoffEndToEndHarness) k8s.P2HandoffDelivery
			afterRestart func(*handoffEndToEndHarness)
		}{
			{
				name:    "prepared",
				waiting: k8s.HandoffAwaitPreparedAck,
				next:    k8s.HandoffAwaitWithdrawal,
				setup: func(h *handoffEndToEndHarness) {
					h.warmAndPrepare(t, ctx)
				},
				delivery: func(h *handoffEndToEndHarness) k8s.P2HandoffDelivery { return h.p2.only(k8s.P2HandoffPrepared) },
				afterRestart: func(h *handoffEndToEndHarness) {
					h.phase(t, ctx, k8s.HandoffAwaitWithdrawal)
					h.assertPoolAudit(t, ctx, h.fixture.active, 1, 0)
				},
			},
			{
				name:    "withdrawal",
				waiting: k8s.HandoffAwaitWithdrawal,
				next:    k8s.HandoffCASActive,
				setup: func(h *handoffEndToEndHarness) {
					h.warmAndPrepare(t, ctx)
					h.p2.attest(t, h.p2.only(k8s.P2HandoffPrepared), time.Now().UTC())
					h.tickOK(t, ctx)
				},
				delivery: func(h *handoffEndToEndHarness) k8s.P2HandoffDelivery { return h.p2.only(k8s.P2HandoffWithdrawal) },
				afterRestart: func(h *handoffEndToEndHarness) {
					h.phase(t, ctx, k8s.HandoffEnableServing)
					h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
				},
			},
			{
				name:    "serving",
				waiting: k8s.HandoffAwaitServingAck,
				next:    k8s.HandoffFinalize,
				setup: func(h *handoffEndToEndHarness) {
					h.toCASReady(t, ctx)
					h.tickOK(t, ctx) // atomic CAS -> enable_serving
					h.tickOK(t, ctx) // exact serving delivery -> await_serving_ack
				},
				delivery: func(h *handoffEndToEndHarness) k8s.P2HandoffDelivery { return h.p2.only(k8s.P2HandoffServing) },
				afterRestart: func(h *handoffEndToEndHarness) {
					h.phase(t, ctx, k8s.HandoffComplete)
					h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
				},
			},
		}
		for _, test := range cases {
			t.Run(test.name, func(t *testing.T) {
				h := newHandoffEndToEndHarness(t, ctx, p, "receipt-"+test.name, false)
				test.setup(h)
				h.phase(t, ctx, test.waiting)
				delivery := test.delivery(h)
				before := h.snapshot(t, ctx)

				// No attestation is no evidence. Retrying and restarting preserve
				// the exact wait phase; a serving retry may repeat only its identity.
				h.tickOK(t, ctx)
				h.restart()
				h.tickOK(t, ctx)
				h.phase(t, ctx, test.waiting)
				h.p2.assertExactOnly(t, delivery.Identity.Role, delivery)
				if got := h.snapshot(t, ctx); got != before {
					t.Fatalf("lost receipt changed durable state: before=%+v after=%+v", before, got)
				}

				// A duplicated v2 attestation is still one operation-keyed receipt.
				h.p2.attest(t, delivery, time.Now().UTC())
				h.p2.attest(t, delivery, time.Now().UTC())
				h.tickOK(t, ctx)
				h.phase(t, ctx, test.next)
				h.restart()
				h.tickOK(t, ctx)
				test.afterRestart(h)
				h.p2.assertExactOnly(t, delivery.Identity.Role, delivery)
			})
		}
	})

	t.Run("database error after withdrawal receipt rolls back atomic CAS and resumes once", func(t *testing.T) {
		h := newHandoffEndToEndHarness(t, ctx, p, "cas-db-error", false)
		h.toCASReady(t, ctx)
		before := h.snapshot(t, ctx)
		locker, err := p.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer locker.Release()
		tx, err := locker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `LOCK TABLE audit_logs IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = h.fence.conn.Exec(context.Background(), `SET statement_timeout = 0`) }()
		if _, err := h.fence.conn.Exec(ctx, `SET statement_timeout = '50ms'`); err != nil {
			t.Fatal(err)
		}
		if result := h.tick(ctx); result.RunnerError == nil {
			t.Fatalf("CAS database timeout was hidden: %+v", result)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := h.fence.conn.Exec(ctx, `SET statement_timeout = 0`); err != nil {
			t.Fatal(err)
		}
		if got := h.snapshot(t, ctx); got != before {
			t.Fatalf("failed atomic CAS changed ownership/audit: before=%+v after=%+v", before, got)
		}
		h.restart()
		h.tickOK(t, ctx)
		h.phase(t, ctx, k8s.HandoffEnableServing)
		h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
		h.restart()
		h.tickOK(t, ctx)
		h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
	})

	t.Run("membership epoch churn between observation and operation claim aborts and needs a fresh threshold", func(t *testing.T) {
		h := newHandoffEndToEndHarness(t, ctx, p, "churn", false)
		h.warmHealth(t, ctx, k8s.PromoteAfterStaleTicks-1)
		before, err := sqlc.New(p).GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(h.fixture)))
		if err != nil {
			t.Fatal(err)
		}
		h.source.afterRead = func() {
			if _, err := p.Exec(ctx, `DELETE FROM k8s_connector_pool_members WHERE pool_id=$1 AND node_id=$2`, h.fixture.pool, h.fixture.candidate); err != nil {
				t.Fatalf("remove candidate during churn: %v", err)
			}
			if _, err := sqlc.New(p).AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: h.fixture.pool, OrgID: h.fixture.org, NodeID: h.fixture.candidate, AdminPriority: 10}); err != nil {
				t.Fatalf("re-add candidate during churn: %v", err)
			}
			syncProductionHandoffTickPoolEpoch(t, ctx, p, h.fixture)
		}
		h.tickOK(t, ctx)
		after, err := sqlc.New(p).GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(h.fixture)))
		if err != nil {
			t.Fatal(err)
		}
		if after.MembershipEpoch <= before.MembershipEpoch || h.operationCount(t, ctx) != 0 || h.p2.attemptCount() != 0 {
			t.Fatalf("membership churn reused threshold: before=%+v after=%+v operations=%d p2=%d", before, after, h.operationCount(t, ctx), h.p2.attemptCount())
		}
		for tick := 0; tick < k8s.PromoteAfterStaleTicks; tick++ {
			h.tickOK(t, ctx)
			if tick < k8s.PromoteAfterStaleTicks-1 && h.operationCount(t, ctx) != 0 {
				t.Fatalf("churned pool promoted at fresh tick %d", tick+1)
			}
		}
		if h.operationCount(t, ctx) != 1 || h.p2.count(k8s.P2HandoffPrepared) != 1 {
			t.Fatalf("fresh threshold did not create exactly one prepared operation: operations=%d prepared=%d", h.operationCount(t, ctx), h.p2.count(k8s.P2HandoffPrepared))
		}
	})

	t.Run("post-claim membership churn terminally aborts every pre-CAS phase and a fresh epoch creates new intent", func(t *testing.T) {
		for _, stage := range []k8s.HandoffPhase{k8s.HandoffAwaitPreparedAck, k8s.HandoffAwaitWithdrawal, k8s.HandoffCASActive} {
			t.Run(string(stage), func(t *testing.T) {
				h := newHandoffEndToEndHarness(t, ctx, p, "post-claim-"+string(stage), false)
				// The old/new member FKs deliberately protect those two rows. An
				// auxiliary member exercises the permitted delete/re-add churn
				// path that must nevertheless abort this pool's handoff.
				extra := addHandoffTickMember(t, ctx, p, h.fixture, time.Now().UTC(), 1, false)
				syncProductionHandoffTickPoolEpoch(t, ctx, p, h.fixture)
				h.warmAndPrepare(t, ctx)
				switch stage {
				case k8s.HandoffAwaitWithdrawal:
					h.p2.attest(t, h.p2.only(k8s.P2HandoffPrepared), time.Now().UTC())
					h.tickOK(t, ctx)
					h.phase(t, ctx, k8s.HandoffAwaitWithdrawal)
				case k8s.HandoffCASActive:
					h.toCASReady(t, ctx)
				}
				before := h.snapshot(t, ctx)
				beforeCalls := h.p2.attemptCount()
				beforePrepared := h.p2.count(k8s.P2HandoffPrepared)
				claimed := h.operation(t, ctx)
				if claimed.ObservedMembershipEpoch == nil {
					t.Fatal("observer-originated operation did not persist membership epoch")
				}
				if _, err := p.Exec(ctx, `DELETE FROM k8s_connector_pool_members WHERE pool_id=$1 AND node_id=$2`, h.fixture.pool, extra); err != nil {
					t.Fatalf("delete auxiliary member: %v", err)
				}
				if _, err := sqlc.New(p).AddK8sConnectorPoolMember(ctx, sqlc.AddK8sConnectorPoolMemberParams{PoolID: h.fixture.pool, OrgID: h.fixture.org, NodeID: extra, AdminPriority: 1}); err != nil {
					t.Fatalf("re-add auxiliary member: %v", err)
				}
				failed := h.operation(t, ctx)
				if failed.Phase != "failed" || failed.FailureReason == nil || *failed.FailureReason != "membership_epoch_changed" {
					t.Fatalf("membership churn did not terminally fail operation: %+v", failed)
				}
				after := h.snapshot(t, ctx)
				if after.Active != before.Active || after.Generation != before.Generation || after.Audits != before.Audits {
					t.Fatalf("membership abort changed pool/audit: before=%+v after=%+v", before, after)
				}

				syncProductionHandoffTickPoolEpoch(t, ctx, p, h.fixture)
				h.restart()
				h.tickOK(t, ctx)
				if h.p2.attemptCount() != beforeCalls || h.operation(t, ctx).Phase != "failed" {
					t.Fatalf("terminal operation resumed: p2=%d/%d operation=%+v", h.p2.attemptCount(), beforeCalls, h.operation(t, ctx))
				}
				// The restart's first post-churn observation is tick one. Only two
				// further distinct observations may create a second, epoch-keyed
				// operation; the failed row is never reopened.
				for range k8s.PromoteAfterStaleTicks - 1 {
					h.tickOK(t, ctx)
				}
				if h.operationCount(t, ctx) != 2 || h.p2.count(k8s.P2HandoffPrepared) != beforePrepared+1 {
					t.Fatalf("fresh epoch did not create exactly one new prepared intent: operations=%d prepared=%d", h.operationCount(t, ctx), h.p2.count(k8s.P2HandoffPrepared))
				}
				var freshID uuid.UUID
				var freshEpoch *int64
				if err := p.QueryRow(ctx, `SELECT id,observed_membership_epoch FROM k8s_connector_handoff_operations WHERE pool_id=$1 AND id<>$2`, h.fixture.pool, claimed.ID).Scan(&freshID, &freshEpoch); err != nil {
					t.Fatal(err)
				}
				if freshID == uuid.Nil || freshEpoch == nil || *freshEpoch <= *claimed.ObservedMembershipEpoch {
					t.Fatalf("fresh operation did not bind a newer membership incarnation: old=%+v new_id=%s new_epoch=%v", claimed, freshID, freshEpoch)
				}
			})
		}
	})

	t.Run("old and new priority changes terminally abort pre-CAS operations", func(t *testing.T) {
		for name, nodeID := range map[string]func(handoffTickPoolFixture) uuid.UUID{
			"old": func(f handoffTickPoolFixture) uuid.UUID { return f.active },
			"new": func(f handoffTickPoolFixture) uuid.UUID { return f.candidate },
		} {
			t.Run(name, func(t *testing.T) {
				h := newHandoffEndToEndHarness(t, ctx, p, "pre-cas-priority-"+name, false)
				h.toCASReady(t, ctx)
				before := h.snapshot(t, ctx)
				calls := h.p2.attemptCount()
				if _, err := p.Exec(ctx, `UPDATE k8s_connector_pool_members SET admin_priority = admin_priority + 1 WHERE pool_id=$1 AND node_id=$2`, h.fixture.pool, nodeID(h.fixture)); err != nil {
					t.Fatalf("change %s member priority: %v", name, err)
				}
				failed := h.operation(t, ctx)
				if failed.Phase != "failed" || failed.FailureReason == nil || *failed.FailureReason != "membership_epoch_changed" {
					t.Fatalf("%s priority change did not terminally fail pre-CAS operation: %+v", name, failed)
				}
				h.restart()
				h.tickOK(t, ctx)
				if h.p2.attemptCount() != calls || h.snapshot(t, ctx) != (handoffEndToEndSnapshot{Phase: "failed", Active: before.Active, Generation: before.Generation, Audits: before.Audits}) {
					t.Fatalf("%s priority abort resumed or changed pool/audit: calls=%d/%d before=%+v after=%+v", name, h.p2.attemptCount(), calls, before, h.snapshot(t, ctx))
				}
			})
		}
	})

	t.Run("operation membership FKs refuse old or new deletion", func(t *testing.T) {
		for name, nodeID := range map[string]func(handoffTickPoolFixture) uuid.UUID{
			"old": func(f handoffTickPoolFixture) uuid.UUID { return f.active },
			"new": func(f handoffTickPoolFixture) uuid.UUID { return f.candidate },
		} {
			t.Run(name, func(t *testing.T) {
				h := newHandoffEndToEndHarness(t, ctx, p, "protected-member-"+name, false)
				h.toCASReady(t, ctx)
				if _, err := p.Exec(ctx, `DELETE FROM k8s_connector_pool_members WHERE pool_id=$1 AND node_id=$2`, h.fixture.pool, nodeID(h.fixture)); err == nil {
					t.Fatalf("operation FK allowed deleting %s handoff member", name)
				}
				h.phase(t, ctx, k8s.HandoffCASActive)
			})
		}
	})

	t.Run("post-CAS membership churn preserves one fenced serving completion", func(t *testing.T) {
		for _, stage := range []k8s.HandoffPhase{k8s.HandoffEnableServing, k8s.HandoffAwaitServingAck, k8s.HandoffFinalize} {
			t.Run(string(stage), func(t *testing.T) {
				h := newHandoffEndToEndHarness(t, ctx, p, "post-cas-"+string(stage), false)
				extra := addHandoffTickMember(t, ctx, p, h.fixture, time.Now().UTC(), 1, false)
				syncProductionHandoffTickPoolEpoch(t, ctx, p, h.fixture)
				h.toCASReady(t, ctx)
				h.tickOK(t, ctx) // atomic CAS -> enable_serving
				h.phase(t, ctx, k8s.HandoffEnableServing)

				var serving k8s.P2HandoffDelivery
				if stage == k8s.HandoffAwaitServingAck || stage == k8s.HandoffFinalize {
					h.tickOK(t, ctx) // deliver serving -> await_serving_ack
					h.phase(t, ctx, k8s.HandoffAwaitServingAck)
					serving = h.p2.only(k8s.P2HandoffServing)
				}
				if stage == k8s.HandoffFinalize {
					h.p2.attest(t, serving, time.Now().UTC())
					h.tickOK(t, ctx) // fresh serving acknowledgement -> finalize
					h.phase(t, ctx, k8s.HandoffFinalize)
				}

				before := h.snapshot(t, ctx)
				claimed := h.operation(t, ctx)
				if _, err := p.Exec(ctx, `UPDATE k8s_connector_pool_members SET admin_priority = admin_priority + 1 WHERE pool_id=$1 AND node_id=$2`, h.fixture.pool, extra); err != nil {
					t.Fatalf("change auxiliary priority: %v", err)
				}
				afterChurn := h.operation(t, ctx)
				if afterChurn.ID != claimed.ID || afterChurn.Phase != string(stage) || afterChurn.FailureReason != nil {
					t.Fatalf("post-CAS churn did not preserve the fenced operation: before=%+v after=%+v", claimed, afterChurn)
				}
				health, err := sqlc.New(p).GetK8sConnectorPoolHealthState(ctx, healthScopeParams(healthScope(h.fixture)))
				if err != nil {
					t.Fatal(err)
				}
				if health.LastObservationAt.Valid || health.LastObservationKey != nil {
					t.Fatalf("post-CAS churn did not invalidate health history: %+v", health)
				}
				if got := h.snapshot(t, ctx); got != before {
					t.Fatalf("post-CAS churn changed ownership/audit: before=%+v after=%+v", before, got)
				}

				h.restart()
				switch stage {
				case k8s.HandoffEnableServing:
					h.tickOK(t, ctx) // deliver exact serving identity
					h.phase(t, ctx, k8s.HandoffAwaitServingAck)
					serving = h.p2.only(k8s.P2HandoffServing)
				case k8s.HandoffAwaitServingAck:
					h.tickOK(t, ctx) // no ack: replay only same serving identity
					h.phase(t, ctx, k8s.HandoffAwaitServingAck)
				case k8s.HandoffFinalize:
					h.tickOK(t, ctx) // finalize -> complete
					h.phase(t, ctx, k8s.HandoffComplete)
				}
				h.p2.assertExactOnly(t, k8s.P2HandoffServing, serving)

				if stage != k8s.HandoffFinalize {
					h.p2.attest(t, serving, time.Now().UTC())
					h.tickOK(t, ctx)
					h.phase(t, ctx, k8s.HandoffFinalize)
					h.tickOK(t, ctx)
					h.phase(t, ctx, k8s.HandoffComplete)
				}
				h.assertPoolAudit(t, ctx, h.fixture.candidate, 2, 1)
				if h.operationCount(t, ctx) != 1 || h.p2.uniqueCountForOperation(claimed.ID) != 3 {
					t.Fatalf("post-CAS completion reopened operation or delivery: operations=%d operation_deliveries=%d", h.operationCount(t, ctx), h.p2.uniqueCountForOperation(claimed.ID))
				}
				for range k8s.PromoteAfterStaleTicks - 1 {
					h.tickOK(t, ctx)
				}
				if h.operationCount(t, ctx) != 1 {
					t.Fatalf("post-completion membership epoch created a new operation before a fresh threshold: %d", h.operationCount(t, ctx))
				}
			})
		}
	})
}

type handoffEndToEndHarness struct {
	p         *pgxpool.Pool
	fixture   handoffTickPoolFixture
	p2        *endToEndP2Store
	source    *endToEndAttestingSource
	fence     *endToEndFence
	scheduler *k8s.HandoffScheduler
}

func newHandoffEndToEndHarness(t *testing.T, ctx context.Context, p *pgxpool.Pool, name string, expiryFallback bool) *handoffEndToEndHarness {
	t.Helper()
	// PostgreSQL persists timestamptz at microsecond precision. The plan is
	// immutable and compared exactly on restart, so the test-only provenance
	// source must construct values at the same precision as durable storage.
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixture := newProductionHandoffTickPool(t, ctx, p, now, name, false)
	plans := &endToEndPlanResolver{now: now, expiryFallback: expiryFallback}
	p2 := newEndToEndP2Store()
	adapter := k8s.NewP2HandoffAdapter(p2, p2)
	observer := NewPostgresHandoffHealthHistory(p, handoffTickPolicy{}, time.Minute)
	base := NewPostgresHandoffTickSource(p, handoffTickPolicy{}, observer, plans, tickSourceConfig())
	source := &endToEndAttestingSource{pool: p, base: base, adapter: adapter, nextObservationAt: now}
	fence := newEndToEndFence(t, ctx, p, int64(93000000+time.Now().UnixNano()%1000000))
	h := &handoffEndToEndHarness{p: p, fixture: fixture, p2: p2, source: source, fence: fence}
	h.scheduler = k8s.NewHandoffScheduler(source, k8s.NewHandoffCoordinator(k8s.NewService(p), adapter), fence, k8s.HandoffSchedulerConfig{PerTickTimeout: 3 * time.Second})
	t.Cleanup(func() { fence.close(ctx) })
	return h
}

func (h *handoffEndToEndHarness) restart() {
	adapter := k8s.NewP2HandoffAdapter(h.p2, h.p2)
	h.source.adapter = adapter
	h.scheduler = k8s.NewHandoffScheduler(h.source, k8s.NewHandoffCoordinator(k8s.NewService(h.p), adapter), h.fence, k8s.HandoffSchedulerConfig{PerTickTimeout: 3 * time.Second})
}

func (h *handoffEndToEndHarness) tick(ctx context.Context) k8s.HandoffSchedulerResult {
	return h.scheduler.Tick(ctx)
}

func (h *handoffEndToEndHarness) tickOK(t *testing.T, ctx context.Context) {
	t.Helper()
	if result := h.tick(ctx); result.SourceError != nil || result.RunnerError != nil {
		t.Fatalf("scheduler result=%+v", result)
	}
}

func (h *handoffEndToEndHarness) warmHealth(t *testing.T, ctx context.Context, ticks int) {
	t.Helper()
	for range ticks {
		h.tickOK(t, ctx)
	}
}

func (h *handoffEndToEndHarness) warmAndPrepare(t *testing.T, ctx context.Context) {
	t.Helper()
	h.warmHealth(t, ctx, k8s.PromoteAfterStaleTicks)
	h.phase(t, ctx, k8s.HandoffAwaitPreparedAck)
}

func (h *handoffEndToEndHarness) toCASReady(t *testing.T, ctx context.Context) {
	t.Helper()
	h.warmAndPrepare(t, ctx)
	h.p2.attest(t, h.p2.only(k8s.P2HandoffPrepared), time.Now().UTC())
	h.tickOK(t, ctx)
	h.phase(t, ctx, k8s.HandoffAwaitWithdrawal)
	h.p2.attest(t, h.p2.only(k8s.P2HandoffWithdrawal), time.Now().UTC())
	h.tickOK(t, ctx)
	h.phase(t, ctx, k8s.HandoffCASActive)
}

func (h *handoffEndToEndHarness) operation(t *testing.T, ctx context.Context) sqlc.K8sConnectorHandoffOperation {
	t.Helper()
	row := h.p.QueryRow(ctx, `SELECT id, org_id, site_id, pool_id, cluster_id, old_node_id, new_node_id, expected_generation, target_generation, old_serving_manifest_identity, candidate_prepared_manifest_identity, old_withdrawal_manifest_identity, new_serving_manifest_identity, old_serving_manifest_revision, candidate_prepared_manifest_revision, old_withdrawal_manifest_revision, new_serving_manifest_revision, old_lease_identity, target_lease_identity, old_lease_epoch, target_lease_epoch, old_lease_expires_at, target_lease_expires_at, observed_membership_epoch, decision_transition, old_serving_role, candidate_prepared_role, old_withdrawal_role, new_serving_role, phase, prepared_ack_received_at, withdrawal_ack_received_at, withdrawal_expiry_received_at, serving_ack_received_at, cas_receipt_at, cas_audit_id, cas_audit_applied, failure_reason, created_at, updated_at FROM k8s_connector_handoff_operations WHERE org_id=$1 AND site_id=$2 AND pool_id=$3 ORDER BY created_at DESC LIMIT 1`, h.fixture.org, h.fixture.site, h.fixture.pool)
	var op sqlc.K8sConnectorHandoffOperation
	if err := row.Scan(&op.ID, &op.OrgID, &op.SiteID, &op.PoolID, &op.ClusterID, &op.OldNodeID, &op.NewNodeID, &op.ExpectedGeneration, &op.TargetGeneration, &op.OldServingManifestIdentity, &op.CandidatePreparedManifestIdentity, &op.OldWithdrawalManifestIdentity, &op.NewServingManifestIdentity, &op.OldServingManifestRevision, &op.CandidatePreparedManifestRevision, &op.OldWithdrawalManifestRevision, &op.NewServingManifestRevision, &op.OldLeaseIdentity, &op.TargetLeaseIdentity, &op.OldLeaseEpoch, &op.TargetLeaseEpoch, &op.OldLeaseExpiresAt, &op.TargetLeaseExpiresAt, &op.ObservedMembershipEpoch, &op.DecisionTransition, &op.OldServingRole, &op.CandidatePreparedRole, &op.OldWithdrawalRole, &op.NewServingRole, &op.Phase, &op.PreparedAckReceivedAt, &op.WithdrawalAckReceivedAt, &op.WithdrawalExpiryReceivedAt, &op.ServingAckReceivedAt, &op.CasReceiptAt, &op.CasAuditID, &op.CasAuditApplied, &op.FailureReason, &op.CreatedAt, &op.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	return op
}

func (h *handoffEndToEndHarness) phase(t *testing.T, ctx context.Context, want k8s.HandoffPhase) {
	t.Helper()
	if got := h.operation(t, ctx).Phase; got != string(want) {
		t.Fatalf("operation phase=%q, want %q", got, want)
	}
}

func (h *handoffEndToEndHarness) operationCount(t *testing.T, ctx context.Context) int {
	t.Helper()
	var count int
	if err := h.p.QueryRow(ctx, `SELECT count(*) FROM k8s_connector_handoff_operations WHERE pool_id=$1`, h.fixture.pool).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

type handoffEndToEndSnapshot struct {
	Phase      string
	Active     uuid.UUID
	Generation int64
	Audits     int
}

func (h *handoffEndToEndHarness) snapshot(t *testing.T, ctx context.Context) handoffEndToEndSnapshot {
	t.Helper()
	var out handoffEndToEndSnapshot
	if h.operationCount(t, ctx) == 1 {
		out.Phase = h.operation(t, ctx).Phase
	}
	if err := h.p.QueryRow(ctx, `SELECT active_node_id, generation FROM k8s_connector_pools WHERE id=$1`, h.fixture.pool).Scan(&out.Active, &out.Generation); err != nil {
		t.Fatal(err)
	}
	if err := h.p.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='k8s.connector_pool.handoff_applied'`, h.fixture.org).Scan(&out.Audits); err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *handoffEndToEndHarness) assertPoolAudit(t *testing.T, ctx context.Context, active uuid.UUID, generation int64, audits int) {
	t.Helper()
	got := h.snapshot(t, ctx)
	if got.Active != active || got.Generation != generation || got.Audits != audits {
		t.Fatalf("pool/audit=%+v, want active=%s generation=%d audits=%d", got, active, generation, audits)
	}
}

type endToEndPlanResolver struct {
	now            time.Time
	expiryFallback bool
}

func (r *endToEndPlanResolver) ResolveHandoffPlan(_ context.Context, intent HandoffTickIntent) (k8s.DurableHandoffPlan, bool, error) {
	plan := testHandoffPlan(intent, r.now)
	if r.expiryFallback {
		plan.Plan.OldServing.Lease.ExpiresAt = r.now.Add(-5 * time.Second)
	}
	return plan, true, nil
}

// This harness models an already validated, in-process P1 plan source. The
// production resolver is separately required to use the P2 direct-session
// provenance seam; the test double must still acknowledge the scheduler's
// exact leader connection so the scheduler does not fall back to an unsafe
// generic fresh-plan path.
func (r *endToEndPlanResolver) ResolveHandoffPlanWithLeadership(ctx context.Context, intent HandoffTickIntent, _ k8s.HandoffLeadershipEpoch, _ *pgxpool.Conn) (k8s.DurableHandoffPlan, bool, error) {
	return r.ResolveHandoffPlan(ctx, intent)
}

type endToEndAttestingSource struct {
	pool              *pgxpool.Pool
	base              *PostgresHandoffTickSource
	adapter           *k8s.P2HandoffAdapter
	nextObservationAt time.Time
	afterRead         func()
	mu                sync.Mutex
	readCount         int
}

func (s *endToEndAttestingSource) HandoffRequests(ctx context.Context, schedulerNow time.Time) ([]k8s.HandoffCoordinatorRequest, error) {
	return nil, errors.New("end-to-end source requires leader-bound scheduler callback")
}

func (s *endToEndAttestingSource) HandoffRequestsWithLeadership(ctx context.Context, schedulerNow time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn) ([]k8s.HandoffCoordinatorRequest, error) {
	s.mu.Lock()
	observedAt := s.nextObservationAt
	s.nextObservationAt = s.nextObservationAt.Add(time.Second)
	s.readCount++
	after := s.afterRead
	s.afterRead = nil
	s.mu.Unlock()
	requests, err := s.base.HandoffRequestsWithLeadership(ctx, observedAt, epoch, conn)
	if err != nil {
		return nil, err
	}
	if after != nil {
		after()
	}
	q := sqlc.New(s.pool)
	for index := range requests {
		req := &requests[index]
		op, err := q.GetK8sConnectorHandoffOperation(ctx, sqlc.GetK8sConnectorHandoffOperationParams{OperationID: req.Plan.Plan.OperationID, OrgID: req.Plan.Plan.Scope.OrgID, SiteID: req.Plan.Plan.Scope.SiteID, PoolID: req.Plan.Plan.Scope.PoolID})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		acks, err := s.adapter.AcknowledgementsForPhase(ctx, req.Plan, k8s.HandoffPhase(op.Phase), schedulerNow.UTC(), req.MaxAckAge)
		if err != nil {
			return nil, err
		}
		req.PreparedAck, req.WithdrawalAck, req.ServingAck = acks.Prepared, acks.Withdrawal, acks.Serving
	}
	return requests, nil
}

func (s *endToEndAttestingSource) reads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readCount
}

type endToEndP2Store struct {
	mu              sync.Mutex
	deliveries      map[uuid.UUID]k8s.P2HandoffDelivery
	attempts        []k8s.P2HandoffDelivery
	attestations    map[uuid.UUID]k8s.P2HandoffAppliedAttestation
	failAfterRecord map[k8s.P2HandoffRole]int
}

func newEndToEndP2Store() *endToEndP2Store {
	return &endToEndP2Store{deliveries: map[uuid.UUID]k8s.P2HandoffDelivery{}, attestations: map[uuid.UUID]k8s.P2HandoffAppliedAttestation{}, failAfterRecord: map[k8s.P2HandoffRole]int{}}
}

func (s *endToEndP2Store) IssueP2HandoffDelivery(_ context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, delivery k8s.P2HandoffDelivery) error {
	if conn == nil || epoch.BackendPID <= 0 || epoch.LockKey == 0 {
		return errors.New("missing leader session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found := s.deliveries[delivery.Identity.DeliveryID]; found && existing != delivery {
		return errors.New("delivery identity conflict")
	}
	s.deliveries[delivery.Identity.DeliveryID] = delivery
	s.attempts = append(s.attempts, delivery)
	if s.failAfterRecord[delivery.Identity.Role] > 0 {
		s.failAfterRecord[delivery.Identity.Role]--
		return errors.New("injected delivery crash")
	}
	return nil
}

func (s *endToEndP2Store) LoadP2HandoffAppliedAttestation(_ context.Context, identity k8s.P2HandoffDeliveryIdentity) (k8s.P2HandoffAppliedAttestation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, found := s.attestations[identity.DeliveryID]
	return item, found, nil
}

func (s *endToEndP2Store) only(role k8s.P2HandoffRole) k8s.P2HandoffDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.deliveries {
		if item.Identity.Role == role {
			return item
		}
	}
	return k8s.P2HandoffDelivery{}
}

func (s *endToEndP2Store) attest(t *testing.T, delivery k8s.P2HandoffDelivery, receipt time.Time) {
	t.Helper()
	if delivery.Identity.DeliveryID == uuid.Nil {
		t.Fatal("cannot attest an undispatched P2 delivery")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestations[delivery.Identity.DeliveryID] = k8s.P2HandoffAppliedAttestation{Version: k8s.P2HandoffAttestationVersion, Identity: delivery.Identity, CPReceiptAt: receipt.UTC(), DeliveryExpiresAt: delivery.LeaseExpiresAt, AppliedRole: delivery.Identity.Role, AppliedManifestIdentity: delivery.Identity.ManifestIdentity, AppliedPromotionGeneration: delivery.Identity.PromotionGeneration, AppliedManifestRevision: delivery.Identity.ManifestRevision, AppliedLeaseEpoch: endToEndAppliedLeaseEpoch(delivery.Identity), AppliedRouteDigest: delivery.Identity.ExpectedRouteDigest, AppliedVIPMapDigest: delivery.Identity.ExpectedVIPMapDigest}
}

func endToEndAppliedLeaseEpoch(identity k8s.P2HandoffDeliveryIdentity) uint64 {
	if identity.Role == k8s.P2HandoffWithdrawal {
		return identity.PriorLeaseEpoch
	}
	return identity.LeaseEpoch
}

func (s *endToEndP2Store) count(role k8s.P2HandoffRole) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, item := range s.attempts {
		if item.Identity.Role == role {
			count++
		}
	}
	return count
}

func (s *endToEndP2Store) attemptCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.attempts)
}

func (s *endToEndP2Store) uniqueCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.deliveries)
}

func (s *endToEndP2Store) uniqueCountForOperation(operationID uuid.UUID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, delivery := range s.deliveries {
		if delivery.Identity.OperationID == operationID {
			count++
		}
	}
	return count
}

func (s *endToEndP2Store) assertExactOnly(t *testing.T, role k8s.P2HandoffRole, want k8s.P2HandoffDelivery) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.attempts {
		if item.Identity.Role == role && item != want {
			t.Fatalf("retry changed %s delivery identity: got=%+v want=%+v", role, item.Identity, want.Identity)
		}
	}
}

type endToEndFence struct {
	conn     *pgxpool.Conn
	key      int64
	pid      int32
	held     bool
	follower bool
	mu       sync.Mutex
}

func newEndToEndFence(t *testing.T, ctx context.Context, p *pgxpool.Pool, key int64) *endToEndFence {
	t.Helper()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &endToEndFence{conn: conn, key: key}
}

func (f *endToEndFence) AcquireEpoch(ctx context.Context) (k8s.HandoffLeadershipEpoch, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn == nil || f.follower {
		return k8s.HandoffLeadershipEpoch{}, false
	}
	if f.held {
		return k8s.HandoffLeadershipEpoch{BackendPID: f.pid, LockKey: f.key}, true
	}
	var acquired bool
	if err := f.conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", f.key).Scan(&acquired); err != nil || !acquired {
		return k8s.HandoffLeadershipEpoch{}, false
	}
	if err := f.conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&f.pid); err != nil {
		_, _ = f.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", f.key)
		return k8s.HandoffLeadershipEpoch{}, false
	}
	f.held = true
	return k8s.HandoffLeadershipEpoch{BackendPID: f.pid, LockKey: f.key}, true
}

func (f *endToEndFence) WithEpoch(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, fn func(*pgxpool.Conn) error) (bool, error) {
	f.mu.Lock()
	if f.conn == nil || !f.held || epoch.BackendPID != f.pid || epoch.LockKey != f.key {
		f.mu.Unlock()
		return false, nil
	}
	var held bool
	if err := f.conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted)").Scan(&held); err != nil || !held {
		f.mu.Unlock()
		return false, err
	}
	conn := f.conn
	f.mu.Unlock()
	return true, fn(conn)
}

func (f *endToEndFence) drop(ctx context.Context) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil && f.held {
		_, _ = f.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", f.key)
		f.held = false
	}
}

func (f *endToEndFence) close(ctx context.Context) {
	f.drop(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		f.conn.Release()
		f.conn = nil
	}
}

func newHandoffEndToEndTestDB(t *testing.T, ctx context.Context, admin string) *pgxpool.Pool {
	return newHandoffEndToEndTestDBAt(t, ctx, admin, 120, "e2e")
}

func newHandoffProductionSchedulerTestDB(t *testing.T, ctx context.Context, admin string) *pgxpool.Pool {
	return newHandoffEndToEndTestDBAt(t, ctx, admin, 122, "production")
}

func newHandoffEndToEndTestDBAt(t *testing.T, ctx context.Context, admin string, version uint, suffix string) *pgxpool.Pool {
	t.Helper()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("tnx_handoff_%s_%d", suffix, time.Now().UnixNano())
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		adminPool.Close()
	})
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	if err := db.MigrateTo(u.String(), version); err != nil {
		t.Fatalf("migrate through %04d: %v", version, err)
	}
	p, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

var _ k8s.HandoffTickSource = (*endToEndAttestingSource)(nil)
var _ k8s.HandoffLeaderBoundTickSource = (*endToEndAttestingSource)(nil)
var _ k8s.P2HandoffDeliveryIssuer = (*endToEndP2Store)(nil)
var _ k8s.P2HandoffAttestationReader = (*endToEndP2Store)(nil)
var _ k8s.HandoffLeaderFence = (*endToEndFence)(nil)
