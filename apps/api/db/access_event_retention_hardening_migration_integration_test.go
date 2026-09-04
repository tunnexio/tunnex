package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestAccessEventRetentionHardeningMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0130 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	databaseName := "tnx_access_retention_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	testURL := *base
	testURL.Path = "/" + databaseName
	dsn := testURL.String()

	// Prove the hardening migration reverses cleanly before exercising the
	// durable rows that it protects.
	if err := db.MigrateTo(dsn, 129); err != nil {
		t.Fatalf("migrate prerequisite chain through 0129: %v", err)
	}
	if err := db.MigrateTo(dsn, 130); err != nil {
		t.Fatalf("apply 0130: %v", err)
	}
	if err := db.MigrateTo(dsn, 129); err != nil {
		t.Fatalf("0130 down: %v", err)
	}
	preMigrationPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	dbNow := accessEventRetentionDatabaseNow(t, ctx, preMigrationPool)
	defaultOrg, defaultActor := seedAccessEventRetentionPrincipal(t, ctx, preMigrationPool, "default")
	defaultExpired := insertAccessEventRetentionEvent(t, ctx, preMigrationPool, defaultOrg, 1, dbNow.Add(-45*24*time.Hour))
	defaultFresh := insertAccessEventRetentionEvent(t, ctx, preMigrationPool, defaultOrg, 2, dbNow)
	proveLegacyDeleteWaitsForMigrationFence(t, ctx, dsn, preMigrationPool, defaultExpired)
	preMigrationPool.Close()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	for _, signature := range []string{
		"access_event_retention_authorized(uuid)",
		"access_event_retention_prune_batch(uuid)",
		"access_event_retention_run_lease_guard()",
		"audit_log_retention_run_lease_guard()",
	} {
		var publicExecute bool
		if err := pool.QueryRow(ctx, `
			SELECT COALESCE(bool_or(privilege.grantee=0 AND privilege.privilege_type='EXECUTE'),false)
			FROM pg_proc function
			CROSS JOIN LATERAL aclexplode(COALESCE(function.proacl,acldefault('f',function.proowner))) privilege
			WHERE function.oid=$1::regprocedure`, signature).Scan(&publicExecute); err != nil {
			t.Fatalf("inspect %s ACL: %v", signature, err)
		}
		if publicExecute {
			t.Fatalf("PUBLIC can execute access-event retention function %s", signature)
		}
	}

	// Rows written before 0130 must be represented exactly by the locked
	// backfill before trigger-maintained deltas begin.
	assertAccessEventRetentionState(t, ctx, pool, defaultOrg, 2)

	// This is the v0.1.19 global age-sweep shape. 0130 must reject it before
	// any row is removed, even for the revision-zero default policy.
	if _, err := pool.Exec(ctx, `DELETE FROM access_events WHERE created_at < $1`, dbNow.Add(-30*24*time.Hour)); err == nil || !strings.Contains(err.Error(), "access_events_delete_not_authorized") {
		t.Fatalf("legacy access-event age sweep was not fenced: %v", err)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, defaultExpired, true)
	assertAccessEventRetentionEvent(t, ctx, pool, defaultFresh, true)
	if _, err := pool.Exec(ctx, `TRUNCATE access_events`); err == nil || !strings.Contains(err.Error(), "access_events_delete_not_authorized") {
		t.Fatalf("access-event TRUNCATE was not fenced: %v", err)
	}

	defaultRun := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: defaultOrg, actorID: defaultActor, key: "default-policy",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: dbNow, leaseExpiresAt: dbNow.Add(15 * time.Minute),
	})
	if deleted := pruneAccessEventRetentionTestRun(t, ctx, pool, defaultRun); deleted != 1 {
		t.Fatalf("revision-zero default prune deleted %d rows, want 1", deleted)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, defaultExpired, false)
	assertAccessEventRetentionEvent(t, ctx, pool, defaultFresh, true)
	assertAccessEventRetentionState(t, ctx, pool, defaultOrg, 1)
	assertAccessEventRetentionRunTruth(t, ctx, pool, defaultRun, 1, 1)
	if deleted := pruneAccessEventRetentionTestRun(t, ctx, pool, defaultRun); deleted != 0 {
		t.Fatalf("default-policy no-op prune deleted %d rows", deleted)
	}
	assertAccessEventRetentionRunTruth(t, ctx, pool, defaultRun, 1, 1)
	finishAccessEventRetentionTestRun(t, ctx, pool, defaultRun, defaultOrg)

	proveAccessEventLeaseGuardCompatibility(t, ctx, pool)
	proveAccessEventOldFinalizePreservesCounters(t, ctx, pool)
	proveAccessEventPruneCountersAfterLeaseExpiry(t, ctx, pool)
	proveAccessEventRequestedByCascade(t, ctx, pool)

	// A persisted long-retention policy is the exact mixed-version hazard: the
	// old fixed-30-day sweeper must not erase the 45-day row, while an exact
	// current-policy run may remove only evidence older than 3650 days.
	longOrg, longActor := seedAccessEventRetentionPrincipal(t, ctx, pool, "long")
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_event_retention_settings
			(org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id)
		VALUES($1,3650,60,1,$2)`, longOrg, longActor); err != nil {
		t.Fatalf("seed long persisted policy: %v", err)
	}
	longProtected := insertAccessEventRetentionEvent(t, ctx, pool, longOrg, 1, dbNow.Add(-45*24*time.Hour))
	longExpired := insertAccessEventRetentionEvent(t, ctx, pool, longOrg, 2, dbNow.Add(-4001*24*time.Hour))
	assertAccessEventRetentionState(t, ctx, pool, longOrg, 2)
	if _, err := pool.Exec(ctx, `DELETE FROM access_events WHERE org_id=$1 AND created_at < $2`, longOrg, dbNow.Add(-30*24*time.Hour)); err == nil || !strings.Contains(err.Error(), "access_events_delete_not_authorized") {
		t.Fatalf("legacy sweep bypassed persisted long policy: %v", err)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, longProtected, true)
	assertAccessEventRetentionEvent(t, ctx, pool, longExpired, true)

	mismatchedRun := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: longOrg, actorID: longActor, key: "stale-policy",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: dbNow, leaseExpiresAt: dbNow.Add(15 * time.Minute),
	})
	if _, err := pool.Exec(ctx, `SELECT access_event_retention_prune_batch($1)`, mismatchedRun); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("stale policy run authorized deletion: %v", err)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, longProtected, true)
	assertAccessEventRetentionEvent(t, ctx, pool, longExpired, true)
	finishAccessEventRetentionTestRun(t, ctx, pool, mismatchedRun, longOrg)

	exactRun := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: longOrg, actorID: longActor, key: "exact-long-policy",
		retentionDays: 3650, cleanupIntervalMinutes: 60, settingsRevision: 1,
		startedAt: dbNow, leaseExpiresAt: dbNow.Add(15 * time.Minute),
	})
	if deleted := pruneAccessEventRetentionTestRun(t, ctx, pool, exactRun); deleted != 1 {
		t.Fatalf("exact persisted-policy prune deleted %d rows, want 1", deleted)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, longProtected, true)
	assertAccessEventRetentionEvent(t, ctx, pool, longExpired, false)
	assertAccessEventRetentionState(t, ctx, pool, longOrg, 1)
	assertAccessEventRetentionRunTruth(t, ctx, pool, exactRun, 1, 1)
	finishAccessEventRetentionTestRun(t, ctx, pool, exactRun, longOrg)

	expiredRun := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: longOrg, actorID: longActor, key: "expired-lease",
		retentionDays: 3650, cleanupIntervalMinutes: 60, settingsRevision: 1,
		startedAt: dbNow.Add(-2 * time.Hour), leaseExpiresAt: dbNow.Add(-time.Hour),
	})
	if _, err := pool.Exec(ctx, `SELECT access_event_retention_prune_batch($1)`, expiredRun); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("expired lease authorized deletion: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE access_event_retention_runs SET lease_expires_at=clock_timestamp()+interval '15 minutes' WHERE id=$1`, expiredRun); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("expired run accepted arbitrary lease renewal: %v", err)
	}
	expireAccessEventRetentionTestRun(t, ctx, pool, expiredRun, longOrg)

	// A statement_timestamp-based predicate can be true before a lock wait and
	// remain frozen after the lease expires. Exercise both locks independently,
	// then the exact renewal statement shape shipped by the original v0.1.20.
	proveAccessEventPruneRejectsPostWaitExpiry(t, ctx, pool, "organization")
	proveAccessEventPruneRejectsPostWaitExpiry(t, ctx, pool, "run")
	proveAccessEventOldRenewRejectsPostWaitExpiry(t, ctx, pool)
	proveAuditLogPruneRejectsPostWaitExpiry(t, ctx, pool)
	proveAuditLogOldRenewRejectsPostWaitExpiry(t, ctx, pool)
	proveAuditLogRequestedByCascade(t, ctx, pool)

	// Both actor triggers must use live membership authority after 0130.
	if _, err := pool.Exec(ctx, `UPDATE memberships SET access_revoked_at=statement_timestamp() WHERE org_id=$1 AND user_id=$2`, longOrg, longActor); err != nil {
		t.Fatalf("revoke actor membership: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE access_event_retention_settings SET cleanup_interval_minutes=120 WHERE org_id=$1`, longOrg); err == nil || !strings.Contains(err.Error(), "access_event_retention_actor_not_organization_member") {
		t.Fatalf("revoked actor changed retention settings: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_event_retention_runs (
			org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,row_cap,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES ($1,'manual','running','revoked-actor',$2,3650,60,1,100000,1000,100,
			$3,$4,$5)`, longOrg, longActor, dbNow.Add(-3650*24*time.Hour), dbNow, dbNow.Add(15*time.Minute)); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_actor_not_organization_member") {
		t.Fatalf("revoked actor created manual retention run: %v", err)
	}

	// Production batch ingestion uses one COPY statement. Prove its transition
	// table groups a mixed-tenant batch into one exact delta per organization.
	copyOrgA, _ := seedAccessEventRetentionPrincipal(t, ctx, pool, "copy-a")
	copyOrgB, _ := seedAccessEventRetentionPrincipal(t, ctx, pool, "copy-b")
	copyRows := make([][]any, 0, 5)
	for seq := int64(1); seq <= 2; seq++ {
		copyRows = append(copyRows, accessEventRetentionCopyRow(copyOrgA, seq, dbNow))
	}
	for seq := int64(1); seq <= 3; seq++ {
		copyRows = append(copyRows, accessEventRetentionCopyRow(copyOrgB, seq, dbNow))
	}
	copied, err := pool.CopyFrom(ctx, pgx.Identifier{"access_events"}, []string{
		"id", "org_id", "seq", "occurred_at", "decision", "src_ip", "dst_ip", "protocol", "created_at",
	}, pgx.CopyFromRows(copyRows))
	if err != nil || copied != 5 {
		t.Fatalf("COPY transition-table proof copied=%d err=%v", copied, err)
	}
	assertAccessEventRetentionState(t, ctx, pool, copyOrgA, 2)
	assertAccessEventRetentionState(t, ctx, pool, copyOrgB, 3)

	var authorizationRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_event_retention_authorizations`).Scan(&authorizationRows); err != nil {
		t.Fatal(err)
	}
	if authorizationRows != 0 {
		t.Fatalf("access-event retention authorization leaked %d rows", authorizationRows)
	}

	// Hard organization deletion is the sole non-retention DELETE path. Its FK
	// cascade must remain available for lifecycle cleanup and test teardown.
	cascadeOrg, _ := seedAccessEventRetentionPrincipal(t, ctx, pool, "cascade")
	cascadeEvent := insertAccessEventRetentionEvent(t, ctx, pool, cascadeOrg, 1, dbNow)
	if _, err := pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, cascadeOrg); err != nil {
		t.Fatalf("hard organization cascade was blocked: %v", err)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, cascadeEvent, false)
	assertAccessEventRetentionStateMissing(t, ctx, pool, cascadeOrg)
}

// A v0.1.19 sweeper does not lock organizations before deleting from the
// child table. Pause 0130 at a later DDL lock and prove that its access_events
// lock is already held: the old DELETE must wait, then observe the committed
// trigger and fail closed rather than slipping through the installation gap.
func proveLegacyDeleteWaitsForMigrationFence(t *testing.T, ctx context.Context, dsn string, pool *pgxpool.Pool, eventID uuid.UUID) {
	t.Helper()
	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerPID := postgresBackendPID(t, ctx, blocker)
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	if _, err := blockerTx.Exec(ctx, `LOCK TABLE access_event_retention_runs IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatalf("hold later migration lock: %v", err)
	}

	migrationResult := make(chan error, 1)
	go func() {
		migrationResult <- db.MigrateTo(dsn, 130)
	}()
	migratorPID := waitForPostgresBackendBlockedBy(t, ctx, pool, blockerPID)
	var holdsEventFence bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_locks
			WHERE pid=$1 AND relation='access_events'::regclass
			  AND mode='ShareRowExclusiveLock' AND granted
		)`, migratorPID).Scan(&holdsEventFence); err != nil {
		t.Fatalf("inspect migration access-event fence: %v", err)
	}
	if !holdsEventFence {
		t.Fatal("0130 reached later DDL without holding the access_events fence")
	}

	legacy, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Release()
	legacyPID := postgresBackendPID(t, ctx, legacy)
	deleteResult := make(chan error, 1)
	go func() {
		_, err := legacy.Exec(ctx, `DELETE FROM access_events WHERE id=$1`, eventID)
		deleteResult <- err
	}()
	waitForPostgresLock(t, ctx, pool, legacyPID)

	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release later migration lock: %v", err)
	}
	if err := receivePostgresCall(t, migrationResult); err != nil {
		t.Fatalf("0130 re-up behind rollout fence: %v", err)
	}
	if err := receivePostgresCall(t, deleteResult); err == nil || !strings.Contains(err.Error(), "access_events_delete_not_authorized") {
		t.Fatalf("legacy delete crossed the migration installation fence: %v", err)
	}
}

func proveAccessEventLeaseGuardCompatibility(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "lease-shapes")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	runID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "lease-shapes",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: startedAt, leaseExpiresAt: startedAt.Add(15 * time.Minute),
	})

	// Exact original-v0.1.20 expiry shape: a forward-skewed application clock
	// satisfies its WHERE clause, but cannot terminate a database-live run.
	forwardClock := startedAt.Add(24 * time.Hour)
	var prematureStatus string
	if err := pool.QueryRow(ctx, `
		UPDATE access_event_retention_runs
		SET status='failed',completed_at=$1,lease_expires_at=NULL,
			more_pending=true,error_code='lease_expired'
		WHERE org_id=$2 AND status='running' AND lease_expires_at <= $1
		RETURNING status`, forwardClock, orgID).Scan(&prematureStatus); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("forward-skewed v0.1.20 expiry terminated a live run: status=%q err=%v", prematureStatus, err)
	}

	// Exact original renewal shape accepted an arbitrary application timestamp.
	// The guard must keep compatibility but issue its own fixed database lease.
	beforeOldRenew := accessEventRetentionDatabaseNow(t, ctx, pool)
	var oldNormalizedLease time.Time
	if err := pool.QueryRow(ctx, `
		UPDATE access_event_retention_runs
		SET lease_expires_at=$1
		WHERE id=$2 AND org_id=$3 AND status='running'
		RETURNING lease_expires_at`, startedAt.Add(365*24*time.Hour), runID, orgID).Scan(&oldNormalizedLease); err != nil {
		t.Fatalf("renew through original v0.1.20 shape: %v", err)
	}
	afterOldRenew := accessEventRetentionDatabaseNow(t, ctx, pool)
	assertFixedAccessEventRetentionLease(t, oldNormalizedLease, beforeOldRenew, afterOldRenew)

	// The current DB-clock-fenced query follows the same normalized path.
	beforeCurrentRenew := accessEventRetentionDatabaseNow(t, ctx, pool)
	var currentNormalizedLease time.Time
	if err := pool.QueryRow(ctx, `
		UPDATE access_event_retention_runs
		SET lease_expires_at=clock_timestamp() + interval '15 minutes'
		WHERE id=$1 AND org_id=$2 AND status='running'
		  AND lease_expires_at > clock_timestamp()
		RETURNING lease_expires_at`, runID, orgID).Scan(&currentNormalizedLease); err != nil {
		t.Fatalf("renew through current query shape: %v", err)
	}
	afterCurrentRenew := accessEventRetentionDatabaseNow(t, ctx, pool)
	assertFixedAccessEventRetentionLease(t, currentNormalizedLease, beforeCurrentRenew, afterCurrentRenew)
	finishAccessEventRetentionTestRun(t, ctx, pool, runID, orgID)

	// Exercise the current live failure-finalization shape as well.
	failureStartedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	failureRunID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "current-failure",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: failureStartedAt, leaseExpiresAt: failureStartedAt.Add(15 * time.Minute),
	})
	var failureStatus string
	if err := pool.QueryRow(ctx, `
		UPDATE access_event_retention_runs
		SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),
			lease_expires_at=NULL,more_pending=true,error_code='prune_failed'
		WHERE id=$1 AND org_id=$2 AND status='running'
		  AND lease_expires_at > clock_timestamp()
		RETURNING status`, failureRunID, orgID).Scan(&failureStatus); err != nil {
		t.Fatalf("finalize through current failure query shape: %v", err)
	}
	if failureStatus != "failed" {
		t.Fatalf("current failure finalization status=%q", failureStatus)
	}
}

func proveAccessEventOldFinalizePreservesCounters(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "old-finalize")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	insertAccessEventRetentionEvent(t, ctx, pool, orgID, 1, startedAt.Add(-31*24*time.Hour))
	runID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "old-finalize",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: startedAt, leaseExpiresAt: startedAt.Add(15 * time.Minute),
	})
	if _, err := pool.Exec(ctx, `
		UPDATE access_event_retention_runs
		SET deleted_rows=deleted_rows+1,batches=batches+1
		WHERE id=$1`, runID); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("direct caller forged durable prune counters: %v", err)
	}
	if deleted := pruneAccessEventRetentionTestRun(t, ctx, pool, runID); deleted != 1 {
		t.Fatalf("pre-finalization prune deleted %d rows, want 1", deleted)
	}

	// The original finalizer rewrote counters from process memory. Its zeroes
	// must not erase the atomic 1/1 truth committed by the prune function.
	proposedCompletion := startedAt.Add(365 * 24 * time.Hour)
	var completedAt time.Time
	var deletedRows int64
	var batches int
	if err := pool.QueryRow(ctx, `
		UPDATE access_event_retention_runs
		SET status='succeeded',completed_at=$1,lease_expires_at=NULL,
			deleted_rows=0,batches=0,more_pending=false,error_code=NULL
		WHERE id=$2 AND org_id=$3 AND status='running'
		RETURNING completed_at,deleted_rows,batches`, proposedCompletion, runID, orgID).
		Scan(&completedAt, &deletedRows, &batches); err != nil {
		t.Fatalf("finalize through original v0.1.20 shape: %v", err)
	}
	if deletedRows != 1 || batches != 1 {
		t.Fatalf("old finalizer overwrote durable truth: deleted=%d batches=%d", deletedRows, batches)
	}
	if !completedAt.Before(proposedCompletion.Add(-time.Hour)) {
		t.Fatalf("old finalizer retained forward-skewed completion %s", completedAt)
	}
}

func proveAccessEventPruneCountersAfterLeaseExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `CREATE TABLE access_event_retention_test_gate (id boolean PRIMARY KEY)`); err != nil {
		t.Fatalf("create prune test gate: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_event_retention_test_gate VALUES (true)`); err != nil {
		t.Fatalf("seed prune test gate: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION access_event_retention_test_wait_after_delete()
		RETURNS trigger AS $$
		BEGIN
			PERFORM 1 FROM access_event_retention_test_gate WHERE id FOR UPDATE;
			RETURN NULL;
		END;
		$$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create prune test gate function: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TRIGGER zz_access_event_retention_test_wait_after_delete
		AFTER DELETE ON access_events
		FOR EACH STATEMENT EXECUTE FUNCTION access_event_retention_test_wait_after_delete()`); err != nil {
		t.Fatalf("create prune test gate trigger: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS zz_access_event_retention_test_wait_after_delete ON access_events`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS access_event_retention_test_wait_after_delete()`)
		_, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS access_event_retention_test_gate`)
	}()

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	if _, err := blockerTx.Exec(ctx, `SELECT 1 FROM access_event_retention_test_gate WHERE id FOR UPDATE`); err != nil {
		t.Fatalf("hold prune post-delete gate: %v", err)
	}

	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "prune-lease-expiry")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	leaseExpiresAt := startedAt.Add(3 * time.Second)
	insertAccessEventRetentionEvent(t, ctx, pool, orgID, 1, startedAt.Add(-31*24*time.Hour))
	runID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "prune-lease-expiry",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: startedAt, leaseExpiresAt: leaseExpiresAt,
	})
	worker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Release()
	workerPID := postgresBackendPID(t, ctx, worker)
	var deleted int64
	result := make(chan error, 1)
	go func() {
		result <- worker.QueryRow(ctx, `SELECT access_event_retention_prune_batch($1)`, runID).Scan(&deleted)
	}()
	waitForPostgresLockBeforeLease(t, ctx, pool, workerPID, leaseExpiresAt)
	waitForDatabaseLeaseExpiry(t, ctx, pool, leaseExpiresAt)
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release prune post-delete gate: %v", err)
	}
	if err := receivePostgresCall(t, result); err != nil {
		t.Fatalf("finish authorized prune after lease expiry: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("authorized prune after lease expiry deleted %d rows, want 1", deleted)
	}
	assertAccessEventRetentionRunTruth(t, ctx, pool, runID, 1, 1)
	assertAccessEventRetentionState(t, ctx, pool, orgID, 0)
	expireAccessEventRetentionTestRun(t, ctx, pool, runID, orgID)
}

func proveAccessEventRequestedByCascade(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "requester-cascade")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	runID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "requester-cascade",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: startedAt, leaseExpiresAt: startedAt.Add(15 * time.Minute),
	})
	if _, err := pool.Exec(ctx, `UPDATE access_event_retention_runs SET requested_by_user_id=NULL WHERE id=$1`, runID); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("direct clearing of live run attribution was accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, actorID); err != nil {
		t.Fatalf("hard user deletion could not apply requested-by FK action: %v", err)
	}
	var requesterCleared bool
	var status string
	if err := pool.QueryRow(ctx, `
		SELECT requested_by_user_id IS NULL,status
		FROM access_event_retention_runs WHERE id=$1`, runID).Scan(&requesterCleared, &status); err != nil {
		t.Fatal(err)
	}
	if !requesterCleared || status != "running" {
		t.Fatalf("requested-by FK result cleared=%v status=%q", requesterCleared, status)
	}
	finishAccessEventRetentionTestRun(t, ctx, pool, runID, orgID)
}

func assertFixedAccessEventRetentionLease(t *testing.T, lease, before, after time.Time) {
	t.Helper()
	minLease := before.Add(15*time.Minute - time.Second)
	maxLease := after.Add(15*time.Minute + time.Second)
	if lease.Before(minLease) || lease.After(maxLease) {
		t.Fatalf("normalized lease %s outside database-clock window [%s,%s]", lease, minLease, maxLease)
	}
}

func proveAccessEventPruneRejectsPostWaitExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool, lockTarget string) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "wait-"+lockTarget)
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	leaseExpiresAt := startedAt.Add(3 * time.Second)
	eventID := insertAccessEventRetentionEvent(t, ctx, pool, orgID, 1, startedAt.Add(-31*24*time.Hour))
	runID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "wait-" + lockTarget,
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: startedAt, leaseExpiresAt: leaseExpiresAt,
	})

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	switch lockTarget {
	case "organization":
		_, err = blockerTx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, orgID)
	case "run":
		_, err = blockerTx.Exec(ctx, `SELECT 1 FROM access_event_retention_runs WHERE id=$1 FOR UPDATE`, runID)
	default:
		t.Fatalf("unknown lock target %q", lockTarget)
	}
	if err != nil {
		t.Fatalf("hold %s lock: %v", lockTarget, err)
	}

	worker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Release()
	workerPID := postgresBackendPID(t, ctx, worker)
	result := make(chan error, 1)
	go func() {
		var deleted int64
		result <- worker.QueryRow(ctx, `SELECT access_event_retention_prune_batch($1)`, runID).Scan(&deleted)
	}()
	waitForPostgresLockBeforeLease(t, ctx, pool, workerPID, leaseExpiresAt)
	waitForDatabaseLeaseExpiry(t, ctx, pool, leaseExpiresAt)
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release %s lock: %v", lockTarget, err)
	}
	if err := receivePostgresCall(t, result); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("access prune passed a %s lock after lease expiry: %v", lockTarget, err)
	}
	assertAccessEventRetentionEvent(t, ctx, pool, eventID, true)
	assertAccessEventRetentionState(t, ctx, pool, orgID, 1)
	expireAccessEventRetentionTestRun(t, ctx, pool, runID, orgID)
}

func proveAccessEventOldRenewRejectsPostWaitExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "wait-old-renew")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	leaseExpiresAt := startedAt.Add(3 * time.Second)
	runID := insertAccessEventRetentionTestRun(t, ctx, pool, accessEventRetentionRunFixture{
		orgID: orgID, actorID: actorID, key: "wait-old-renew",
		retentionDays: 30, cleanupIntervalMinutes: 60, settingsRevision: 0,
		startedAt: startedAt, leaseExpiresAt: leaseExpiresAt,
	})

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	if _, err := blockerTx.Exec(ctx, `SELECT 1 FROM access_event_retention_runs WHERE id=$1 FOR UPDATE`, runID); err != nil {
		t.Fatalf("hold access run lock for old renew: %v", err)
	}

	worker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Release()
	workerPID := postgresBackendPID(t, ctx, worker)
	result := make(chan error, 1)
	go func() {
		_, err := worker.Exec(ctx, `
			UPDATE access_event_retention_runs
			SET lease_expires_at=$1
			WHERE id=$2 AND org_id=$3 AND status='running'`,
			startedAt.Add(30*time.Minute), runID, orgID)
		result <- err
	}()
	waitForPostgresLockBeforeLease(t, ctx, pool, workerPID, leaseExpiresAt)
	waitForDatabaseLeaseExpiry(t, ctx, pool, leaseExpiresAt)
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release access run lock for old renew: %v", err)
	}
	if err := receivePostgresCall(t, result); err == nil || !strings.Contains(err.Error(), "access_event_retention_run_not_owned") {
		t.Fatalf("original v0.1.20 renewal revived an expired run: %v", err)
	}
	expireAccessEventRetentionTestRun(t, ctx, pool, runID, orgID)
}

func proveAuditLogPruneRejectsPostWaitExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "wait-audit")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	leaseExpiresAt := startedAt.Add(3 * time.Second)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_settings
			(org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id)
		VALUES($1,30,60,1,$2)`, orgID, actorID); err != nil {
		t.Fatalf("seed audit lock-wait policy: %v", err)
	}
	auditID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_logs(id,org_id,actor_user_id,action,created_at)
		VALUES($1,$2,$3,'retention.lock_wait',$4)`, auditID, orgID, actorID, startedAt.Add(-31*24*time.Hour)); err != nil {
		t.Fatalf("seed audit lock-wait evidence: %v", err)
	}
	auditRunID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_runs (
			id,org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES($1,$2,'manual','running','wait-audit',$3,30,60,1,1000,100,$4,$5,$6)`,
		auditRunID, orgID, actorID, startedAt.Add(-30*24*time.Hour), startedAt, leaseExpiresAt); err != nil {
		t.Fatalf("seed audit lock-wait run: %v", err)
	}

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	if _, err := blockerTx.Exec(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, orgID); err != nil {
		t.Fatalf("hold audit organization lock: %v", err)
	}

	worker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Release()
	workerPID := postgresBackendPID(t, ctx, worker)
	result := make(chan error, 1)
	go func() {
		var deleted int64
		result <- worker.QueryRow(ctx, `SELECT audit_log_retention_prune_batch($1)`, auditRunID).Scan(&deleted)
	}()
	waitForPostgresLockBeforeLease(t, ctx, pool, workerPID, leaseExpiresAt)
	waitForDatabaseLeaseExpiry(t, ctx, pool, leaseExpiresAt)
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release audit organization lock: %v", err)
	}
	if err := receivePostgresCall(t, result); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("audit prune passed an organization lock after lease expiry: %v", err)
	}
	assertAuditLogRetentionRow(t, ctx, pool, auditID, true)
	if _, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_runs
		SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),
			lease_expires_at=NULL,more_pending=true,error_code='lease_expired'
		WHERE id=$1`, auditRunID); err != nil {
		t.Fatalf("expire audit lock-wait run: %v", err)
	}
}

func proveAuditLogOldRenewRejectsPostWaitExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "wait-audit-old-renew")
	startedAt := accessEventRetentionDatabaseNow(t, ctx, pool)
	leaseExpiresAt := startedAt.Add(3 * time.Second)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_settings
			(org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id)
		VALUES($1,30,60,1,$2)`, orgID, actorID); err != nil {
		t.Fatalf("seed audit old-renew policy: %v", err)
	}
	auditRunID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_runs (
			id,org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES($1,$2,'manual','running','wait-audit-old-renew',$3,30,60,1,1000,100,$4,$5,$6)`,
		auditRunID, orgID, actorID, startedAt.Add(-30*24*time.Hour), startedAt, leaseExpiresAt); err != nil {
		t.Fatalf("seed audit old-renew run: %v", err)
	}

	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockerTx.Rollback(context.Background()) }()
	if _, err := blockerTx.Exec(ctx, `SELECT 1 FROM audit_log_retention_runs WHERE id=$1 FOR UPDATE`, auditRunID); err != nil {
		t.Fatalf("hold audit run lock for old renew: %v", err)
	}

	worker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Release()
	workerPID := postgresBackendPID(t, ctx, worker)
	result := make(chan error, 1)
	go func() {
		_, err := worker.Exec(ctx, `
			UPDATE audit_log_retention_runs
			SET lease_expires_at=statement_timestamp() + interval '15 minutes'
			WHERE id=$1 AND org_id=$2 AND status='running'
			  AND lease_expires_at > statement_timestamp()`, auditRunID, orgID)
		result <- err
	}()
	waitForPostgresLockBeforeLease(t, ctx, pool, workerPID, leaseExpiresAt)
	waitForDatabaseLeaseExpiry(t, ctx, pool, leaseExpiresAt)
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatalf("release audit run lock for old renew: %v", err)
	}
	if err := receivePostgresCall(t, result); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("original v0.1.20 audit renewal revived an expired run: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_runs
		SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),
			lease_expires_at=NULL,more_pending=true,error_code='lease_expired'
		WHERE id=$1`, auditRunID); err != nil {
		t.Fatalf("expire audit old-renew run: %v", err)
	}
}

func proveAuditLogRequestedByCascade(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	orgID, actorID := seedAccessEventRetentionPrincipal(t, ctx, pool, "audit-requester-cascade")
	dbNow := accessEventRetentionDatabaseNow(t, ctx, pool)
	startedAt := dbNow.Add(-2 * time.Hour)
	runID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_runs (
			id,org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES($1,$2,'manual','running','audit-requester-cascade',$3,
			30,60,1,1000,100,$4,$5,$6)`, runID, orgID, actorID,
		startedAt.Add(-30*24*time.Hour), startedAt, dbNow.Add(-time.Hour)); err != nil {
		t.Fatalf("seed expired audit requester run: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE audit_log_retention_runs SET requested_by_user_id=NULL WHERE id=$1`, runID); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("direct clearing of expired audit run attribution was accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, actorID); err != nil {
		t.Fatalf("hard user deletion could not apply audit requested-by FK action: %v", err)
	}
	var requesterCleared bool
	var status string
	if err := pool.QueryRow(ctx, `
		SELECT requested_by_user_id IS NULL,status
		FROM audit_log_retention_runs WHERE id=$1`, runID).Scan(&requesterCleared, &status); err != nil {
		t.Fatal(err)
	}
	if !requesterCleared || status != "running" {
		t.Fatalf("audit requested-by FK result cleared=%v status=%q", requesterCleared, status)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_runs
		SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),
			lease_expires_at=NULL,more_pending=true,error_code='lease_expired'
		WHERE id=$1`, runID); err != nil {
		t.Fatalf("expire audit requester run: %v", err)
	}
}

func postgresBackendPID(t *testing.T, ctx context.Context, conn *pgxpool.Conn) int32 {
	t.Helper()
	var pid int32
	if err := conn.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func waitForPostgresLockBeforeLease(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pid int32, leaseExpiresAt time.Time) {
	t.Helper()
	waitForPostgresLock(t, ctx, pool, pid)
	now := accessEventRetentionDatabaseNow(t, ctx, pool)
	if !now.Before(leaseExpiresAt) {
		t.Fatalf("worker reached its lock only after lease expiry: now=%s lease=%s", now, leaseExpiresAt)
	}
}

func waitForPostgresLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, pid int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(ctx, `
			SELECT COALESCE((
				SELECT wait_event_type='Lock'
				FROM pg_stat_activity
				WHERE pid=$1
			),false)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend %d did not enter a PostgreSQL lock wait", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForPostgresBackendBlockedBy(t *testing.T, ctx context.Context, pool *pgxpool.Pool, blockerPID int32) int32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blockedPID int32
		if err := pool.QueryRow(ctx, `
			SELECT COALESCE((
				SELECT pid FROM pg_stat_activity
				WHERE datname=current_database()
				  AND $1=ANY(pg_blocking_pids(pid))
				ORDER BY pid
				LIMIT 1
			),0)`, blockerPID).Scan(&blockedPID); err != nil {
			t.Fatal(err)
		}
		if blockedPID != 0 {
			return blockedPID
		}
		if time.Now().After(deadline) {
			t.Fatalf("no PostgreSQL backend became blocked by backend %d", blockerPID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForDatabaseLeaseExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool, leaseExpiresAt time.Time) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !accessEventRetentionDatabaseNow(t, ctx, pool).Before(leaseExpiresAt) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("database clock did not pass lease expiry %s", leaseExpiresAt)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func receivePostgresCall(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("blocked PostgreSQL call did not return after lock release")
		return nil
	}
}

type accessEventRetentionRunFixture struct {
	orgID                  uuid.UUID
	actorID                uuid.UUID
	key                    string
	retentionDays          int
	cleanupIntervalMinutes int
	settingsRevision       int64
	startedAt              time.Time
	leaseExpiresAt         time.Time
}

func accessEventRetentionDatabaseNow(t *testing.T, ctx context.Context, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT statement_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	return now.UTC().Truncate(time.Microsecond)
}

func seedAccessEventRetentionPrincipal(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	orgID, actorID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,$2,$3,'10.244.0.0/24')`, orgID, "0130 "+label, "access-retention-"+label+"-"+orgID.String()[:8]); err != nil {
		t.Fatalf("seed %s organization: %v", label, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,statement_timestamp())`, actorID, "access-retention-"+label+"-"+actorID.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed %s actor: %v", label, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'admin')`, orgID, actorID); err != nil {
		t.Fatalf("seed %s membership: %v", label, err)
	}
	return orgID, actorID
}

func insertAccessEventRetentionEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, seq int64, createdAt time.Time) uuid.UUID {
	t.Helper()
	eventID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_events
			(id,org_id,seq,occurred_at,decision,src_ip,dst_ip,created_at)
		VALUES($1,$2,$3,$4,'deny','100.64.0.2','100.96.0.2',$4)`, eventID, orgID, seq, createdAt); err != nil {
		t.Fatalf("seed access event: %v", err)
	}
	return eventID
}

func accessEventRetentionCopyRow(orgID uuid.UUID, seq int64, createdAt time.Time) []any {
	return []any{
		uuid.New(), orgID, seq, createdAt, "deny",
		"100.64.0.2", "100.96.0.2", "tcp", createdAt,
	}
}

func insertAccessEventRetentionTestRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, run accessEventRetentionRunFixture) uuid.UUID {
	t.Helper()
	runID := uuid.New()
	cutoffAt := run.startedAt.Add(-time.Duration(run.retentionDays) * 24 * time.Hour)
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_event_retention_runs (
			id,org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,row_cap,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES($1,$2,'manual','running',$3,$4,$5,$6,$7,100000,1000,100,$8,$9,$10)`,
		runID, run.orgID, run.key, run.actorID, run.retentionDays,
		run.cleanupIntervalMinutes, run.settingsRevision, cutoffAt,
		run.startedAt, run.leaseExpiresAt); err != nil {
		t.Fatalf("seed retention run %q: %v", run.key, err)
	}
	return runID
}

func pruneAccessEventRetentionTestRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID) int64 {
	t.Helper()
	var deleted int64
	if err := pool.QueryRow(ctx, `SELECT access_event_retention_prune_batch($1)`, runID).Scan(&deleted); err != nil {
		t.Fatalf("prune access-event retention run %s: %v", runID, err)
	}
	return deleted
}

func finishAccessEventRetentionTestRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID, orgID uuid.UUID) {
	t.Helper()
	result, err := pool.Exec(ctx, `
		UPDATE access_event_retention_runs
		SET status='succeeded',completed_at=GREATEST(clock_timestamp(),started_at),
			lease_expires_at=NULL,more_pending=false,error_code=NULL
		WHERE id=$1 AND org_id=$2 AND status='running'
		  AND lease_expires_at > clock_timestamp()`, runID, orgID)
	if err != nil {
		t.Fatalf("finish retention run %s: %v", runID, err)
	}
	if result.RowsAffected() != 1 {
		t.Fatalf("finish retention run %s affected %d rows", runID, result.RowsAffected())
	}
}

func expireAccessEventRetentionTestRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID, orgID uuid.UUID) {
	t.Helper()
	var expiredRunID uuid.UUID
	if err := pool.QueryRow(ctx, `
		UPDATE access_event_retention_runs
		SET status='failed',completed_at=GREATEST(clock_timestamp(),started_at),
			lease_expires_at=NULL,more_pending=true,error_code='lease_expired'
		WHERE org_id=$1 AND status='running'
		  AND lease_expires_at <= clock_timestamp()
		RETURNING id`, orgID).Scan(&expiredRunID); err != nil {
		t.Fatalf("expire retention run %s: %v", runID, err)
	}
	if expiredRunID != runID {
		t.Fatalf("expired run %s, want %s", expiredRunID, runID)
	}
}

func assertAccessEventRetentionEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventID uuid.UUID, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_events WHERE id=$1)`, eventID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("access event %s exists=%v, want %v", eventID, exists, want)
	}
}

func assertAccessEventRetentionRunTruth(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID, wantDeleted int64, wantBatches int) {
	t.Helper()
	var deletedRows int64
	var batches int
	if err := pool.QueryRow(ctx, `SELECT deleted_rows,batches FROM access_event_retention_runs WHERE id=$1`, runID).Scan(&deletedRows, &batches); err != nil {
		t.Fatal(err)
	}
	if deletedRows != wantDeleted || batches != wantBatches {
		t.Fatalf("run %s truth=(deleted=%d batches=%d), want (%d,%d)", runID, deletedRows, batches, wantDeleted, wantBatches)
	}
}

func assertAccessEventRetentionState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, want int64) {
	t.Helper()
	var retainedRows int64
	if err := pool.QueryRow(ctx, `SELECT retained_rows FROM access_event_retention_state WHERE org_id=$1`, orgID).Scan(&retainedRows); err != nil {
		t.Fatalf("read access-event retention state for %s: %v", orgID, err)
	}
	if retainedRows != want {
		t.Fatalf("access-event retention state for %s = %d, want %d", orgID, retainedRows, want)
	}
}

func assertAccessEventRetentionStateMissing(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_event_retention_state WHERE org_id=$1)`, orgID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("access-event retention state for deleted organization %s still exists", orgID)
	}
}
