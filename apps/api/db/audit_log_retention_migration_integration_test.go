package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestAuditLogRetentionMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0129 PostgreSQL proof")
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
	databaseName := "tnx_audit_retention_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+databaseName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+databaseName+" WITH (FORCE)")
	})
	testURL := *base
	testURL.Path = "/" + databaseName
	dsn := testURL.String()

	// Prove the empty migration is reversible and re-applicable before retaining
	// any durable settings or run history, which intentionally make 0129 down
	// refuse contraction.
	if err := db.MigrateTo(dsn, 128); err != nil {
		t.Fatalf("migrate prerequisite chain through 0128: %v", err)
	}
	if err := db.MigrateTo(dsn, 129); err != nil {
		t.Fatalf("apply 0129: %v", err)
	}
	if err := db.MigrateTo(dsn, 128); err != nil {
		t.Fatalf("empty 0129 down: %v", err)
	}
	if err := db.MigrateTo(dsn, 129); err != nil {
		t.Fatalf("0129 re-up: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	for _, signature := range []string{
		"audit_log_retention_authorized(uuid)",
		"audit_log_retention_prune_batch(uuid)",
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
			t.Fatalf("PUBLIC can execute audit retention function %s", signature)
		}
	}

	fixture := seedAuditLogRetentionMigrationFixture(t, ctx, pool)

	if _, err := pool.Exec(ctx, `DELETE FROM audit_logs WHERE id=$1`, fixture.expiredAuditID); err == nil || !strings.Contains(err.Error(), "audit_logs is append-only") {
		t.Fatalf("ordinary audit DELETE must remain blocked, got %v", err)
	}
	assertAuditLogRetentionRow(t, ctx, pool, fixture.expiredAuditID, true)

	if _, err := pool.Exec(ctx, `SELECT audit_log_retention_prune_batch($1)`, uuid.New()); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("unknown run authorized audit deletion: %v", err)
	}
	assertAuditLogRetentionRow(t, ctx, pool, fixture.expiredAuditID, true)

	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_settings
			(org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id)
		VALUES ($1,30,60,1,$2)`, fixture.orgID, fixture.actorID); err != nil {
		t.Fatalf("seed persisted policy: %v", err)
	}
	queries := sqlc.New(pool)
	dueOrganizations, err := queries.ListDueAuditLogRetentionOrganizations(ctx, 10)
	if err != nil {
		t.Fatalf("list due organizations with expired ordinary evidence: %v", err)
	}
	if !containsAuditLogRetentionOrg(dueOrganizations, fixture.orgID) {
		t.Fatalf("bounded policy with expired ordinary evidence absent from due scan: %v", dueOrganizations)
	}
	due, err := queries.IsAuditLogRetentionDue(ctx, sqlc.IsAuditLogRetentionDueParams{
		OrgID: fixture.orgID, CleanupIntervalMinutes: 60,
	})
	if err != nil || due == nil || !*due {
		t.Fatalf("bounded policy with expired ordinary evidence due=%v err=%v", due, err)
	}

	// A forward-skewed application host must not be able to mint a future
	// cutoff and turn a fresh audit row into deletion-eligible evidence. The
	// security-definer function independently fences its run against DB time.
	freshAuditID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_logs(id,org_id,actor_user_id,action,created_at)
		VALUES($1,$2,$3,'retention.fresh_clock_skew',statement_timestamp())`,
		freshAuditID, fixture.orgID, fixture.actorID); err != nil {
		t.Fatalf("seed fresh clock-skew audit: %v", err)
	}
	futureStartedAt := now.Add(31 * 24 * time.Hour)
	futureRunID := uuid.New()
	insertAuditLogRetentionRun(t, ctx, pool, auditLogRetentionRunFixture{
		id: futureRunID, orgID: fixture.orgID, actorID: fixture.actorID,
		key: "forward-skewed-clock", retentionDays: 30, cleanupIntervalMinutes: 60,
		settingsRevision: 1, startedAt: futureStartedAt,
		leaseExpiresAt: futureStartedAt.Add(15 * time.Minute),
	})
	if _, err := pool.Exec(ctx, `SELECT audit_log_retention_prune_batch($1)`, futureRunID); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("forward-skewed run authorized premature deletion: %v", err)
	}
	assertAuditLogRetentionRow(t, ctx, pool, freshAuditID, true)
	finishAuditLogRetentionTestRun(t, ctx, pool, futureRunID, futureStartedAt.Add(time.Second))

	mismatchedRunID := uuid.New()
	insertAuditLogRetentionRun(t, ctx, pool, auditLogRetentionRunFixture{
		id: mismatchedRunID, orgID: fixture.orgID, actorID: fixture.actorID,
		key: "policy-mismatch", retentionDays: 30, cleanupIntervalMinutes: 60,
		settingsRevision: 2, startedAt: now, leaseExpiresAt: now.Add(15 * time.Minute),
	})
	if _, err := pool.Exec(ctx, `SELECT audit_log_retention_prune_batch($1)`, mismatchedRunID); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("run not matching the live persisted policy authorized deletion: %v", err)
	}
	assertAuditLogRetentionRow(t, ctx, pool, fixture.expiredAuditID, true)
	finishAuditLogRetentionTestRun(t, ctx, pool, mismatchedRunID, now.Add(time.Second))

	expiredStartedAt := now.Add(-2 * time.Hour)
	expiredRunID := uuid.New()
	insertAuditLogRetentionRun(t, ctx, pool, auditLogRetentionRunFixture{
		id: expiredRunID, orgID: fixture.orgID, actorID: fixture.actorID,
		key: "expired-lease", retentionDays: 30, cleanupIntervalMinutes: 60,
		settingsRevision: 1, startedAt: expiredStartedAt,
		leaseExpiresAt: expiredStartedAt.Add(time.Hour),
	})
	tag, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_runs
		SET lease_expires_at=$2
		WHERE id=$1 AND status='running' AND lease_expires_at > statement_timestamp()`,
		expiredRunID, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("attempt expired lease renewal: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("expired run renewed %d rows", tag.RowsAffected())
	}
	if _, err := pool.Exec(ctx, `SELECT audit_log_retention_prune_batch($1)`, expiredRunID); err == nil || !strings.Contains(err.Error(), "audit_log_retention_run_not_owned") {
		t.Fatalf("expired run authorized audit deletion: %v", err)
	}
	assertAuditLogRetentionRow(t, ctx, pool, fixture.expiredAuditID, true)
	finishAuditLogRetentionTestRun(t, ctx, pool, expiredRunID, now)

	liveStartedAt := now.Add(-2 * time.Hour)
	liveRunID := uuid.New()
	insertAuditLogRetentionRun(t, ctx, pool, auditLogRetentionRunFixture{
		id: liveRunID, orgID: fixture.orgID, actorID: fixture.actorID,
		key: "exact-live-policy", retentionDays: 30, cleanupIntervalMinutes: 60,
		settingsRevision: 1, startedAt: liveStartedAt, leaseExpiresAt: now.Add(15 * time.Minute),
	})
	var deleted int64
	if err := pool.QueryRow(ctx, `SELECT audit_log_retention_prune_batch($1)`, liveRunID).Scan(&deleted); err != nil {
		t.Fatalf("exact live persisted-policy run prune: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("exact live prune deleted %d rows, want only the ordinary expired row", deleted)
	}
	assertAuditLogRetentionRunTruth(t, ctx, pool, liveRunID, "running", 1, 1)
	assertAuditLogRetentionRow(t, ctx, pool, fixture.expiredAuditID, false)
	assertAuditLogRetentionRow(t, ctx, pool, fixture.pinnedAuditID, true)

	// A no-op batch does not consume the durable batch budget. Leave the run
	// unfinalized to model a worker crash after its irreversible DELETE commits.
	// Lease expiry must preserve the counters written atomically by the prune.
	if err := pool.QueryRow(ctx, `SELECT audit_log_retention_prune_batch($1)`, liveRunID).Scan(&deleted); err != nil {
		t.Fatalf("no-op exact live prune: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("pinned-only follow-up prune deleted %d rows", deleted)
	}
	assertAuditLogRetentionRunTruth(t, ctx, pool, liveRunID, "running", 1, 1)
	if _, err := pool.Exec(ctx, `UPDATE audit_log_retention_runs SET lease_expires_at=$2 WHERE id=$1`, liveRunID, liveStartedAt.Add(time.Hour)); err != nil {
		t.Fatalf("simulate post-commit worker lease expiry: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_settings
		SET retention_days=NULL,revision=revision+1
		WHERE org_id=$1`, fixture.orgID); err != nil {
		t.Fatalf("switch crashed run policy back to Forever: %v", err)
	}
	recoveryDue, err := queries.ListDueAuditLogRetentionOrganizations(ctx, 10)
	if err != nil {
		t.Fatalf("list expired claim after final batch: %v", err)
	}
	if !containsAuditLogRetentionOrg(recoveryDue, fixture.orgID) {
		t.Fatalf("expired claim with no eligible rows and Forever policy was stranded: %v", recoveryDue)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_runs
		SET status='failed',completed_at=$2,lease_expires_at=NULL,
			more_pending=true,error_code='lease_expired'
		WHERE id=$1 AND status='running' AND lease_expires_at <= $2`, liveRunID, now); err != nil {
		t.Fatalf("expire crashed retention run: %v", err)
	}
	assertAuditLogRetentionRunTruth(t, ctx, pool, liveRunID, "failed", 1, 1)

	var pinnedByHandoff bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM k8s_connector_handoff_operations
			WHERE org_id=$1 AND cas_audit_id=$2 AND cas_audit_applied
		)`, fixture.orgID, fixture.pinnedAuditID).Scan(&pinnedByHandoff); err != nil {
		t.Fatal(err)
	}
	if !pinnedByHandoff {
		t.Fatal("retained CAS audit row is not pinned by the expected handoff operation")
	}
	var authorizationRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log_retention_authorizations`).Scan(&authorizationRows); err != nil {
		t.Fatal(err)
	}
	if authorizationRows != 0 {
		t.Fatalf("retention authorization capability leaked %d rows after prune", authorizationRows)
	}

	// Once the only expired row left is FK-pinned CAS evidence, the tenant must
	// not remain scheduler-eligible regardless of prior run state.
	dueOrganizations, err = queries.ListDueAuditLogRetentionOrganizations(ctx, 10)
	if err != nil {
		t.Fatalf("list due organizations with pinned-only evidence: %v", err)
	}
	if containsAuditLogRetentionOrg(dueOrganizations, fixture.orgID) {
		t.Fatalf("pinned-only tenant remained scheduler-eligible: %v", dueOrganizations)
	}
	due, err = queries.IsAuditLogRetentionDue(ctx, sqlc.IsAuditLogRetentionDueParams{
		OrgID: fixture.orgID, CleanupIntervalMinutes: 60,
	})
	if err != nil || due == nil || *due {
		t.Fatalf("pinned-only tenant due=%v err=%v, want false", due, err)
	}
}

type auditLogRetentionMigrationFixture struct {
	orgID          uuid.UUID
	actorID        uuid.UUID
	expiredAuditID uuid.UUID
	pinnedAuditID  uuid.UUID
}

func seedAuditLogRetentionMigrationFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) auditLogRetentionMigrationFixture {
	t.Helper()
	orgID, actorID := uuid.New(), uuid.New()
	siteID, clusterID, connectorPoolID := uuid.New(), uuid.New(), uuid.New()
	oldNodeID, newNodeID := uuid.New(), uuid.New()
	expiredAuditID, pinnedAuditID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)

	exec := func(label, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}
	exec("seed organization", `INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0129 retention proof',$2,'10.245.0.0/24')`, orgID, "audit-retention-"+orgID.String()[:8])
	exec("seed actor", `INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, actorID, "audit-retention-"+actorID.String()[:8]+"@example.com")
	exec("seed actor membership", `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'admin')`, orgID, actorID)
	exec("seed site", `INSERT INTO sites(id,org_id,name) VALUES($1,$2,'0129 retention site')`, siteID, orgID)
	exec("seed old connector", `INSERT INTO nodes(id,org_id,site_id,name,cert_serial) VALUES($1,$2,$3,'0129 old connector',$4)`, oldNodeID, orgID, siteID, "0129-old-"+oldNodeID.String())
	exec("seed new connector", `INSERT INTO nodes(id,org_id,site_id,name,cert_serial) VALUES($1,$2,$3,'0129 new connector',$4)`, newNodeID, orgID, siteID, "0129-new-"+newNodeID.String())
	exec("seed cluster", `INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range) VALUES($1,$2,$3,'0129 retention cluster','100.124.0.0/24')`, clusterID, orgID, siteID)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO k8s_connector_pools
			(id,org_id,site_id,cluster_id,preferred_node_id,active_node_id,generation)
		VALUES($1,$2,$3,$4,$5,$5,1)`, connectorPoolID, orgID, siteID, clusterID, oldNodeID); err == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO k8s_connector_pool_members(pool_id,org_id,site_id,node_id)
			VALUES($1,$2,$3,$4),($1,$2,$3,$5)`, connectorPoolID, orgID, siteID, oldNodeID, newNodeID)
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("seed connector pool: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit connector pool: %v", err)
	}

	oldCreatedAt := now.Add(-45 * 24 * time.Hour)
	exec("seed ordinary expired audit", `
		INSERT INTO audit_logs(id,org_id,actor_user_id,action,created_at)
		VALUES($1,$2,$3,'retention.ordinary_expired',$4)`, expiredAuditID, orgID, actorID, oldCreatedAt)
	exec("seed pinned expired audit", `
		INSERT INTO audit_logs(id,org_id,actor_user_id,action,created_at)
		VALUES($1,$2,$3,'k8s.connector_handoff_cas',$4)`, pinnedAuditID, orgID, actorID, oldCreatedAt.Add(-time.Second))
	insertAuditLogRetentionPinnedHandoff(t, ctx, pool, orgID, siteID, clusterID, connectorPoolID, oldNodeID, newNodeID, pinnedAuditID, now)

	return auditLogRetentionMigrationFixture{
		orgID: orgID, actorID: actorID,
		expiredAuditID: expiredAuditID, pinnedAuditID: pinnedAuditID,
	}
}

func insertAuditLogRetentionPinnedHandoff(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, siteID, clusterID, connectorPoolID, oldNodeID, newNodeID, auditID uuid.UUID, now time.Time) {
	t.Helper()
	servingRouteDigest := strings.Repeat("a", 64)
	servingVIPDigest := strings.Repeat("b", 64)
	emptyRouteDigest := "5a5b4496f8450b9f72a61fe951ee55dff755371bdbdb0ed910273674a6ec947d"
	if _, err := pool.Exec(ctx, `
		INSERT INTO k8s_connector_handoff_operations (
			id,org_id,site_id,pool_id,cluster_id,old_node_id,new_node_id,
			expected_generation,target_generation,
			old_serving_manifest_identity,candidate_prepared_manifest_identity,
			old_withdrawal_manifest_identity,new_serving_manifest_identity,
			old_serving_manifest_revision,candidate_prepared_manifest_revision,
			old_withdrawal_manifest_revision,new_serving_manifest_revision,
			old_serving_expected_route_digest,old_serving_expected_vip_map_digest,
			candidate_prepared_expected_route_digest,candidate_prepared_expected_vip_map_digest,
			old_withdrawal_expected_route_digest,old_withdrawal_expected_vip_map_digest,
			new_serving_expected_route_digest,new_serving_expected_vip_map_digest,
			old_lease_identity,target_lease_identity,old_lease_epoch,target_lease_epoch,
			old_lease_expires_at,target_lease_expires_at,decision_transition,
			phase,prepared_ack_received_at,withdrawal_ack_received_at,
			cas_receipt_at,cas_audit_id,cas_audit_applied
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,1,2,
			'old-serving','candidate-prepared','old-withdrawal','new-serving',
			1,2,2,3,$8,$9,$10,'',$10,'',$8,$9,
			'old-lease','target-lease',1,2,$11,$12,'promoted',
			'enable_serving',$13,$13,$13,$14,true
		)`, uuid.New(), orgID, siteID, connectorPoolID, clusterID, oldNodeID, newNodeID,
		servingRouteDigest, servingVIPDigest, emptyRouteDigest,
		now.Add(time.Hour), now.Add(2*time.Hour), now, auditID); err != nil {
		t.Fatalf("seed FK-pinned handoff CAS evidence: %v", err)
	}
}

type auditLogRetentionRunFixture struct {
	id                     uuid.UUID
	orgID                  uuid.UUID
	actorID                uuid.UUID
	key                    string
	retentionDays          int
	cleanupIntervalMinutes int
	settingsRevision       int64
	startedAt              time.Time
	leaseExpiresAt         time.Time
}

func insertAuditLogRetentionRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, run auditLogRetentionRunFixture) {
	t.Helper()
	cutoffAt := run.startedAt.Add(-time.Duration(run.retentionDays) * 24 * time.Hour)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_runs (
			id,org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES ($1,$2,'manual','running',$3,$4,$5,$6,$7,1000,100,$8,$9,$10)`,
		run.id, run.orgID, run.key, run.actorID, run.retentionDays,
		run.cleanupIntervalMinutes, run.settingsRevision, cutoffAt,
		run.startedAt, run.leaseExpiresAt); err != nil {
		t.Fatalf("seed retention run %q: %v", run.key, err)
	}
}

func finishAuditLogRetentionTestRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID, completedAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		UPDATE audit_log_retention_runs
		SET status='failed',completed_at=$2,lease_expires_at=NULL,error_code='test_finished'
		WHERE id=$1`, runID, completedAt); err != nil {
		t.Fatalf("finish retention test run %s: %v", runID, err)
	}
}

func assertAuditLogRetentionRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, auditID uuid.UUID, want bool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id=$1)`, auditID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != want {
		t.Fatalf("audit row %s exists=%v, want %v", auditID, exists, want)
	}
}

func assertAuditLogRetentionRunTruth(t *testing.T, ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID, wantStatus string, wantDeleted int64, wantBatches int) {
	t.Helper()
	var (
		status      string
		deletedRows int64
		batches     int
	)
	if err := pool.QueryRow(ctx, `
		SELECT status,deleted_rows,batches
		FROM audit_log_retention_runs
		WHERE id=$1`, runID).Scan(&status, &deletedRows, &batches); err != nil {
		t.Fatal(err)
	}
	if status != wantStatus || deletedRows != wantDeleted || batches != wantBatches {
		t.Fatalf("run %s truth=(status=%q deleted=%d batches=%d), want (%q,%d,%d)", runID, status, deletedRows, batches, wantStatus, wantDeleted, wantBatches)
	}
}

func containsAuditLogRetentionOrg(orgIDs []uuid.UUID, want uuid.UUID) bool {
	for _, orgID := range orgIDs {
		if orgID == want {
			return true
		}
	}
	return false
}
