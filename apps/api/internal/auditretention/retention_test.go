package auditretention

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func days(value int32) *int32 { return &value }

func TestSettingsValidationAllowsForeverAndEnforcesBounds(t *testing.T) {
	tests := []struct {
		name string
		in   SettingsInput
		code string
	}{
		{"forever", SettingsInput{RetentionDays: nil, CleanupIntervalMinutes: 60}, ""},
		{"minimums", SettingsInput{RetentionDays: days(1), CleanupIntervalMinutes: 5}, ""},
		{"maximums", SettingsInput{RetentionDays: days(3650), CleanupIntervalMinutes: 1440}, ""},
		{"days low", SettingsInput{RetentionDays: days(0), CleanupIntervalMinutes: 60}, "invalid_audit_log_retention_days"},
		{"days high", SettingsInput{RetentionDays: days(3651), CleanupIntervalMinutes: 60}, "invalid_audit_log_retention_days"},
		{"interval low", SettingsInput{RetentionDays: nil, CleanupIntervalMinutes: 4}, "invalid_audit_log_cleanup_interval"},
		{"interval high", SettingsInput{RetentionDays: nil, CleanupIntervalMinutes: 1441}, "invalid_audit_log_cleanup_interval"},
		{"revision", SettingsInput{RetentionDays: nil, CleanupIntervalMinutes: 60, ExpectedRevision: -1}, "invalid_expected_revision"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSettings(tt.in)
			if tt.code == "" {
				if err != nil {
					t.Fatalf("valid settings rejected: %v", err)
				}
				return
			}
			var got *apierr.Error
			if !errors.As(err, &got) || got.Code != tt.code {
				t.Fatalf("error = %v, want API code %q", err, tt.code)
			}
		})
	}
}

func TestManualIdempotencyKeyPattern(t *testing.T) {
	for _, key := range []string{"request-1", "request_1", "request.1", "request:1", "A9"} {
		if err := validateManual(uuid.New(), key); err != nil {
			t.Errorf("valid key %q rejected: %v", key, err)
		}
	}
	for _, key := range []string{"", " leading", "trailing ", "slash/key", "unicode-λ", string(make([]byte, 129))} {
		if err := validateManual(uuid.New(), key); err == nil {
			t.Errorf("invalid key %q accepted", key)
		}
	}
}

func retentionFixture(t *testing.T) (*pgxpool.Pool, *Service, uuid.UUID, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'audit retention',$2)`, org, "audit-retention-"+org.String()); err != nil {
		t.Fatalf("organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Audit Retention Owner',now())`, actor, fmt.Sprintf("%s@example.test", actor)); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, actor); err != nil {
		t.Fatalf("membership: %v", err)
	}
	return pool, NewService(pool), org, actor
}

func TestDefaultIsForeverAndCASIsAuditedOnce(t *testing.T) {
	pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()

	got, err := service.GetSettings(ctx, org)
	if err != nil {
		t.Fatalf("get defaults: %v", err)
	}
	if got.RetentionDays != nil || got.CleanupIntervalMinutes != 60 || got.Revision != 0 || got.UpdatedAt != nil {
		t.Fatalf("unexpected effective defaults: %+v", got)
	}
	if _, _, err := service.RunManual(ctx, org, actor, "forever-refusal"); !hasCode(err, "audit_log_retention_disabled") {
		t.Fatalf("manual prune under Forever = %v", err)
	}
	if due, err := service.ListDueOrganizations(ctx, 100); err != nil || containsUUID(due, org) {
		t.Fatalf("Forever organization became due: %v, %v", due, err)
	}

	got, err = service.SetSettings(ctx, org, actor, SettingsInput{
		RetentionDays: days(90), CleanupIntervalMinutes: 120, ExpectedRevision: 0,
	})
	if err != nil || got.RetentionDays == nil || *got.RetentionDays != 90 || got.Revision != 1 {
		t.Fatalf("first bounded policy = %+v, %v", got, err)
	}
	assertPolicyCounts(t, pool, org, 1, 1)

	// Exact transition replay is side-effect free.
	got, err = service.SetSettings(ctx, org, actor, SettingsInput{
		RetentionDays: days(90), CleanupIntervalMinutes: 120, ExpectedRevision: 0,
	})
	if err != nil || got.Revision != 1 {
		t.Fatalf("exact replay = %+v, %v", got, err)
	}
	assertPolicyCounts(t, pool, org, 1, 1)

	got, err = service.SetSettings(ctx, org, actor, SettingsInput{
		RetentionDays: nil, CleanupIntervalMinutes: 60, ExpectedRevision: 1,
	})
	if err != nil || got.RetentionDays != nil || got.Revision != 2 {
		t.Fatalf("restore Forever = %+v, %v", got, err)
	}
	assertPolicyCounts(t, pool, org, 1, 2)
	overview, err := service.GetOverview(ctx, org)
	if err != nil || overview.NextRunAt != nil {
		t.Fatalf("Forever overview scheduled cleanup: %+v, %v", overview, err)
	}
}

func TestManualPruneIsOldOnlyTenantScopedBatchedAndIdempotent(t *testing.T) {
	pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := service.SetSettings(ctx, org, actor, SettingsInput{
		RetentionDays: days(30), CleanupIntervalMinutes: 60, ExpectedRevision: 0,
	}); err != nil {
		t.Fatalf("save bounded policy: %v", err)
	}

	other := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'audit retention other',$2)`, other, "audit-retention-other-"+other.String()); err != nil {
		t.Fatalf("other organization: %v", err)
	}
	old := now.Add(-31 * 24 * time.Hour)
	fresh := now.Add(-24 * time.Hour)
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_logs(org_id,action,created_at)
		SELECT $1,'old.audit', $2 FROM generate_series(1,1005)`, org, old); err != nil {
		t.Fatalf("old audit rows: %v", err)
	}
	var freshID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO audit_logs(org_id,action,created_at) VALUES($1,'fresh.audit',$2) RETURNING id`, org, fresh).Scan(&freshID); err != nil {
		t.Fatalf("fresh audit row: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO audit_logs(org_id,action,created_at) VALUES($1,'other.audit',$2)`, other, old); err != nil {
		t.Fatalf("other audit row: %v", err)
	}

	// Ordinary direct deletion remains blocked even after retention is enabled.
	if _, err := pool.Exec(ctx, `DELETE FROM audit_logs WHERE id=$1`, freshID); err == nil {
		t.Fatal("ordinary DELETE bypassed append-only audit protection")
	}

	run, claimed, err := service.RunManual(ctx, org, actor, "audit-manual-1")
	if err != nil {
		t.Fatalf("manual prune: %v", err)
	}
	if !claimed || run.Status != RetentionRunSucceeded || run.DeletedRows != 1005 || run.Batches != 2 || run.MorePending {
		t.Fatalf("unexpected run: claimed=%v run=%+v", claimed, run)
	}
	assertActionCount(t, pool, org, "old.audit", 0)
	assertActionCount(t, pool, org, "fresh.audit", 1)
	assertActionCount(t, pool, other, "other.audit", 1)

	replay, claimed, err := service.RunManual(ctx, org, actor, "audit-manual-1")
	if err != nil || claimed || replay.ID != run.ID || replay.DeletedRows != run.DeletedRows {
		t.Fatalf("manual replay: claimed=%v run=%+v err=%v", claimed, replay, err)
	}
	assertActionCount(t, pool, org, "audit_log_retention.prune_requested", 1)
}

func TestScheduledPruneRequiresExplicitBoundedPolicy(t *testing.T) {
	pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(ctx, `INSERT INTO audit_logs(org_id,action,created_at) VALUES($1,'old.audit',$2)`, org, now.Add(-31*24*time.Hour)); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("Forever scheduled run: claimed=%v err=%v", claimed, err)
	}
	if _, err := service.SetSettings(ctx, org, actor, SettingsInput{
		RetentionDays: days(30), CleanupIntervalMinutes: 5, ExpectedRevision: 0,
	}); err != nil {
		t.Fatalf("save bounded policy: %v", err)
	}
	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil || !containsUUID(due, org) {
		t.Fatalf("bounded organization not due: %v, %v", due, err)
	}
	run, claimed, err := service.RunScheduled(ctx, org)
	if err != nil || !claimed || run.DeletedRows != 1 || run.Status != RetentionRunSucceeded {
		t.Fatalf("scheduled run: claimed=%v run=%+v err=%v", claimed, run, err)
	}
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("same-clock rerun: claimed=%v err=%v", claimed, err)
	}
}

func TestScheduledRunHistoryIsBoundedWithoutEvictingManualIdempotency(t *testing.T) {
	pool, _, org, actor := retentionFixture(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		WITH moments AS (
			SELECT statement_timestamp() - n * interval '1 second' AS at
			FROM generate_series(1,1001) AS n
		)
		INSERT INTO audit_log_retention_runs (
			org_id,trigger_kind,status,retention_days,cleanup_interval_minutes,
			settings_revision,batch_size,max_batches,cutoff_at,started_at,
			completed_at,deleted_rows,batches,more_pending
		)
		SELECT $1,'scheduled','succeeded',30,60,1,1000,100,
			at - interval '30 days',at,at,0,0,false
		FROM moments`, org); err != nil {
		t.Fatalf("seed scheduled run history: %v", err)
	}
	manualKey := "manual-idempotency-survives-history-compaction"
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_log_retention_runs (
			org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,batch_size,
			max_batches,cutoff_at,started_at,completed_at,deleted_rows,batches,more_pending
		) VALUES (
			$1,'manual','succeeded',$2,$3,30,60,1,1000,100,
			statement_timestamp() - interval '31 days',
			statement_timestamp() - interval '1 day',
			statement_timestamp() - interval '1 day',0,0,false
		)`, org, manualKey, actor); err != nil {
		t.Fatalf("seed manual run history: %v", err)
	}

	if err := pruneScheduledRunHistory(ctx, sqlc.New(pool), org); err != nil {
		t.Fatalf("compact scheduled history: %v", err)
	}
	var scheduled, manual int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE trigger_kind='scheduled'),
		       count(*) FILTER (WHERE trigger_kind='manual' AND manual_idempotency_key=$2)
		FROM audit_log_retention_runs WHERE org_id=$1`, org, manualKey).Scan(&scheduled, &manual); err != nil {
		t.Fatalf("count compacted history: %v", err)
	}
	if scheduled != int(RetentionScheduledHistoryLimit-1) || manual != 1 {
		t.Fatalf("retained scheduled/manual history = %d/%d, want %d/1", scheduled, manual, RetentionScheduledHistoryLimit-1)
	}
}

func hasCode(err error, code string) bool {
	var apiError *apierr.Error
	return errors.As(err, &apiError) && apiError.Code == code
}

func assertPolicyCounts(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, settings, audits int) {
	t.Helper()
	var gotSettings, gotAudits int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log_retention_settings WHERE org_id=$1`, org).Scan(&gotSettings); err != nil {
		t.Fatalf("count settings: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='audit_log_retention.settings_changed'`, org).Scan(&gotAudits); err != nil {
		t.Fatalf("count policy audits: %v", err)
	}
	if gotSettings != settings || gotAudits != audits {
		t.Fatalf("settings/audits = %d/%d, want %d/%d", gotSettings, gotAudits, settings, audits)
	}
}

func assertActionCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, action string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action=$2`, org, action).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", action, err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", action, got, want)
	}
}

func containsUUID(values []uuid.UUID, want uuid.UUID) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
