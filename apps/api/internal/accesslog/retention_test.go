package accesslog

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func TestRetentionSettingsValidationBounds(t *testing.T) {
	tests := []struct {
		name string
		in   RetentionSettingsInput
		code string
	}{
		{"minimums", RetentionSettingsInput{RetentionDays: 1, CleanupIntervalMinutes: 5}, ""},
		{"maximums", RetentionSettingsInput{RetentionDays: 3650, CleanupIntervalMinutes: 1440}, ""},
		{"days low", RetentionSettingsInput{RetentionDays: 0, CleanupIntervalMinutes: 60}, "invalid_access_event_retention_days"},
		{"days high", RetentionSettingsInput{RetentionDays: 3651, CleanupIntervalMinutes: 60}, "invalid_access_event_retention_days"},
		{"interval low", RetentionSettingsInput{RetentionDays: 30, CleanupIntervalMinutes: 4}, "invalid_access_event_cleanup_interval"},
		{"interval high", RetentionSettingsInput{RetentionDays: 30, CleanupIntervalMinutes: 1441}, "invalid_access_event_cleanup_interval"},
		{"revision", RetentionSettingsInput{RetentionDays: 30, CleanupIntervalMinutes: 60, ExpectedRevision: -1}, "invalid_expected_revision"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRetentionSettings(tt.in)
			if tt.code == "" {
				if err != nil {
					t.Fatalf("valid bounds rejected: %v", err)
				}
				return
			}
			var got *apierr.Error
			if !errors.As(err, &got) || got.Code != tt.code {
				t.Fatalf("error = %v, want api code %q", err, tt.code)
			}
		})
	}
}

func TestManualRetentionIdempotencyKeyPattern(t *testing.T) {
	for _, key := range []string{"request-1", "request_1", "request.1", "request:1", "A9"} {
		if err := validateManualRetention(uuid.New(), key); err != nil {
			t.Errorf("valid key %q rejected: %v", key, err)
		}
	}
	for _, key := range []string{"", " leading", "trailing ", "slash/key", "unicode-λ", string(make([]byte, 129))} {
		if err := validateManualRetention(uuid.New(), key); err == nil {
			t.Errorf("invalid key %q accepted", key)
		}
	}
}

func retentionFixture(t *testing.T) (*sqlc.Queries, *pgxpool.Pool, *RetentionService, uuid.UUID, uuid.UUID) {
	t.Helper()
	q, pool := storeQ(t)
	ctx := context.Background()
	org, actor := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'retention',$2)`, org, "retention-"+org.String()); err != nil {
		t.Fatalf("organization: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name,email_verified_at) VALUES($1,$2,'Retention Owner',now())`, actor, fmt.Sprintf("%s@example.test", actor)); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, actor); err != nil {
		t.Fatalf("membership: %v", err)
	}
	return q, pool, NewRetentionService(pool, nil), org, actor
}

func TestRetentionSettingsDefaultCASAndAuditIdempotency(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()

	got, err := service.GetSettings(ctx, org)
	if err != nil {
		t.Fatalf("get defaults: %v", err)
	}
	if got.RetentionDays != 30 || got.CleanupIntervalMinutes != 60 || got.Revision != 0 || got.UpdatedAt != nil || got.UpdatedByUserID != nil {
		t.Fatalf("unexpected effective defaults: %+v", got)
	}
	// Writing the effective default is a true no-op: no row, revision or audit.
	got, err = service.SetSettings(ctx, org, actor, RetentionSettingsInput{RetentionDays: 30, CleanupIntervalMinutes: 60, ExpectedRevision: 0})
	if err != nil || got.Revision != 0 {
		t.Fatalf("default no-op = %+v, %v", got, err)
	}
	assertRetentionCounts(t, pool, org, 0, 0)

	got, err = service.SetSettings(ctx, org, actor, RetentionSettingsInput{RetentionDays: 45, CleanupIntervalMinutes: 120, ExpectedRevision: 0})
	if err != nil || got.Revision != 1 || got.RetentionDays != 45 || got.CleanupIntervalMinutes != 120 {
		t.Fatalf("first persisted setting = %+v, %v", got, err)
	}
	assertRetentionCounts(t, pool, org, 1, 1)

	// Exact replay of the committed rev-0 -> rev-1 transition.
	replayed, err := service.SetSettings(ctx, org, actor, RetentionSettingsInput{RetentionDays: 45, CleanupIntervalMinutes: 120, ExpectedRevision: 0})
	if err != nil || replayed.Revision != 1 {
		t.Fatalf("exact retry = %+v, %v", replayed, err)
	}
	assertRetentionCounts(t, pool, org, 1, 1)

	// Current-revision same-value write is also side-effect free.
	if _, err := service.SetSettings(ctx, org, actor, RetentionSettingsInput{RetentionDays: 45, CleanupIntervalMinutes: 120, ExpectedRevision: 1}); err != nil {
		t.Fatalf("current no-op: %v", err)
	}
	assertRetentionCounts(t, pool, org, 1, 1)

	_, err = service.SetSettings(ctx, org, actor, RetentionSettingsInput{RetentionDays: 46, CleanupIntervalMinutes: 120, ExpectedRevision: 0})
	var conflict *apierr.Error
	if !errors.As(err, &conflict) || conflict.Code != "access_event_retention_revision_conflict" {
		t.Fatalf("stale CAS = %v, want revision conflict", err)
	}
	assertRetentionCounts(t, pool, org, 1, 1)

	got, err = service.SetSettings(ctx, org, actor, RetentionSettingsInput{RetentionDays: 46, CleanupIntervalMinutes: 5, ExpectedRevision: 1})
	if err != nil || got.Revision != 2 {
		t.Fatalf("second setting = %+v, %v", got, err)
	}
	assertRetentionCounts(t, pool, org, 1, 2)
}

func assertRetentionCounts(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, settings, audits int) {
	t.Helper()
	ctx := context.Background()
	var gotSettings, gotAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_event_retention_settings WHERE org_id=$1`, org).Scan(&gotSettings); err != nil {
		t.Fatalf("count settings: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='access_event_retention.settings_changed'`, org).Scan(&gotAudits); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if gotSettings != settings || gotAudits != audits {
		t.Fatalf("settings/audits = %d/%d, want %d/%d", gotSettings, gotAudits, settings, audits)
	}
}

func TestManualRetentionIsTenantScopedBatchedAndIdempotent(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	other := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name,slug) VALUES($1,'retention-other',$2)`, other, "retention-other-"+other.String()); err != nil {
		t.Fatalf("other organization: %v", err)
	}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	insertRetentionEvents(t, pool, org, 1005, now.Add(-31*24*time.Hour))
	insertRetentionEvents(t, pool, other, 3, now.Add(-31*24*time.Hour))

	run, claimed, err := service.RunManual(ctx, org, actor, "manual-batched-1")
	if err != nil {
		t.Fatalf("manual run: %v", err)
	}
	if !claimed || run.Status != RetentionRunSucceeded || run.DeletedRows != 1005 || run.Batches != 2 || run.MorePending {
		t.Fatalf("unexpected completed run: claimed=%v run=%+v", claimed, run)
	}
	assertEventCount(t, pool, org, 0)
	assertEventCount(t, pool, other, 3)

	replay, claimed, err := service.RunManual(ctx, org, actor, "manual-batched-1")
	if err != nil || claimed || replay.ID != run.ID || replay.DeletedRows != run.DeletedRows {
		t.Fatalf("manual replay: claimed=%v run=%+v err=%v", claimed, replay, err)
	}
	var requestAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='access_event_retention.prune_requested'`, org).Scan(&requestAudits); err != nil {
		t.Fatalf("count request audits: %v", err)
	}
	if requestAudits != 1 {
		t.Fatalf("manual replay emitted %d request audits, want 1", requestAudits)
	}

	overview, err := service.GetOverview(ctx, org)
	if err != nil || overview.LastRun == nil || overview.LastRun.ID != run.ID || overview.NextRunAt == nil || !overview.NextRunAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("durable overview = %+v, %v", overview, err)
	}
}

func TestManualRetentionReplayReturnsItsOriginalRunAfterANewerRun(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 3, 13, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	insertRetentionEvents(t, pool, org, 1, now.Add(-31*24*time.Hour))

	original, claimed, err := service.RunManual(ctx, org, actor, "manual-original")
	if err != nil || !claimed {
		t.Fatalf("original manual run: claimed=%v run=%+v err=%v", claimed, original, err)
	}
	now = now.Add(time.Minute)
	newer, claimed, err := service.RunManual(ctx, org, actor, "manual-newer")
	if err != nil || !claimed || newer.ID == original.ID {
		t.Fatalf("newer manual run: claimed=%v run=%+v err=%v", claimed, newer, err)
	}

	replayed, claimed, err := service.RunManual(ctx, org, actor, "manual-original")
	if err != nil || claimed || replayed.ID != original.ID || replayed.DeletedRows != original.DeletedRows {
		t.Fatalf("historical replay: claimed=%v run=%+v err=%v", claimed, replayed, err)
	}
	overview, err := service.GetOverview(ctx, org)
	if err != nil || overview.LastRun == nil || overview.LastRun.ID != newer.ID {
		t.Fatalf("latest overview changed by historical replay: %+v, %v", overview, err)
	}
	var requestAudits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='access_event_retention.prune_requested'`, org).Scan(&requestAudits); err != nil {
		t.Fatalf("count request audits: %v", err)
	}
	if requestAudits != 2 {
		t.Fatalf("historical replay emitted a duplicate request audit: got %d, want 2", requestAudits)
	}
}

func TestScheduledRetentionHonorsDueInterval(t *testing.T) {
	_, pool, service, org, _ := retentionFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 3, 14, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	insertRetentionEvents(t, pool, org, 1, now)

	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil || !containsUUID(due, org) {
		t.Fatalf("new event org not due: orgs=%v err=%v", due, err)
	}
	run, claimed, err := service.RunScheduled(ctx, org)
	if err != nil || !claimed || run.Status != RetentionRunSucceeded || run.DeletedRows != 0 {
		t.Fatalf("first scheduled run: claimed=%v run=%+v err=%v", claimed, run, err)
	}
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("same-clock rerun: claimed=%v err=%v", claimed, err)
	}
	now = now.Add(59 * time.Minute)
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("pre-interval rerun: claimed=%v err=%v", claimed, err)
	}
	now = now.Add(time.Minute)
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || !claimed {
		t.Fatalf("at-interval rerun: claimed=%v err=%v", claimed, err)
	}
}

func TestRetentionRunStopsAtGlobalBatchBudget(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 3, 15, 30, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	insertRetentionEvents(t, pool, org, int(RetentionBatchSize*RetentionMaxBatches)+1, now.Add(-31*24*time.Hour))

	run, claimed, err := service.RunManual(ctx, org, actor, "batch-budget")
	if err != nil || !claimed {
		t.Fatalf("bounded run: claimed=%v err=%v", claimed, err)
	}
	wantDeleted := int64(RetentionBatchSize * RetentionMaxBatches)
	if run.Status != RetentionRunSucceeded || run.DeletedRows != wantDeleted || run.Batches != RetentionMaxBatches || !run.MorePending {
		t.Fatalf("run did not stop at the bounded budget: %+v", run)
	}
	assertEventCount(t, pool, org, 1)

	// more_pending bypasses the ordinary interval so the elected scheduler can
	// continue the backlog on its next bounded tick.
	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil || !containsUUID(due, org) {
		t.Fatalf("bounded backlog not immediately due: orgs=%v err=%v", due, err)
	}
}

func TestClaimedRunCancellationFinalizesDurableFailure(t *testing.T) {
	q, _, service, org, _ := retentionFixture(t)
	now := time.Date(2026, 9, 3, 16, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	raw, err := q.InsertScheduledAccessEventRetentionRun(context.Background(), sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
		CutoffAt: now.Add(-DefaultRetention), StartedAt: now,
		LeaseExpiresAt: pgtype.Timestamptz{Time: now.Add(RetentionRunLease), Valid: true},
	})
	if err != nil {
		t.Fatalf("claim fixture: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	finished, err := service.executeClaimedRun(canceled, raw)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("execution error = %v, want canceled", err)
	}
	if finished.Status != RetentionRunFailed || finished.ErrorCode == nil || *finished.ErrorCode != "context_canceled" || !finished.CompletedAt.Valid {
		t.Fatalf("failure was not durably finalized: %+v", finished)
	}
	stored, err := q.GetLatestAccessEventRetentionRun(context.Background(), org)
	if err != nil || stored.Status != RetentionRunFailed || stored.ErrorCode == nil || *stored.ErrorCode != "context_canceled" {
		t.Fatalf("stored failure = %+v, %v", stored, err)
	}
}

func TestRunFinalizationSurvivesRequesterMembershipRemoval(t *testing.T) {
	q, pool, service, org, actor := retentionFixture(t)
	now := time.Date(2026, 9, 3, 17, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	raw, err := q.InsertManualAccessEventRetentionRun(context.Background(), manualRunParams(
		org, actor, "membership-removal", defaultRetentionSettings(org), now,
	))
	if err != nil {
		t.Fatalf("manual claim fixture: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, org, actor); err != nil {
		t.Fatalf("remove requester membership: %v", err)
	}
	finished, err := service.executeClaimedRun(context.Background(), raw)
	if err != nil || finished.Status != RetentionRunSucceeded {
		t.Fatalf("finalize after membership removal = %+v, %v", finished, err)
	}
}

func TestRetentionSchemaEnforcesBoundsActorsAndSingleRunner(t *testing.T) {
	q, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 3, 18, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	if _, err := pool.Exec(ctx, `INSERT INTO access_event_retention_settings
		(org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id)
		VALUES($1,0,60,1,$2)`, org, actor); err == nil {
		t.Fatal("database accepted retention_days below its hard minimum")
	}
	foreignActor := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,name) VALUES($1,$2,'Foreign Actor')`, foreignActor, fmt.Sprintf("%s@example.test", foreignActor)); err != nil {
		t.Fatalf("foreign user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_event_retention_settings
		(org_id,retention_days,cleanup_interval_minutes,revision,updated_by_user_id)
		VALUES($1,30,60,1,$2)`, org, foreignActor); err == nil {
		t.Fatal("database accepted an actor from outside the organization")
	}

	first, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
		CutoffAt: now.Add(-DefaultRetention), StartedAt: now,
		LeaseExpiresAt: pgTimestamp(now.Add(RetentionRunLease)),
	})
	if err != nil {
		t.Fatalf("first running row: %v", err)
	}
	if _, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
		CutoffAt: now.Add(-DefaultRetention), StartedAt: now,
		LeaseExpiresAt: pgTimestamp(now.Add(RetentionRunLease)),
	}); err == nil {
		t.Fatal("database admitted two running retention jobs for one organization")
	}
	finished, err := q.FinalizeAccessEventRetentionRunSuccess(ctx, sqlc.FinalizeAccessEventRetentionRunSuccessParams{
		CompletedAt: pgTimestamp(now), ID: first.ID, OrgID: org,
	})
	if err != nil || finished.Status != RetentionRunSucceeded {
		t.Fatalf("finish schema fixture: %+v, %v", finished, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_event_retention_runs
		(org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
		 retention_days,cleanup_interval_minutes,settings_revision,row_cap,batch_size,max_batches,
		 cutoff_at,started_at,lease_expires_at)
		VALUES($1,'manual','running','bad/key',$2,30,60,0,100000,1000,100,$3,$4,$5)`,
		org, actor, now.Add(-DefaultRetention), now, now.Add(RetentionRunLease)); err == nil {
		t.Fatal("database accepted a manual idempotency key outside the API pattern")
	}
}

func insertRetentionEvents(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, count int, createdAt time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO access_events(org_id,seq,occurred_at,decision,src_ip,dst_ip,protocol,created_at)
		SELECT $1,series,$2,'deny','10.0.0.1','10.0.0.2','tcp',$2
		FROM generate_series(1,$3::integer) AS series`, org, createdAt, count); err != nil {
		t.Fatalf("insert %d retention events: %v", count, err)
	}
}

func assertEventCount(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM access_events WHERE org_id=$1`, org).Scan(&got); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if got != want {
		t.Fatalf("event count = %d, want %d", got, want)
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
