package accesslog

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
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
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
	})
	return q, pool, NewRetentionService(pool), org, actor
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
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, 1005, now.Add(-31*24*time.Hour))
	insertRetentionEvents(t, pool, other, 3, now.Add(-31*24*time.Hour))
	assertRetainedRows(t, pool, org, 1005)
	assertRetainedRows(t, pool, other, 3)

	run, claimed, err := service.RunManual(ctx, org, actor, "manual-batched-1")
	if err != nil {
		t.Fatalf("manual run: %v", err)
	}
	if !claimed || run.Status != RetentionRunSucceeded || run.DeletedRows != 1005 || run.Batches != 2 || run.MorePending {
		t.Fatalf("unexpected completed run: claimed=%v run=%+v", claimed, run)
	}
	assertEventCount(t, pool, org, 0)
	assertEventCount(t, pool, other, 3)
	assertRetainedRows(t, pool, org, 0)
	assertRetainedRows(t, pool, other, 3)

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
	if err != nil || run.CompletedAt == nil || overview.LastRun == nil || overview.LastRun.ID != run.ID || overview.NextRunAt == nil || !overview.NextRunAt.Equal(run.CompletedAt.Add(time.Hour)) {
		t.Fatalf("durable overview = %+v, %v", overview, err)
	}
}

func TestManualRetentionReplayReturnsItsOriginalRunAfterANewerRun(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, 1, now.Add(-31*24*time.Hour))

	original, claimed, err := service.RunManual(ctx, org, actor, "manual-original")
	if err != nil || !claimed {
		t.Fatalf("original manual run: claimed=%v run=%+v err=%v", claimed, original, err)
	}
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
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, 1, now.Add(-31*24*time.Hour))

	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil || !containsUUID(due, org) {
		t.Fatalf("new event org not due: orgs=%v err=%v", due, err)
	}
	run, claimed, err := service.RunScheduled(ctx, org)
	if err != nil || !claimed || run.Status != RetentionRunSucceeded || run.DeletedRows != 1 {
		t.Fatalf("first scheduled run: claimed=%v run=%+v err=%v", claimed, run, err)
	}
	insertRetentionEvents(t, pool, org, 1, now.Add(-31*24*time.Hour))
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("same-clock rerun: claimed=%v err=%v", claimed, err)
	}
	if _, err := pool.Exec(ctx, `
		WITH db_clock AS (SELECT clock_timestamp() AS now_at)
		UPDATE access_event_retention_runs
		SET started_at=db_clock.now_at - interval '61 minutes',
		    cutoff_at=db_clock.now_at - interval '30 days 61 minutes',
		    completed_at=db_clock.now_at - interval '59 minutes'
		FROM db_clock
		WHERE id=$1`, run.ID); err != nil {
		t.Fatalf("set pre-interval completed run: %v", err)
	}
	if _, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("pre-interval rerun: claimed=%v err=%v", claimed, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE access_event_retention_runs
		SET completed_at=clock_timestamp() - interval '61 minutes'
		WHERE id=$1`, run.ID); err != nil {
		t.Fatalf("backdate completed run: %v", err)
	}
	second, claimed, err := service.RunScheduled(ctx, org)
	if err != nil || !claimed || second.DeletedRows != 1 {
		t.Fatalf("at-interval rerun: claimed=%v run=%+v err=%v", claimed, second, err)
	}
}

func TestScheduledRetentionSkipsFreshEvidence(t *testing.T) {
	_, pool, service, org, _ := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, 1, now)
	assertRetainedRows(t, pool, org, 1)

	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil {
		t.Fatalf("list due organizations: %v", err)
	}
	if containsUUID(due, org) {
		t.Fatalf("fresh-only organization was scheduled: %v", due)
	}
	if run, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("fresh-only scheduled run: claimed=%v run=%+v err=%v", claimed, run, err)
	}
	var runs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_event_retention_runs WHERE org_id=$1`, org).Scan(&runs); err != nil {
		t.Fatalf("count scheduled runs: %v", err)
	}
	if runs != 0 {
		t.Fatalf("fresh-only evidence created %d run rows, want 0", runs)
	}
}

func TestScheduledRetentionTreatsRowCapOverflowAsEligible(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, int(DefaultPGRowCap)+1, now)
	assertRetainedRows(t, pool, org, int64(DefaultPGRowCap)+1)

	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil || !containsUUID(due, org) {
		t.Fatalf("cap-only organization not due: orgs=%v err=%v", due, err)
	}
	run, claimed, err := service.RunManual(ctx, org, actor, "cap-only")
	if err != nil || !claimed {
		t.Fatalf("cap-only manual run: claimed=%v run=%+v err=%v", claimed, run, err)
	}
	if run.DeletedRows != 1 || run.Batches != 1 || run.MorePending {
		t.Fatalf("cap-only result = %+v, want one deleted row in one batch", run)
	}
	assertEventCount(t, pool, org, int(DefaultPGRowCap))
	assertRetainedRows(t, pool, org, int64(DefaultPGRowCap))
}

func TestExpiredRunIsRecoveredAfterItsFinalEventDisappears(t *testing.T) {
	q, pool, service, org, _ := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	started := now.Add(-time.Hour)
	runID := insertExpiredScheduledRetentionRunFixture(t, pool, org, started)
	raw, err := q.GetLatestAccessEventRetentionRun(ctx, org)
	if err != nil {
		t.Fatalf("load expired claim fixture: %v", err)
	}
	if raw.ID != runID {
		t.Fatalf("latest expired claim id = %s, want %s", raw.ID, runID)
	}

	due, err := service.ListDueOrganizations(ctx, 1000)
	if err != nil || !containsUUID(due, org) {
		t.Fatalf("expired empty claim not listed for recovery: orgs=%v err=%v", due, err)
	}
	if run, claimed, err := service.RunScheduled(ctx, org); err != nil || claimed {
		t.Fatalf("expired empty recovery created a successor: claimed=%v run=%+v err=%v", claimed, run, err)
	}
	stored, err := q.GetLatestAccessEventRetentionRun(ctx, org)
	if err != nil || stored.ID != raw.ID || stored.Status != RetentionRunFailed || stored.ErrorCode == nil || *stored.ErrorCode != "lease_expired" {
		t.Fatalf("expired claim recovery = %+v, %v", stored, err)
	}
	var runs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_event_retention_runs WHERE org_id=$1`, org).Scan(&runs); err != nil {
		t.Fatalf("count retention runs: %v", err)
	}
	if runs != 1 {
		t.Fatalf("expired empty recovery left %d runs, want only the failed original", runs)
	}
}

func TestRetentionRunStopsAtGlobalBatchBudget(t *testing.T) {
	_, pool, service, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
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
	raw, err := q.InsertScheduledAccessEventRetentionRun(context.Background(), sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
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

func TestExpiredLeaseCannotBeRenewedToResumeDeletion(t *testing.T) {
	q, pool, service, org, _ := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, 1, now.Add(-31*24*time.Hour))
	started := now.Add(-time.Hour)
	runID := insertExpiredScheduledRetentionRunFixture(t, pool, org, started)
	raw, err := q.GetLatestAccessEventRetentionRun(ctx, org)
	if err != nil {
		t.Fatalf("load expired claim fixture: %v", err)
	}
	if raw.ID != runID {
		t.Fatalf("latest expired claim id = %s, want %s", raw.ID, runID)
	}

	finished, err := service.executeClaimedRun(ctx, raw)
	if !errors.Is(err, ErrRetentionRunOwnershipLost) {
		t.Fatalf("expired claim execution = %+v, %v; want ownership lost", finished, err)
	}
	assertEventCount(t, pool, org, 1)
	stored, err := q.GetLatestAccessEventRetentionRun(ctx, org)
	if err != nil || stored.ID != raw.ID || stored.Status != RetentionRunRunning || stored.DeletedRows != 0 || stored.Batches != 0 {
		t.Fatalf("expired claim changed before scheduler recovery: %+v, %v", stored, err)
	}
}

func TestRunFinalizationSurvivesRequesterMembershipRemoval(t *testing.T) {
	q, pool, service, org, actor := retentionFixture(t)
	raw, err := q.InsertManualAccessEventRetentionRun(context.Background(), manualRunParams(
		org, actor, "membership-removal", defaultRetentionSettings(org),
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

func TestPruneBatchPersistsCountersBeforeFinalization(t *testing.T) {
	q, pool, _, org, _ := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	insertRetentionEvents(t, pool, org, 1, now.Add(-31*24*time.Hour))
	raw, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
	})
	if err != nil {
		t.Fatalf("claim fixture: %v", err)
	}
	deleted, err := q.PruneAccessEventRetentionBatch(ctx, raw.ID)
	if err != nil || deleted != 1 {
		t.Fatalf("prune batch deleted %d: %v", deleted, err)
	}
	stored, err := q.GetLatestAccessEventRetentionRun(ctx, org)
	if err != nil {
		t.Fatalf("load running claim: %v", err)
	}
	if stored.Status != RetentionRunRunning || stored.DeletedRows != 1 || stored.Batches != 1 {
		t.Fatalf("batch truth was not durable before finalization: %+v", stored)
	}
	assertEventCount(t, pool, org, 0)
}

func TestFailureFinalizationPreservesAtomicBatchCounters(t *testing.T) {
	q, pool, service, org, _ := retentionFixture(t)
	ctx := context.Background()
	insertRetentionEvents(t, pool, org, 1, time.Now().UTC().Add(-31*24*time.Hour))
	raw, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
	})
	if err != nil {
		t.Fatalf("claim fixture: %v", err)
	}
	if deleted, err := q.PruneAccessEventRetentionBatch(ctx, raw.ID); err != nil || deleted != 1 {
		t.Fatalf("atomic prune before failure deleted %d: %v", deleted, err)
	}

	cause := errors.New("forced failure after committed batch")
	finished, gotErr := service.failClaimedRun(ctx, raw, cause)
	if !errors.Is(gotErr, cause) {
		t.Fatalf("finalization error = %v, want original cause", gotErr)
	}
	if finished.Status != RetentionRunFailed || finished.DeletedRows != 1 || finished.Batches != 1 ||
		finished.ErrorCode == nil || *finished.ErrorCode != "prune_failed" {
		t.Fatalf("failure finalization overwrote atomic batch truth: %+v", finished)
	}
	stored, err := q.GetLatestAccessEventRetentionRun(ctx, org)
	if err != nil || stored.ID != raw.ID || stored.DeletedRows != 1 || stored.Batches != 1 {
		t.Fatalf("stored failure lost atomic counters: %+v, %v", stored, err)
	}
	assertEventCount(t, pool, org, 0)
	assertRetainedRows(t, pool, org, 0)
}

func TestRetentionClaimTimestampsComeFromOneDatabaseClock(t *testing.T) {
	q, pool, _, org, _ := retentionFixture(t)
	ctx := context.Background()
	var before, after time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatalf("read database clock before claim: %v", err)
	}
	run, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
	})
	if err != nil {
		t.Fatalf("database-clock claim: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&after); err != nil {
		t.Fatalf("read database clock after claim: %v", err)
	}
	if run.StartedAt.Before(before) || run.StartedAt.After(after) {
		t.Fatalf("started_at %s is outside database interval [%s,%s]", run.StartedAt, before, after)
	}
	if want := run.StartedAt.Add(-DefaultRetention); !run.CutoffAt.Equal(want) {
		t.Fatalf("cutoff_at=%s, want started_at-retention=%s", run.CutoffAt, want)
	}
	if !run.LeaseExpiresAt.Valid || !run.LeaseExpiresAt.Time.Equal(run.StartedAt.Add(RetentionRunLease)) {
		t.Fatalf("lease_expires_at=%v, want started_at+lease=%s", run.LeaseExpiresAt, run.StartedAt.Add(RetentionRunLease))
	}
}

func TestScheduledRunHistoryIsBoundedWithoutEvictingManualOrRunningRows(t *testing.T) {
	q, pool, _, org, actor := retentionFixture(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		WITH moments AS (
			SELECT statement_timestamp() - n * interval '1 second' AS at
			FROM generate_series(1,1001) AS n
		)
		INSERT INTO access_event_retention_runs (
			org_id,trigger_kind,status,retention_days,cleanup_interval_minutes,
			settings_revision,row_cap,batch_size,max_batches,cutoff_at,started_at,
			completed_at,deleted_rows,batches,more_pending
		)
		SELECT $1,'scheduled','succeeded',30,60,0,100000,1000,100,
			at - interval '30 days',at,at,0,0,false
		FROM moments`, org); err != nil {
		t.Fatalf("seed scheduled run history: %v", err)
	}
	manualKey := "manual-idempotency-survives-history-compaction"
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_event_retention_runs (
			org_id,trigger_kind,status,manual_idempotency_key,requested_by_user_id,
			retention_days,cleanup_interval_minutes,settings_revision,row_cap,
			batch_size,max_batches,cutoff_at,started_at,completed_at,
			deleted_rows,batches,more_pending
		) VALUES (
			$1,'manual','succeeded',$2,$3,30,60,0,100000,1000,100,
			statement_timestamp() - interval '31 days',
			statement_timestamp() - interval '1 day',
			statement_timestamp() - interval '1 day',0,0,false
		)`, org, manualKey, actor); err != nil {
		t.Fatalf("seed manual run history: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_event_retention_runs (
			org_id,trigger_kind,status,retention_days,cleanup_interval_minutes,
			settings_revision,row_cap,batch_size,max_batches,cutoff_at,started_at,
			lease_expires_at
		) VALUES (
			$1,'scheduled','running',30,60,0,100000,1000,100,
			statement_timestamp() - interval '30 days',statement_timestamp(),
			statement_timestamp() + interval '15 minutes'
		)`, org); err != nil {
		t.Fatalf("seed running claim: %v", err)
	}

	if err := pruneScheduledRetentionRunHistory(ctx, q, org); err != nil {
		t.Fatalf("compact scheduled history: %v", err)
	}
	var scheduledTerminal, running, manual int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE trigger_kind='scheduled' AND status <> 'running'),
		       count(*) FILTER (WHERE status='running'),
		       count(*) FILTER (WHERE trigger_kind='manual' AND manual_idempotency_key=$2)
		FROM access_event_retention_runs WHERE org_id=$1`, org, manualKey).Scan(&scheduledTerminal, &running, &manual); err != nil {
		t.Fatalf("count compacted history: %v", err)
	}
	if scheduledTerminal != int(RetentionScheduledHistoryLimit-1) || running != 1 || manual != 1 {
		t.Fatalf("retained scheduled/running/manual = %d/%d/%d, want %d/1/1",
			scheduledTerminal, running, manual, RetentionScheduledHistoryLimit-1)
	}
}

func TestRetentionSchemaEnforcesBoundsActorsAndSingleRunner(t *testing.T) {
	q, pool, _, org, actor := retentionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

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
	})
	if err != nil {
		t.Fatalf("first running row: %v", err)
	}
	if _, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: org, RetentionDays: DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes, SettingsRevision: 0,
		RowCap: DefaultPGRowCap, BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
	}); err == nil {
		t.Fatal("database admitted two running retention jobs for one organization")
	}
	finished, err := q.FinalizeAccessEventRetentionRunSuccess(ctx, sqlc.FinalizeAccessEventRetentionRunSuccessParams{
		ID: first.ID, OrgID: org,
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

func assertRetainedRows(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(context.Background(), `
		SELECT COALESCE((
			SELECT retained_rows FROM access_event_retention_state WHERE org_id=$1
		),0)`, org).Scan(&got); err != nil {
		t.Fatalf("read retained-row state: %v", err)
	}
	if got != want {
		t.Fatalf("retained-row state = %d, want %d", got, want)
	}
}

func insertExpiredScheduledRetentionRunFixture(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, started time.Time) uuid.UUID {
	t.Helper()
	runID := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO access_event_retention_runs (
			id,org_id,trigger_kind,status,retention_days,
			cleanup_interval_minutes,settings_revision,row_cap,batch_size,max_batches,
			cutoff_at,started_at,lease_expires_at
		) VALUES (
			$1,$2,'scheduled','running',30,60,0,100000,1000,100,
			$3::timestamptz - interval '30 days',$3::timestamptz,
			$3::timestamptz + interval '15 minutes'
		)`, runID, org, started); err != nil {
		t.Fatalf("insert expired retention lease fixture: %v", err)
	}
	return runID
}

func containsUUID(values []uuid.UUID, want uuid.UUID) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
