package accesslog

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

const (
	RetentionTriggerScheduled = "scheduled"
	RetentionTriggerManual    = "manual"

	RetentionRunRunning   = "running"
	RetentionRunSucceeded = "succeeded"
	RetentionRunFailed    = "failed"
)

var ErrRetentionRunOwnershipLost = errors.New("access-event retention run ownership lost")

var retentionIdempotencyKeyRE = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// RetentionSettings is the effective per-organization policy. Revision zero is
// the intentional missing-row default; persisted settings always have a
// positive revision.
type RetentionSettings struct {
	OrgID                  uuid.UUID  `json:"org_id"`
	RetentionDays          int32      `json:"retention_days"`
	CleanupIntervalMinutes int32      `json:"cleanup_interval_minutes"`
	Revision               int64      `json:"revision"`
	UpdatedByUserID        *uuid.UUID `json:"updated_by_user_id,omitempty"`
	UpdatedAt              *time.Time `json:"updated_at,omitempty"`
}

type RetentionSettingsInput struct {
	RetentionDays          int32 `json:"retention_days"`
	CleanupIntervalMinutes int32 `json:"cleanup_interval_minutes"`
	ExpectedRevision       int64 `json:"expected_revision"`
}

// RetentionRun is the durable status and immutable configuration snapshot for
// one bounded prune operation.
type RetentionRun struct {
	ID                     uuid.UUID  `json:"id"`
	OrgID                  uuid.UUID  `json:"org_id"`
	TriggerKind            string     `json:"trigger_kind"`
	Status                 string     `json:"status"`
	ManualIdempotencyKey   *string    `json:"manual_idempotency_key,omitempty"`
	RequestedByUserID      *uuid.UUID `json:"requested_by_user_id,omitempty"`
	RetentionDays          int32      `json:"retention_days"`
	CleanupIntervalMinutes int32      `json:"cleanup_interval_minutes"`
	SettingsRevision       int64      `json:"settings_revision"`
	RowCap                 int32      `json:"row_cap"`
	BatchSize              int32      `json:"batch_size"`
	MaxBatches             int32      `json:"max_batches"`
	CutoffAt               time.Time  `json:"cutoff_at"`
	StartedAt              time.Time  `json:"started_at"`
	LeaseExpiresAt         *time.Time `json:"lease_expires_at,omitempty"`
	CompletedAt            *time.Time `json:"completed_at,omitempty"`
	DeletedRows            int64      `json:"deleted_rows"`
	Batches                int32      `json:"batches"`
	MorePending            bool       `json:"more_pending"`
	ErrorCode              *string    `json:"error_code,omitempty"`
}

type RetentionOverview struct {
	Settings  RetentionSettings `json:"settings"`
	LastRun   *RetentionRun     `json:"last_run,omitempty"`
	NextRunAt *time.Time        `json:"next_run_at,omitempty"`
}

// RetentionService owns effective settings, durable claims and bounded pruning.
// now is injectable so cutoff, due and idempotency tests never race wall time.
type RetentionService struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func NewRetentionService(pool *pgxpool.Pool, now func() time.Time) *RetentionService {
	if now == nil {
		now = time.Now
	}
	return &RetentionService{pool: pool, now: now}
}

func defaultRetentionSettings(orgID uuid.UUID) RetentionSettings {
	return RetentionSettings{
		OrgID:                  orgID,
		RetentionDays:          DefaultRetentionDays,
		CleanupIntervalMinutes: DefaultCleanupIntervalMinutes,
	}
}

func retentionSettingsFromRow(row sqlc.AccessEventRetentionSetting) RetentionSettings {
	actor, updated := row.UpdatedByUserID, row.UpdatedAt
	return RetentionSettings{
		OrgID: row.OrgID, RetentionDays: row.RetentionDays,
		CleanupIntervalMinutes: row.CleanupIntervalMinutes,
		Revision:               row.Revision, UpdatedByUserID: &actor, UpdatedAt: &updated,
	}
}

func retentionRunFromRow(row sqlc.AccessEventRetentionRun) RetentionRun {
	out := RetentionRun{
		ID: row.ID, OrgID: row.OrgID, TriggerKind: row.TriggerKind, Status: row.Status,
		ManualIdempotencyKey: row.ManualIdempotencyKey,
		RetentionDays:        row.RetentionDays, CleanupIntervalMinutes: row.CleanupIntervalMinutes,
		SettingsRevision: row.SettingsRevision, RowCap: row.RowCap, BatchSize: row.BatchSize,
		MaxBatches: row.MaxBatches, CutoffAt: row.CutoffAt, StartedAt: row.StartedAt,
		DeletedRows: row.DeletedRows, Batches: row.Batches, MorePending: row.MorePending,
		ErrorCode: row.ErrorCode,
	}
	if row.RequestedByUserID.Valid {
		actor := uuid.UUID(row.RequestedByUserID.Bytes)
		out.RequestedByUserID = &actor
	}
	if row.LeaseExpiresAt.Valid {
		lease := row.LeaseExpiresAt.Time
		out.LeaseExpiresAt = &lease
	}
	if row.CompletedAt.Valid {
		completed := row.CompletedAt.Time
		out.CompletedAt = &completed
	}
	return out
}

func (s *RetentionService) GetSettings(ctx context.Context, orgID uuid.UUID) (RetentionSettings, error) {
	q := sqlc.New(s.pool)
	if _, err := q.GetOrganizationByID(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return RetentionSettings{}, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return RetentionSettings{}, err
	}
	return loadEffectiveRetentionSettings(ctx, q, orgID, false)
}

// GetOverview returns the effective policy and durable last-run status. A
// missing run has no next_run_at because no cleanup clock has started yet.
func (s *RetentionService) GetOverview(ctx context.Context, orgID uuid.UUID) (RetentionOverview, error) {
	settings, err := s.GetSettings(ctx, orgID)
	if err != nil {
		return RetentionOverview{}, err
	}
	run, err := s.GetLatestRun(ctx, orgID)
	if err != nil {
		return RetentionOverview{}, err
	}
	out := RetentionOverview{Settings: settings, LastRun: run}
	if run != nil && run.Status != RetentionRunRunning && run.CompletedAt != nil {
		next := run.CompletedAt.Add(time.Duration(settings.CleanupIntervalMinutes) * time.Minute)
		if run.Status == RetentionRunSucceeded && run.MorePending {
			next = *run.CompletedAt
		}
		out.NextRunAt = &next
	}
	return out, nil
}

func loadEffectiveRetentionSettings(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, forUpdate bool) (RetentionSettings, error) {
	var (
		row sqlc.AccessEventRetentionSetting
		err error
	)
	if forUpdate {
		row, err = q.GetAccessEventRetentionSettingsForUpdate(ctx, orgID)
	} else {
		row, err = q.GetAccessEventRetentionSettings(ctx, orgID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultRetentionSettings(orgID), nil
	}
	if err != nil {
		return RetentionSettings{}, err
	}
	return retentionSettingsFromRow(row), nil
}

func validateRetentionSettings(in RetentionSettingsInput) error {
	switch {
	case in.RetentionDays < MinRetentionDays || in.RetentionDays > MaxRetentionDays:
		return apierr.BadRequest("invalid_access_event_retention_days", "retention_days must be between 1 and 3650")
	case in.CleanupIntervalMinutes < MinCleanupIntervalMinutes || in.CleanupIntervalMinutes > MaxCleanupIntervalMinutes:
		return apierr.BadRequest("invalid_access_event_cleanup_interval", "cleanup_interval_minutes must be between 5 and 1440")
	case in.ExpectedRevision < 0:
		return apierr.BadRequest("invalid_expected_revision", "expected_revision cannot be negative")
	default:
		return nil
	}
}

// SetSettings applies a revision-CAS update. A current-value no-op and the
// exact retry of a committed transition neither bump the revision nor emit a
// duplicate audit event.
func (s *RetentionService) SetSettings(ctx context.Context, orgID, actorUserID uuid.UUID, in RetentionSettingsInput) (RetentionSettings, error) {
	if actorUserID == uuid.Nil {
		return RetentionSettings{}, apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if err := validateRetentionSettings(in); err != nil {
		return RetentionSettings{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RetentionSettings{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.LockLiveAccessEventRetentionOrganization(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return RetentionSettings{}, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return RetentionSettings{}, err
	}
	if _, err := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: actorUserID}); errors.Is(err, pgx.ErrNoRows) {
		return RetentionSettings{}, apierr.Forbidden("organization_membership_required", "the actor is not an active organization member")
	} else if err != nil {
		return RetentionSettings{}, err
	}

	current, err := loadEffectiveRetentionSettings(ctx, q, orgID, true)
	if err != nil {
		return RetentionSettings{}, err
	}
	old := current
	same := current.RetentionDays == in.RetentionDays && current.CleanupIntervalMinutes == in.CleanupIntervalMinutes
	changed := false
	switch {
	case current.Revision == 0:
		if in.ExpectedRevision != 0 {
			return RetentionSettings{}, retentionRevisionConflict()
		}
		if same {
			break
		}
		row, err := q.InsertAccessEventRetentionSettings(ctx, sqlc.InsertAccessEventRetentionSettingsParams{
			OrgID: orgID, RetentionDays: in.RetentionDays,
			CleanupIntervalMinutes: in.CleanupIntervalMinutes, UpdatedByUserID: actorUserID,
		})
		if err != nil {
			return RetentionSettings{}, err
		}
		current, changed = retentionSettingsFromRow(row), true
	case same && (in.ExpectedRevision == current.Revision || in.ExpectedRevision+1 == current.Revision):
		// Current-revision no-op or exact replay of the immediately committed CAS.
	default:
		if in.ExpectedRevision != current.Revision {
			return RetentionSettings{}, retentionRevisionConflict()
		}
		row, err := q.UpdateAccessEventRetentionSettings(ctx, sqlc.UpdateAccessEventRetentionSettingsParams{
			OrgID: orgID, RetentionDays: in.RetentionDays,
			CleanupIntervalMinutes: in.CleanupIntervalMinutes,
			Revision:               current.Revision + 1, UpdatedByUserID: actorUserID,
		})
		if err != nil {
			return RetentionSettings{}, err
		}
		current, changed = retentionSettingsFromRow(row), true
	}
	if changed {
		metadata, err := json.Marshal(map[string]any{
			"old_retention_days": old.RetentionDays, "new_retention_days": current.RetentionDays,
			"old_cleanup_interval_minutes": old.CleanupIntervalMinutes,
			"new_cleanup_interval_minutes": current.CleanupIntervalMinutes,
			"old_revision":                 old.Revision, "new_revision": current.Revision,
		})
		if err != nil {
			return RetentionSettings{}, err
		}
		targetType, targetID := "organization", orgID.String()
		if _, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
			OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
			ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: true},
			Action:      "access_event_retention.settings_changed", TargetType: &targetType,
			TargetID: &targetID, Metadata: metadata,
		}); err != nil {
			return RetentionSettings{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return RetentionSettings{}, err
	}
	return current, nil
}

func retentionRevisionConflict() error {
	return apierr.Conflict("access_event_retention_revision_conflict", "the retention setting changed; reload and retry")
}

// GetLatestRun returns nil when the live organization has never been pruned.
func (s *RetentionService) GetLatestRun(ctx context.Context, orgID uuid.UUID) (*RetentionRun, error) {
	q := sqlc.New(s.pool)
	if _, err := q.GetOrganizationByID(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return nil, err
	}
	row, err := q.GetLatestAccessEventRetentionRun(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := retentionRunFromRow(row)
	return &out, nil
}

func (s *RetentionService) ListDueOrganizations(ctx context.Context, limit int32) ([]uuid.UUID, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return sqlc.New(s.pool).ListDueAccessEventRetentionOrganizations(ctx, sqlc.ListDueAccessEventRetentionOrganizationsParams{
		NowAt: pgTimestamp(s.now().UTC()), DefaultIntervalMinutes: DefaultCleanupIntervalMinutes,
		OrgLimit: limit,
	})
}

func validateManualRetention(actor uuid.UUID, key string) error {
	if actor == uuid.Nil {
		return apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if len(key) < 1 || len(key) > 128 || !retentionIdempotencyKeyRE.MatchString(key) {
		return apierr.BadRequest("invalid_idempotency_key", "idempotency_key must contain 1 to 128 letters, digits, dots, underscores, colons, or hyphens")
	}
	return nil
}

// RunManual uses only the persisted effective policy; callers cannot supply a
// cutoff, cap or batch size. A repeated tenant-local key returns the original
// durable result and never prunes or audits twice.
func (s *RetentionService) RunManual(ctx context.Context, orgID, actorUserID uuid.UUID, idempotencyKey string) (RetentionRun, bool, error) {
	if err := validateManualRetention(actorUserID, idempotencyKey); err != nil {
		return RetentionRun{}, false, err
	}
	now := s.now().UTC()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RetentionRun{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.LockLiveAccessEventRetentionOrganization(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return RetentionRun{}, false, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return RetentionRun{}, false, err
	}
	if _, err := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: actorUserID}); errors.Is(err, pgx.ErrNoRows) {
		return RetentionRun{}, false, apierr.Forbidden("organization_membership_required", "the actor is not an active organization member")
	} else if err != nil {
		return RetentionRun{}, false, err
	}
	if err := expireRetentionRun(ctx, q, orgID, now); err != nil {
		return RetentionRun{}, false, err
	}
	prior, err := q.GetManualAccessEventRetentionRun(ctx, sqlc.GetManualAccessEventRetentionRunParams{
		OrgID: orgID, ManualIdempotencyKey: &idempotencyKey,
	})
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return RetentionRun{}, false, err
		}
		return retentionRunFromRow(prior), false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return RetentionRun{}, false, err
	}
	if _, err := q.GetRunningAccessEventRetentionRun(ctx, orgID); err == nil {
		return RetentionRun{}, false, apierr.Conflict("access_event_retention_run_in_progress", "a retention run is already in progress")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return RetentionRun{}, false, err
	}
	settings, err := loadEffectiveRetentionSettings(ctx, q, orgID, false)
	if err != nil {
		return RetentionRun{}, false, err
	}
	raw, err := q.InsertManualAccessEventRetentionRun(ctx, manualRunParams(orgID, actorUserID, idempotencyKey, settings, now))
	if err != nil {
		return RetentionRun{}, false, err
	}
	metadata, err := json.Marshal(map[string]any{
		"run_id": raw.ID, "settings_revision": settings.Revision,
		"retention_days":           settings.RetentionDays,
		"cleanup_interval_minutes": settings.CleanupIntervalMinutes,
	})
	if err != nil {
		return RetentionRun{}, false, err
	}
	targetType, targetID := "access_event_retention_run", raw.ID.String()
	if _, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
		ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: true},
		Action:      "access_event_retention.prune_requested", TargetType: &targetType,
		TargetID: &targetID, Metadata: metadata,
	}); err != nil {
		return RetentionRun{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RetentionRun{}, false, err
	}
	finished, runErr := s.executeClaimedRun(ctx, raw)
	return retentionRunFromRow(finished), true, runErr
}

func manualRunParams(orgID, actor uuid.UUID, key string, settings RetentionSettings, now time.Time) sqlc.InsertManualAccessEventRetentionRunParams {
	lease := now.Add(RetentionRunLease)
	return sqlc.InsertManualAccessEventRetentionRunParams{
		OrgID: orgID, ManualIdempotencyKey: &key,
		RequestedByUserID: pgtype.UUID{Bytes: actor, Valid: true},
		RetentionDays:     settings.RetentionDays, CleanupIntervalMinutes: settings.CleanupIntervalMinutes,
		SettingsRevision: settings.Revision, RowCap: DefaultPGRowCap,
		BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
		CutoffAt:  now.Add(-time.Duration(settings.RetentionDays) * 24 * time.Hour),
		StartedAt: now, LeaseExpiresAt: pgTimestamp(lease),
	}
}

// RunScheduled atomically rechecks due state after taking the per-org row lock.
// The returned bool is false when another worker owns the org or its interval
// has not elapsed.
func (s *RetentionService) RunScheduled(ctx context.Context, orgID uuid.UUID) (RetentionRun, bool, error) {
	now := s.now().UTC()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RetentionRun{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.LockAccessEventRetentionOrganization(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return RetentionRun{}, false, nil
	} else if err != nil {
		return RetentionRun{}, false, err
	}
	if err := expireRetentionRun(ctx, q, orgID, now); err != nil {
		return RetentionRun{}, false, err
	}
	settings, err := loadEffectiveRetentionSettings(ctx, q, orgID, false)
	if err != nil {
		return RetentionRun{}, false, err
	}
	due, err := q.IsAccessEventRetentionDue(ctx, sqlc.IsAccessEventRetentionDueParams{
		OrgID: orgID, NowAt: pgTimestamp(now), CleanupIntervalMinutes: settings.CleanupIntervalMinutes,
	})
	if err != nil {
		return RetentionRun{}, false, err
	}
	if due == nil || !*due {
		if err := tx.Commit(ctx); err != nil {
			return RetentionRun{}, false, err
		}
		return RetentionRun{}, false, nil
	}
	lease := now.Add(RetentionRunLease)
	raw, err := q.InsertScheduledAccessEventRetentionRun(ctx, sqlc.InsertScheduledAccessEventRetentionRunParams{
		OrgID: orgID, RetentionDays: settings.RetentionDays,
		CleanupIntervalMinutes: settings.CleanupIntervalMinutes,
		SettingsRevision:       settings.Revision, RowCap: DefaultPGRowCap,
		BatchSize: RetentionBatchSize, MaxBatches: RetentionMaxBatches,
		CutoffAt:  now.Add(-time.Duration(settings.RetentionDays) * 24 * time.Hour),
		StartedAt: now, LeaseExpiresAt: pgTimestamp(lease),
	})
	if err != nil {
		return RetentionRun{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RetentionRun{}, false, err
	}
	finished, runErr := s.executeClaimedRun(ctx, raw)
	return retentionRunFromRow(finished), true, runErr
}

func expireRetentionRun(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, now time.Time) error {
	_, err := q.ExpireAccessEventRetentionRun(ctx, sqlc.ExpireAccessEventRetentionRunParams{
		CompletedAt: pgTimestamp(now), OrgID: orgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func (s *RetentionService) executeClaimedRun(ctx context.Context, run sqlc.AccessEventRetentionRun) (sqlc.AccessEventRetentionRun, error) {
	q := sqlc.New(s.pool)
	var deleted int64
	var batches int32
	for batches < run.MaxBatches {
		leaseAt := s.now().UTC().Add(RetentionRunLease)
		if !leaseAt.After(run.StartedAt) {
			leaseAt = run.StartedAt.Add(RetentionRunLease)
		}
		renewed, err := q.RenewAccessEventRetentionRunLease(ctx, sqlc.RenewAccessEventRetentionRunLeaseParams{
			LeaseExpiresAt: pgTimestamp(leaseAt), ID: run.ID, OrgID: run.OrgID,
		})
		if err != nil {
			return s.failClaimedRun(ctx, run, deleted, batches, err)
		}
		if renewed != 1 {
			return run, ErrRetentionRunOwnershipLost
		}

		n, err := q.PruneAccessEventsByAgeBatch(ctx, sqlc.PruneAccessEventsByAgeBatchParams{
			OrgID: run.OrgID, OlderThan: run.CutoffAt, BatchLimit: run.BatchSize,
		})
		if err != nil {
			return s.failClaimedRun(ctx, run, deleted, batches, err)
		}
		if n > 0 {
			deleted, batches = deleted+n, batches+1
			continue
		}
		n, err = q.PruneAccessEventsOverCapBatch(ctx, sqlc.PruneAccessEventsOverCapBatchParams{
			OrgID: run.OrgID, KeepNewest: run.RowCap, BatchLimit: run.BatchSize,
		})
		if err != nil {
			return s.failClaimedRun(ctx, run, deleted, batches, err)
		}
		if n == 0 {
			break
		}
		deleted, batches = deleted+n, batches+1
	}
	pending, err := q.AccessEventRetentionMorePending(ctx, sqlc.AccessEventRetentionMorePendingParams{
		OrgID: run.OrgID, OlderThan: run.CutoffAt, KeepNewest: run.RowCap,
	})
	if err != nil {
		return s.failClaimedRun(ctx, run, deleted, batches, err)
	}
	completed := s.now().UTC()
	if completed.Before(run.StartedAt) {
		completed = run.StartedAt
	}
	finished, err := q.FinalizeAccessEventRetentionRunSuccess(ctx, sqlc.FinalizeAccessEventRetentionRunSuccessParams{
		CompletedAt: pgTimestamp(completed), DeletedRows: deleted, Batches: batches,
		MorePending: pending != nil && *pending, ID: run.ID, OrgID: run.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrRetentionRunOwnershipLost
	}
	return finished, err
}

func (s *RetentionService) failClaimedRun(ctx context.Context, run sqlc.AccessEventRetentionRun, deleted int64, batches int32, cause error) (sqlc.AccessEventRetentionRun, error) {
	// A canceled request must not strand a durable running row until lease expiry.
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	completed := s.now().UTC()
	if completed.Before(run.StartedAt) {
		completed = run.StartedAt
	}
	code := "prune_failed"
	if errors.Is(cause, context.Canceled) {
		code = "context_canceled"
	} else if errors.Is(cause, context.DeadlineExceeded) {
		code = "deadline_exceeded"
	}
	finished, finishErr := sqlc.New(s.pool).FinalizeAccessEventRetentionRunFailure(finishCtx, sqlc.FinalizeAccessEventRetentionRunFailureParams{
		CompletedAt: pgTimestamp(completed), DeletedRows: deleted, Batches: batches,
		ErrorCode: &code, ID: run.ID, OrgID: run.OrgID,
	})
	if errors.Is(finishErr, pgx.ErrNoRows) {
		finishErr = ErrRetentionRunOwnershipLost
	}
	if finishErr != nil {
		return run, errors.Join(cause, finishErr)
	}
	return finished, cause
}

func pgTimestamp(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value, Valid: true}
}
