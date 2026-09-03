// Package auditretention owns the explicit, per-organization exception to the
// audit log's otherwise append-only storage contract.
package auditretention

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
	MinRetentionDays          int32 = 1
	MaxRetentionDays          int32 = 3650
	MinCleanupIntervalMinutes int32 = 5
	MaxCleanupIntervalMinutes int32 = 1440

	DefaultCleanupIntervalMinutes  int32 = 60
	RetentionBatchSize             int32 = 1_000
	RetentionMaxBatches            int32 = 100
	RetentionScheduledHistoryLimit int32 = 1_000
	retentionHistoryDeleteBatch    int32 = 1_000

	RetentionTriggerScheduled = "scheduled"
	RetentionTriggerManual    = "manual"
	RetentionRunRunning       = "running"
	RetentionRunSucceeded     = "succeeded"
	RetentionRunFailed        = "failed"
)

const RetentionSchedulerPollInterval = time.Minute

var ErrRetentionRunOwnershipLost = errors.New("audit-log retention run ownership lost")

var retentionIdempotencyKeyRE = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

// Settings is the effective per-organization policy. A nil RetentionDays value
// means retain forever. Revision zero is the intentional missing-row default.
type Settings struct {
	OrgID                  uuid.UUID  `json:"org_id"`
	RetentionDays          *int32     `json:"retention_days"`
	CleanupIntervalMinutes int32      `json:"cleanup_interval_minutes"`
	Revision               int64      `json:"revision"`
	UpdatedByUserID        *uuid.UUID `json:"updated_by_user_id,omitempty"`
	UpdatedAt              *time.Time `json:"updated_at,omitempty"`
}

type SettingsInput struct {
	RetentionDays          *int32 `json:"retention_days"`
	CleanupIntervalMinutes int32  `json:"cleanup_interval_minutes"`
	ExpectedRevision       int64  `json:"expected_revision"`
}

type Run struct {
	ID                     uuid.UUID  `json:"id"`
	OrgID                  uuid.UUID  `json:"org_id"`
	TriggerKind            string     `json:"trigger_kind"`
	Status                 string     `json:"status"`
	ManualIdempotencyKey   *string    `json:"manual_idempotency_key,omitempty"`
	RequestedByUserID      *uuid.UUID `json:"requested_by_user_id,omitempty"`
	RetentionDays          int32      `json:"retention_days"`
	CleanupIntervalMinutes int32      `json:"cleanup_interval_minutes"`
	SettingsRevision       int64      `json:"settings_revision"`
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

type Overview struct {
	Settings  Settings   `json:"settings"`
	LastRun   *Run       `json:"last_run,omitempty"`
	NextRunAt *time.Time `json:"next_run_at,omitempty"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func defaultSettings(orgID uuid.UUID) Settings {
	return Settings{OrgID: orgID, CleanupIntervalMinutes: DefaultCleanupIntervalMinutes}
}

func cloneDays(days *int32) *int32 {
	if days == nil {
		return nil
	}
	out := *days
	return &out
}

func settingsFromRow(row sqlc.AuditLogRetentionSetting) Settings {
	actor, updated := row.UpdatedByUserID, row.UpdatedAt
	return Settings{
		OrgID: row.OrgID, RetentionDays: cloneDays(row.RetentionDays),
		CleanupIntervalMinutes: row.CleanupIntervalMinutes, Revision: row.Revision,
		UpdatedByUserID: &actor, UpdatedAt: &updated,
	}
}

func runFromRow(row sqlc.AuditLogRetentionRun) Run {
	out := Run{
		ID: row.ID, OrgID: row.OrgID, TriggerKind: row.TriggerKind, Status: row.Status,
		ManualIdempotencyKey: row.ManualIdempotencyKey,
		RetentionDays:        row.RetentionDays, CleanupIntervalMinutes: row.CleanupIntervalMinutes,
		SettingsRevision: row.SettingsRevision, BatchSize: row.BatchSize,
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

func (s *Service) GetSettings(ctx context.Context, orgID uuid.UUID) (Settings, error) {
	q := sqlc.New(s.pool)
	if _, err := q.GetOrganizationByID(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return Settings{}, err
	}
	return loadEffectiveSettings(ctx, q, orgID, false)
}

func (s *Service) GetOverview(ctx context.Context, orgID uuid.UUID) (Overview, error) {
	settings, err := s.GetSettings(ctx, orgID)
	if err != nil {
		return Overview{}, err
	}
	run, err := s.GetLatestRun(ctx, orgID)
	if err != nil {
		return Overview{}, err
	}
	out := Overview{Settings: settings, LastRun: run}
	if settings.RetentionDays != nil && run != nil && run.Status != RetentionRunRunning && run.CompletedAt != nil {
		next := run.CompletedAt.Add(time.Duration(settings.CleanupIntervalMinutes) * time.Minute)
		if run.Status == RetentionRunSucceeded && run.MorePending {
			next = *run.CompletedAt
		}
		out.NextRunAt = &next
	}
	return out, nil
}

func loadEffectiveSettings(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, forUpdate bool) (Settings, error) {
	var (
		row sqlc.AuditLogRetentionSetting
		err error
	)
	if forUpdate {
		row, err = q.GetAuditLogRetentionSettingsForUpdate(ctx, orgID)
	} else {
		row, err = q.GetAuditLogRetentionSettings(ctx, orgID)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return defaultSettings(orgID), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return settingsFromRow(row), nil
}

func validateSettings(in SettingsInput) error {
	switch {
	case in.RetentionDays != nil && (*in.RetentionDays < MinRetentionDays || *in.RetentionDays > MaxRetentionDays):
		return apierr.BadRequest("invalid_audit_log_retention_days", "retention_days must be null or between 1 and 3650")
	case in.CleanupIntervalMinutes < MinCleanupIntervalMinutes || in.CleanupIntervalMinutes > MaxCleanupIntervalMinutes:
		return apierr.BadRequest("invalid_audit_log_cleanup_interval", "cleanup_interval_minutes must be between 5 and 1440")
	case in.ExpectedRevision < 0:
		return apierr.BadRequest("invalid_expected_revision", "expected_revision cannot be negative")
	default:
		return nil
	}
}

func sameDays(a, b *int32) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// SetSettings applies a revision-CAS update. An exact retry or current-value
// no-op neither bumps the revision nor creates duplicate audit evidence.
func (s *Service) SetSettings(ctx context.Context, orgID, actorUserID uuid.UUID, in SettingsInput) (Settings, error) {
	if actorUserID == uuid.Nil {
		return Settings{}, apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if err := validateSettings(in); err != nil {
		return Settings{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Settings{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.LockLiveAuditLogRetentionOrganization(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return Settings{}, err
	}
	if _, err := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: actorUserID}); errors.Is(err, pgx.ErrNoRows) {
		return Settings{}, apierr.Forbidden("organization_membership_required", "the actor is not an active organization member")
	} else if err != nil {
		return Settings{}, err
	}

	current, err := loadEffectiveSettings(ctx, q, orgID, true)
	if err != nil {
		return Settings{}, err
	}
	old := current
	same := sameDays(current.RetentionDays, in.RetentionDays) && current.CleanupIntervalMinutes == in.CleanupIntervalMinutes
	changed := false
	switch {
	case current.Revision == 0:
		if in.ExpectedRevision != 0 {
			return Settings{}, revisionConflict()
		}
		if same {
			break
		}
		row, err := q.InsertAuditLogRetentionSettings(ctx, sqlc.InsertAuditLogRetentionSettingsParams{
			OrgID: orgID, RetentionDays: cloneDays(in.RetentionDays),
			CleanupIntervalMinutes: in.CleanupIntervalMinutes, UpdatedByUserID: actorUserID,
		})
		if err != nil {
			return Settings{}, err
		}
		current, changed = settingsFromRow(row), true
	case same && (in.ExpectedRevision == current.Revision || in.ExpectedRevision+1 == current.Revision):
		// Current-revision no-op or exact replay of the immediately committed CAS.
	default:
		if in.ExpectedRevision != current.Revision {
			return Settings{}, revisionConflict()
		}
		row, err := q.UpdateAuditLogRetentionSettings(ctx, sqlc.UpdateAuditLogRetentionSettingsParams{
			OrgID: orgID, RetentionDays: cloneDays(in.RetentionDays),
			CleanupIntervalMinutes: in.CleanupIntervalMinutes,
			Revision:               current.Revision + 1, UpdatedByUserID: actorUserID,
		})
		if err != nil {
			return Settings{}, err
		}
		current, changed = settingsFromRow(row), true
	}
	if changed {
		metadata, err := json.Marshal(map[string]any{
			"old_retention_days": old.RetentionDays, "new_retention_days": current.RetentionDays,
			"old_cleanup_interval_minutes": old.CleanupIntervalMinutes,
			"new_cleanup_interval_minutes": current.CleanupIntervalMinutes,
			"old_revision":                 old.Revision, "new_revision": current.Revision,
		})
		if err != nil {
			return Settings{}, err
		}
		targetType, targetID := "organization", orgID.String()
		if _, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
			OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
			ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: true},
			Action:      "audit_log_retention.settings_changed", TargetType: &targetType,
			TargetID: &targetID, Metadata: metadata,
		}); err != nil {
			return Settings{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Settings{}, err
	}
	return current, nil
}

func revisionConflict() error {
	return apierr.Conflict("audit_log_retention_revision_conflict", "the retention setting changed; reload and retry")
}

func (s *Service) GetLatestRun(ctx context.Context, orgID uuid.UUID) (*Run, error) {
	q := sqlc.New(s.pool)
	if _, err := q.GetOrganizationByID(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return nil, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return nil, err
	}
	row, err := q.GetLatestAuditLogRetentionRun(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := runFromRow(row)
	return &out, nil
}

func (s *Service) ListDueOrganizations(ctx context.Context, limit int32) ([]uuid.UUID, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	return sqlc.New(s.pool).ListDueAuditLogRetentionOrganizations(ctx, limit)
}

func validateManual(actor uuid.UUID, key string) error {
	if actor == uuid.Nil {
		return apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if len(key) < 1 || len(key) > 128 || !retentionIdempotencyKeyRE.MatchString(key) {
		return apierr.BadRequest("invalid_idempotency_key", "idempotency_key must contain 1 to 128 letters, digits, dots, underscores, colons, or hyphens")
	}
	return nil
}

// RunManual uses only the saved policy. A repeated organization-local key
// returns the original result without a second prune or audit mutation.
func (s *Service) RunManual(ctx context.Context, orgID, actorUserID uuid.UUID, idempotencyKey string) (Run, bool, error) {
	if err := validateManual(actorUserID, idempotencyKey); err != nil {
		return Run{}, false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Run{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.LockLiveAuditLogRetentionOrganization(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return Run{}, false, err
	}
	if _, err := q.GetMembership(ctx, sqlc.GetMembershipParams{OrgID: orgID, UserID: actorUserID}); errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, apierr.Forbidden("organization_membership_required", "the actor is not an active organization member")
	} else if err != nil {
		return Run{}, false, err
	}
	if err := expireRun(ctx, q, orgID); err != nil {
		return Run{}, false, err
	}
	prior, err := q.GetManualAuditLogRetentionRun(ctx, sqlc.GetManualAuditLogRetentionRunParams{
		OrgID: orgID, ManualIdempotencyKey: &idempotencyKey,
	})
	if err == nil {
		if err := tx.Commit(ctx); err != nil {
			return Run{}, false, err
		}
		return runFromRow(prior), false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, err
	}
	if err := pruneScheduledRunHistory(ctx, q, orgID); err != nil {
		return Run{}, false, err
	}
	if _, err := q.GetRunningAuditLogRetentionRun(ctx, orgID); err == nil {
		return Run{}, false, apierr.Conflict("audit_log_retention_run_in_progress", "an audit-log retention run is already in progress")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, err
	}
	settings, err := loadEffectiveSettings(ctx, q, orgID, false)
	if err != nil {
		return Run{}, false, err
	}
	if settings.RetentionDays == nil {
		return Run{}, false, apierr.Conflict("audit_log_retention_disabled", "audit logs are retained forever; choose a bounded retention window before pruning")
	}
	raw, err := q.InsertManualAuditLogRetentionRun(ctx, manualRunParams(orgID, actorUserID, idempotencyKey, settings))
	if err != nil {
		return Run{}, false, err
	}
	metadata, err := json.Marshal(map[string]any{
		"run_id": raw.ID, "settings_revision": settings.Revision,
		"retention_days":           *settings.RetentionDays,
		"cleanup_interval_minutes": settings.CleanupIntervalMinutes,
	})
	if err != nil {
		return Run{}, false, err
	}
	targetType, targetID := "audit_log_retention_run", raw.ID.String()
	if _, err := q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		OrgID:       pgtype.UUID{Bytes: orgID, Valid: true},
		ActorUserID: pgtype.UUID{Bytes: actorUserID, Valid: true},
		Action:      "audit_log_retention.prune_requested", TargetType: &targetType,
		TargetID: &targetID, Metadata: metadata,
	}); err != nil {
		return Run{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Run{}, false, err
	}
	finished, runErr := s.executeClaimedRun(ctx, raw)
	return runFromRow(finished), true, runErr
}

func manualRunParams(orgID, actor uuid.UUID, key string, settings Settings) sqlc.InsertManualAuditLogRetentionRunParams {
	return sqlc.InsertManualAuditLogRetentionRunParams{
		OrgID: orgID, ManualIdempotencyKey: &key,
		RequestedByUserID: pgtype.UUID{Bytes: actor, Valid: true},
		RetentionDays:     *settings.RetentionDays, CleanupIntervalMinutes: settings.CleanupIntervalMinutes,
		SettingsRevision: settings.Revision, BatchSize: RetentionBatchSize,
		MaxBatches: RetentionMaxBatches,
	}
}

func (s *Service) RunScheduled(ctx context.Context, orgID uuid.UUID) (Run, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Run{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	if _, err := q.LockAuditLogRetentionOrganization(ctx, orgID); errors.Is(err, pgx.ErrNoRows) {
		return Run{}, false, nil
	} else if err != nil {
		return Run{}, false, err
	}
	if err := expireRun(ctx, q, orgID); err != nil {
		return Run{}, false, err
	}
	if err := pruneScheduledRunHistory(ctx, q, orgID); err != nil {
		return Run{}, false, err
	}
	settings, err := loadEffectiveSettings(ctx, q, orgID, false)
	if err != nil {
		return Run{}, false, err
	}
	if settings.RetentionDays == nil {
		if err := tx.Commit(ctx); err != nil {
			return Run{}, false, err
		}
		return Run{}, false, nil
	}
	due, err := q.IsAuditLogRetentionDue(ctx, sqlc.IsAuditLogRetentionDueParams{
		OrgID: orgID, CleanupIntervalMinutes: settings.CleanupIntervalMinutes,
	})
	if err != nil {
		return Run{}, false, err
	}
	if due == nil || !*due {
		if err := tx.Commit(ctx); err != nil {
			return Run{}, false, err
		}
		return Run{}, false, nil
	}
	raw, err := q.InsertScheduledAuditLogRetentionRun(ctx, sqlc.InsertScheduledAuditLogRetentionRunParams{
		OrgID: orgID, RetentionDays: *settings.RetentionDays,
		CleanupIntervalMinutes: settings.CleanupIntervalMinutes,
		SettingsRevision:       settings.Revision, BatchSize: RetentionBatchSize,
		MaxBatches: RetentionMaxBatches,
	})
	if err != nil {
		return Run{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Run{}, false, err
	}
	finished, runErr := s.executeClaimedRun(ctx, raw)
	return runFromRow(finished), true, runErr
}

func expireRun(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) error {
	_, err := q.ExpireAuditLogRetentionRun(ctx, orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	return err
}

func pruneScheduledRunHistory(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID) error {
	_, err := q.PruneAuditLogRetentionRunHistory(ctx, sqlc.PruneAuditLogRetentionRunHistoryParams{
		OrgID: orgID, KeepTerminal: RetentionScheduledHistoryLimit - 1,
		DeleteLimit: retentionHistoryDeleteBatch,
	})
	return err
}

func (s *Service) executeClaimedRun(ctx context.Context, run sqlc.AuditLogRetentionRun) (sqlc.AuditLogRetentionRun, error) {
	q := sqlc.New(s.pool)
	batches := run.Batches
	for batches < run.MaxBatches {
		renewed, err := q.RenewAuditLogRetentionRunLease(ctx, sqlc.RenewAuditLogRetentionRunLeaseParams{
			ID: run.ID, OrgID: run.OrgID,
		})
		if err != nil {
			return s.failClaimedRun(ctx, run, err)
		}
		if renewed != 1 {
			return run, ErrRetentionRunOwnershipLost
		}
		n, err := q.PruneAuditLogsByAgeBatch(ctx, run.ID)
		if err != nil {
			return s.failClaimedRun(ctx, run, err)
		}
		if n == 0 {
			break
		}
		batches++
	}
	pending, err := q.AuditLogRetentionMorePending(ctx, sqlc.AuditLogRetentionMorePendingParams{
		OrgID: pgtype.UUID{Bytes: run.OrgID, Valid: true}, OlderThan: run.CutoffAt,
	})
	if err != nil {
		return s.failClaimedRun(ctx, run, err)
	}
	finished, err := q.FinalizeAuditLogRetentionRunSuccess(ctx, sqlc.FinalizeAuditLogRetentionRunSuccessParams{
		MorePending: pending, ID: run.ID, OrgID: run.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrRetentionRunOwnershipLost
	}
	return finished, err
}

func (s *Service) failClaimedRun(ctx context.Context, run sqlc.AuditLogRetentionRun, cause error) (sqlc.AuditLogRetentionRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	code := "prune_failed"
	if errors.Is(cause, context.Canceled) {
		code = "context_canceled"
	} else if errors.Is(cause, context.DeadlineExceeded) {
		code = "deadline_exceeded"
	}
	finished, finishErr := sqlc.New(s.pool).FinalizeAuditLogRetentionRunFailure(finishCtx, sqlc.FinalizeAuditLogRetentionRunFailureParams{
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
