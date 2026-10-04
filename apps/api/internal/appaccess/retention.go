package appaccess

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// Each tenant is normally eligible hourly. A full bounded run with remaining
// work resumes on the next leader tick. This is a fixed policy, not an API.
const GrantRetentionSchedulerPollInterval = time.Minute
const grantRetentionMaxBatches = 20

var ErrGrantRetentionOwnershipLost = errors.New("app-access retention run ownership lost")

func (s *Service) ListRetentionDueOrganizations(ctx context.Context, limit int32) ([]uuid.UUID, error) {
	if limit < 1 || limit > 100 {
		return nil, errors.New("invalid app-access retention tenant limit")
	}
	return sqlc.New(s.pool).ListDueAppAccessRetentionOrganizations(ctx, limit)
}

func (s *Service) RunRetentionScheduled(ctx context.Context, org uuid.UUID) (sqlc.AppAccessRetentionRun, bool, error) {
	var empty sqlc.AppAccessRetentionRun
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return empty, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	// Match both retention functions' lock order, including soft-deleted tenants.
	if _, err = q.LockAuditLogRetentionOrganization(ctx, org); errors.Is(err, pgx.ErrNoRows) {
		return empty, false, nil
	} else if err != nil {
		return empty, false, err
	}
	if _, err = q.ExpireAppAccessRetentionRun(ctx, org); err != nil {
		return empty, false, err
	}
	due, err := q.IsAppAccessRetentionDue(ctx, org)
	if err != nil {
		return empty, false, err
	}
	if !due {
		return empty, false, tx.Commit(ctx)
	}
	run, err := q.CreateAppAccessRetentionRun(ctx, org)
	if err != nil {
		return empty, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return empty, false, err
	}
	finished, err := s.executeRetentionRun(ctx, run)
	return finished, true, err
}

func (s *Service) executeRetentionRun(ctx context.Context, run sqlc.AppAccessRetentionRun) (sqlc.AppAccessRetentionRun, error) {
	q := sqlc.New(s.pool)
	for batches := run.Batches; batches < grantRetentionMaxBatches; batches++ {
		renewed, err := q.RenewAppAccessRetentionRun(ctx, sqlc.RenewAppAccessRetentionRunParams{OrgID: run.OrgID, ID: run.ID})
		if err != nil {
			return s.failRetentionRun(ctx, run, err)
		}
		if renewed != 1 {
			return run, ErrGrantRetentionOwnershipLost
		}
		deleted, err := q.PruneAppAccessRetentionBatch(ctx, run.ID)
		if err != nil {
			return s.failRetentionRun(ctx, run, err)
		}
		if deleted == 0 {
			break
		}
	}
	pending, err := q.AppAccessRetentionMorePending(ctx, sqlc.AppAccessRetentionMorePendingParams{OrgID: run.OrgID, GrantCutoff: run.GrantCutoffAt, AuditCutoff: run.AuditCutoffAt})
	if err != nil {
		return s.failRetentionRun(ctx, run, err)
	}
	finished, err := q.FinalizeAppAccessRetentionSuccess(ctx, sqlc.FinalizeAppAccessRetentionSuccessParams{OrgID: run.OrgID, ID: run.ID, MorePending: pending})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrGrantRetentionOwnershipLost
	}
	return finished, err
}

func (s *Service) failRetentionRun(ctx context.Context, run sqlc.AppAccessRetentionRun, cause error) (sqlc.AppAccessRetentionRun, error) {
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	code := "prune_failed"
	if errors.Is(cause, context.Canceled) {
		code = "context_canceled"
	} else if errors.Is(cause, context.DeadlineExceeded) {
		code = "deadline_exceeded"
	}
	finished, err := sqlc.New(s.pool).FinalizeAppAccessRetentionFailure(finishCtx, sqlc.FinalizeAppAccessRetentionFailureParams{OrgID: run.OrgID, ID: run.ID, ErrorCode: code})
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrGrantRetentionOwnershipLost
	}
	if err != nil {
		return run, errors.Join(cause, err)
	}
	return finished, cause
}
