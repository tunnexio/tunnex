package appaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// RecoveryService is an offline operator seam. Callers must fence every API,
// private authority, proxy and readiness worker before replacing either store.
// PostgreSQL cannot detect restoration of its own older authority generation.
type RecoveryService struct{ pool *pgxpool.Pool }

type RecoveryResult struct {
	Generation        uuid.UUID `json:"generation"`
	Version           int64     `json:"version"`
	ProxyCredentials  int64     `json:"proxy_credentials_revoked"`
	PendingOperations int64     `json:"pending_operations_cancelled"`
	Publications      int64     `json:"publications_disabled"`
	Users             int64     `json:"user_epochs_advanced"`
	BeamShares        int64     `json:"beam_shares_revoked,omitempty"`
	Confirmed         bool      `json:"confirmed"`
}

func NewRecoveryService(pool *pgxpool.Pool) *RecoveryService { return &RecoveryService{pool: pool} }

// RecoverAuthority commits durable denial and its audit before waiting. Errors
// after commit deliberately leave recovery incomplete and listeners fenced.
func (s *RecoveryService) RecoverAuthority(ctx context.Context, actor string) (RecoveryResult, error) {
	var out RecoveryResult
	if actor == "" || len(actor) > 100 || strings.TrimSpace(actor) != actor || strings.ContainsAny(actor, "\r\n\t") {
		return out, errors.New("a bounded operator name is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(context.Background())
	q := sqlc.New(tx)
	current, err := q.LockAppAccessInstallationAuthority(ctx)
	if err != nil {
		return out, err
	}
	next, err := q.RotateAppAccessInstallationAuthority(ctx, current.Version)
	if err != nil {
		return out, err
	}
	out.Generation, out.Version = next.Generation, next.Version
	if out.ProxyCredentials, err = q.RevokeAllAppAccessProxyCredentials(ctx); err != nil {
		return out, err
	}
	if out.PendingOperations, err = q.CancelAllAppAccessPublicationOperations(ctx); err != nil {
		return out, err
	}
	if out.Publications, err = q.DisableAllAppAccessServingPublications(ctx); err != nil {
		return out, err
	}
	if out.Users, err = q.AdvanceAllUserAppAuthEpoch(ctx); err != nil {
		return out, err
	}
	// A restored human CLI credential must never resurrect a Beam share.
	// Historical fixture schemas predate Beam; only the current schema has it.
	var beamPresent bool
	if err = tx.QueryRow(ctx, `SELECT to_regclass('public.beam_shares') IS NOT NULL`).Scan(&beamPresent); err != nil {
		return out, err
	}
	if beamPresent {
		tag, e := tx.Exec(ctx, `UPDATE beam_shares SET state='revoked',certificate_serial=NULL,origin_ready=false,version=version+1,authority_version=authority_version+1,generation=uuid_generate_v7() WHERE state IN ('starting','active','paused')`)
		if e != nil {
			return out, e
		}
		out.BeamShares = tag.RowsAffected()
		if _, err = tx.Exec(ctx, `DELETE FROM beam_streams;DELETE FROM beam_browser_sessions;DELETE FROM beam_launch_codes;DELETE FROM beam_pending_launches`); err != nil {
			return out, err
		}
		var settingsPresent bool
		if err = tx.QueryRow(ctx, `SELECT to_regclass('public.beam_installation_settings') IS NOT NULL`).Scan(&settingsPresent); err != nil {
			return out, err
		}
		if settingsPresent {
			if _, err = tx.Exec(ctx, `UPDATE beam_installation_settings SET version=version+1,operator_enabled=false,readiness_passed=false,readiness_version='',readiness_checked_at=NULL,readiness_expires_at=NULL,readiness_checks='[]' WHERE singleton`); err != nil {
				return out, err
			}
		}
	}
	metadata, err := json.Marshal(struct {
		RecoveryResult
		Operator string `json:"operator"`
	}{out, actor})
	if err != nil {
		return out, err
	}
	system, kind, target := "app-access-recovery", "app_access_installation", out.Generation.String()
	_, err = q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{ActorSystem: &system, Action: "app_access.authority.recovered", TargetType: &kind, TargetID: &target, Metadata: metadata})
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, fmt.Errorf("recovery commit unconfirmed: %w", err)
	}
	err = s.ConfirmRecovery(ctx, out.Generation, out.Version)
	out.Confirmed = err == nil
	return out, err
}

// ConfirmRecovery always repeats a full monotonic withdrawal wait, including
// after a process restart. A persisted timestamp is never a substitute.
func (s *RecoveryService) ConfirmRecovery(ctx context.Context, generation uuid.UUID, version int64) error {
	if generation == uuid.Nil || version < 1 {
		return errors.New("invalid recovery tuple")
	}
	current, err := sqlc.New(s.pool).GetAppAccessInstallationAuthority(ctx)
	if err != nil {
		return err
	}
	if current.Generation != generation || current.Version != version {
		return errors.New("recovery generation changed")
	}
	if current.RecoveryCompletedAt.Valid {
		return errors.New("recovery is already completed; a restored completion cannot reopen a new restore barrier")
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	_, err = sqlc.New(s.pool).ConfirmAppAccessInstallationRecovery(ctx, sqlc.ConfirmAppAccessInstallationRecoveryParams{ExpectedGeneration: generation, ExpectedVersion: version})
	if err != nil {
		return fmt.Errorf("recovery confirmation refused: %w", err)
	}
	return nil
}
