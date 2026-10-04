package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

type appPreflightResult struct {
	SchemaVersion          uint      `json:"schema_version"`
	SupportedSchemaVersion uint      `json:"supported_schema_version"`
	Generation             uuid.UUID `json:"generation"`
	AuthorityVersion       int64     `json:"authority_version"`
	RecoveryCompleted      bool      `json:"recovery_completed"`
}

// This is an offline read-only admission, not a migration or authority recovery.
// The shared external guard serializes its DB snapshot with supported restore.
func appPreflight(ctx context.Context, cfg config.Config, args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: backupctl app-preflight")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var result appPreflightResult
	err := backup.WithAppRestoreGuard(cfg.AppAccessRestoreMarker, func() error {
		ceiling, err := supportedSchemaVersion()
		if err != nil {
			return err
		}
		pool, err := dbconn.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			return errors.New("app preflight database unavailable")
		}
		defer pool.Close()
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			return errors.New("app preflight snapshot unavailable")
		}
		defer tx.Rollback(ctx)
		var version uint
		var dirty bool
		if err = tx.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty); err != nil || dirty || version != ceiling {
			return errors.New("app preflight requires clean schema equal to this binary ceiling")
		}
		authority, err := sqlc.New(tx).GetAppAccessInstallationAuthority(ctx)
		if err != nil || authority.Generation == uuid.Nil || authority.Version < 1 || !authority.RecoveryCompletedAt.Valid {
			return errors.New("app preflight requires current completed installation authority")
		}
		result = appPreflightResult{version, ceiling, authority.Generation, authority.Version, true}
		if err = tx.Commit(ctx); err != nil {
			return errors.New("app preflight snapshot incomplete")
		}
		return nil
	})
	if err != nil {
		return errors.New("app preflight refused; preserve listeners and inspect schema, authority and external barrier")
	}
	return json.NewEncoder(out).Encode(result)
}
