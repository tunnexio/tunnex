package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
	"io"
	"path/filepath"
)

func appRecovery(ctx context.Context, cfg config.Config, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("app-recovery", flag.ContinueOnError)
	path := flags.String("barrier", "", "absolute external restore marker path")
	id := flags.String("barrier-id", "", "fresh operator restore marker UUID")
	actor := flags.String("operator", "", "named restoring operator")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == "" || *actor == "" {
		return errors.New("usage: backupctl app-recovery --barrier PATH --barrier-id UUID --operator NAME")
	}
	expected, err := uuid.Parse(*id)
	if err != nil || expected == uuid.Nil {
		return errors.New("fresh restore marker UUID required")
	}
	if !filepath.IsAbs(*path) || cfg.AppAccessRestoreMarker == "" || filepath.Clean(*path) != filepath.Clean(cfg.AppAccessRestoreMarker) {
		return errors.New("recovery must use the configured external listener barrier")
	}
	var result appaccess.RecoveryResult
	err = backup.RecoverAppRestore(*path, expected, func() error {
		version, dirty, initialized, err := db.Version(cfg.DatabaseURL)
		if err != nil {
			return errors.New("restored schema inspection failed; keep listeners stopped and retain the marker")
		}
		if err := validateRecoverySchema(version, dirty, initialized, false); err != nil {
			return err
		}
		// Listeners remain externally fenced while an older restored dump
		// receives the current forward-only authority schema.
		if err := db.Up(cfg.DatabaseURL); err != nil {
			return errors.New("restored schema upgrade failed; keep listeners stopped and retain the marker")
		}
		version, dirty, initialized, err = db.Version(cfg.DatabaseURL)
		if err != nil {
			return errors.New("restored schema readback failed; keep listeners stopped and retain the marker")
		}
		if err := validateRecoverySchema(version, dirty, initialized, true); err != nil {
			return err
		}
		pool, err := dbconn.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			return errors.New("recovery database connection failed; keep listeners stopped and retain the marker")
		}
		defer pool.Close()
		result, err = appaccess.NewRecoveryService(pool).RecoverAuthority(ctx, *actor)
		if err != nil {
			return errors.New("recovery incomplete; keep every listener stopped and retain the marker")
		}
		current, err := sqlc.New(pool).GetAppAccessInstallationAuthority(ctx)
		if err != nil || !current.RecoveryCompletedAt.Valid || current.Generation != result.Generation || current.Version != result.Version {
			return errors.New("recovery readback unconfirmed; restore marker retained")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func appRestoreBegin(cfg config.Config, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("app-restore-begin", flag.ContinueOnError)
	path := flags.String("barrier", "", "configured external marker path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) || cfg.AppAccessRestoreMarker == "" || filepath.Clean(*path) != filepath.Clean(cfg.AppAccessRestoreMarker) {
		return errors.New("begin restore must use the configured external listener barrier")
	}
	m, err := backup.BeginAppRestore(*path)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(m)
}
