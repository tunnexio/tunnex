package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/appaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/backup"
	"github.com/tunnexio/tunnex/apps/api/internal/config"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
	"github.com/tunnexio/tunnex/packages/apptransport/restorebarrier"
)

func appProxyCredential(ctx context.Context, cfg config.Config, command string, args []string, out io.Writer) error {
	return backup.WithAppRestoreGuard(cfg.AppAccessRestoreMarker, func() error {
		return appProxyCredentialGuarded(ctx, cfg, command, args, out)
	})
}

func appProxyCredentialGuarded(ctx context.Context, cfg config.Config, command string, args []string, out io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	name := flags.String("name", "", "dedicated proxy name")
	path := flags.String("output", "", "exclusive private credential output file")
	id := flags.String("id", "", "dedicated proxy credential UUID")
	version := flags.Int64("expected-version", 0, "reviewed current credential version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected credential command arguments")
	}
	if err := restorebarrier.Check(cfg.AppAccessRestoreMarker); err != nil {
		return err
	}
	pool, err := dbconn.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return errors.New("dedicated proxy credential database connection failed")
	}
	defer pool.Close()
	svc := appaccess.NewService(pool, appaccess.Config{})
	if command == "app-proxy-revoke" {
		parsed, err := uuid.Parse(*id)
		if err != nil || parsed == uuid.Nil || *version < 1 {
			return errors.New("credential UUID and reviewed positive version required")
		}
		credential, err := svc.RevokeProxyCredential(ctx, parsed, *version)
		if err != nil {
			return errors.New("dedicated proxy credential revoke unconfirmed; inspect the reviewed credential before retrying")
		}
		return json.NewEncoder(out).Encode(struct {
			ID      uuid.UUID `json:"id"`
			Version int64     `json:"version"`
			Revoked bool      `json:"revoked"`
		}{credential.ID, credential.Version, credential.RevokedAt != nil})
	}
	if *name == "" || !filepath.IsAbs(*path) {
		return errors.New("proxy name and absolute exclusive output file required")
	}
	dir := filepath.Dir(*path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != filepath.Clean(dir) {
		return errors.New("credential output directory must exist without symlinks")
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("credential directory must be private")
	}
	f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("credential output exists or cannot be created; refusing overwrite")
	}
	defer f.Close()
	credential, secret, err := svc.IssueProxyCredential(ctx, *name)
	if err != nil {
		return errors.New("dedicated proxy credential issuance unconfirmed; inspect retained private output before retrying")
	}
	_, err = io.WriteString(f, secret+"\n")
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		directory, openErr := os.Open(dir)
		if openErr != nil {
			err = openErr
		} else {
			err = directory.Sync()
			_ = directory.Close()
		}
	}
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, revokeErr := svc.RevokeProxyCredential(cleanupCtx, credential.ID, credential.Version)
		if revokeErr != nil {
			return fmt.Errorf("credential file failed; revoke credential %s version %d before retrying", credential.ID, credential.Version)
		}
		return errors.New("credential file failed; issued credential revoked; inspect retained private output before retrying")
	}
	return json.NewEncoder(out).Encode(struct {
		ID      uuid.UUID `json:"id"`
		Version int64     `json:"version"`
		Name    string    `json:"name"`
	}{credential.ID, credential.Version, credential.Name})
}
