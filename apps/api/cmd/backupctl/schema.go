package main

import (
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// Derive this binary's ceiling from its embedded migrations rather than a
// separately maintained version constant or the database being restored.
func supportedSchemaVersion() (uint, error) {
	files, err := fs.Glob(db.MigrationsFS, "migrations/*.up.sql")
	if err != nil {
		return 0, errors.New("embedded migration versions unavailable")
	}
	var latest uint64
	for _, file := range files {
		prefix, _, ok := strings.Cut(path.Base(file), "_")
		version, err := strconv.ParseUint(prefix, 10, 32)
		if !ok || err != nil || version == 0 {
			return 0, errors.New("invalid embedded migration version")
		}
		if version > latest {
			latest = version
		}
	}
	if latest == 0 {
		return 0, errors.New("embedded migration versions unavailable")
	}
	return uint(latest), nil
}

func validateBackupSchemaVersion(version int64) error {
	latest, err := supportedSchemaVersion()
	if err != nil {
		return err
	}
	if version <= 0 || uint64(version) > uint64(latest) {
		return errors.New("backup schema is unknown or newer than this binary; use a compatible binary and a verified schema manifest")
	}
	return nil
}

func validateRecoverySchema(version uint, dirty, initialized, upgraded bool) error {
	latest, err := supportedSchemaVersion()
	if err != nil {
		return err
	}
	if !initialized || dirty || version == 0 || version > latest || (upgraded && version != latest) {
		return errors.New("restored schema is unsupported or incomplete; keep listeners stopped and retain the marker")
	}
	return nil
}
