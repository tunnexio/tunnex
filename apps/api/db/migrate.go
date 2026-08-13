package db

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres" // registers "postgres://"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// newMigrator builds a migrate.Migrate over the embedded migrations and the
// given database URL (a standard postgres:// DSN).
func newMigrator(databaseURL string) (*migrate.Migrate, error) {
	src, err := iofs.New(MigrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("init migrator: %w", err)
	}
	return m, nil
}

// Up applies all pending migrations. ErrNoChange is treated as success.
func Up(databaseURL string) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// MigrateTo migrates up OR down to EXACTLY the given version. Migration tests use this so they target
// their OWN version (not "the latest") — otherwise adding a later migration silently changes what
// DownOne rolls back and breaks earlier migration tests.
func MigrateTo(databaseURL string, version uint) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Migrate(version); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate to %d: %w", version, err)
	}
	return nil
}

// DownOne rolls back a single migration.
func DownOne(databaseURL string) error {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate down: %w", err)
	}
	return nil
}

// Version reports the current schema version. ok is false before any migration.
func Version(databaseURL string) (version uint, dirty bool, ok bool, err error) {
	m, err := newMigrator(databaseURL)
	if err != nil {
		return 0, false, false, err
	}
	defer m.Close()
	v, d, verr := m.Version()
	if errors.Is(verr, migrate.ErrNilVersion) {
		return 0, false, false, nil
	}
	if verr != nil {
		return 0, false, false, fmt.Errorf("migrate version: %w", verr)
	}
	return v, d, true, nil
}
