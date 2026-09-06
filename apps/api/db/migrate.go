package db

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/golang-migrate/migrate/v4"
	pgxmigrate "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/tunnexio/tunnex/apps/api/internal/dbconn"
)

// newMigrator builds a migrate.Migrate over the embedded migrations and the
// given database URL (a standard postgres:// DSN).
func newMigrator(databaseURL string) (*migrate.Migrate, error) {
	src, err := iofs.New(MigrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		_ = src.Close()
		return nil, errors.New("invalid migration connection configuration")
	}
	config, err := dbconn.ParseConfig(databaseURL)
	if err != nil {
		_ = src.Close()
		return nil, errors.New("invalid migration connection configuration")
	}
	instance := stdlib.OpenDB(*config)
	// The previous postgres adapter hashes url.Path (including its leading slash)
	// into its advisory-lock identity. CURRENT_DATABASE() would change that key
	// and allow old and new migrators to run concurrently during an upgrade.
	driver, err := pgxmigrate.WithInstance(instance, &pgxmigrate.Config{DatabaseName: parsed.Path})
	if err != nil {
		_ = instance.Close()
		_ = src.Close()
		return nil, fmt.Errorf("init migration connection: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", driver)
	if err != nil {
		_ = driver.Close()
		_ = src.Close()
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
