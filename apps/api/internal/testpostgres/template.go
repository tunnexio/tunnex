package testpostgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
)

// Template is an opt-in, package-owned, pristine latest-schema fixture. Its zero
// value is ready for use. Each New clones it into an independently named database;
// no test can connect to or mutate the template. Historical migration tests must
// continue to use NewAtVersion, which always migrates a fresh database.
// A package using Template must call Run from TestMain to retire it after tests.
// As with ordinary fixtures, an external owner must clean up after process kills.
type Template struct {
	mu     sync.Mutex
	dsn    string
	name   string
	admin  *pgxpool.Pool
	closed bool
}

// Run executes a test package and reports template cleanup failures as a failing
// exit status, including when the tests themselves failed. Tests' own cleanup
// closes and drops every child before m.Run returns.
func (s *Template) Run(m *testing.M) (code int) {
	defer func() {
		if err := s.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup PostgreSQL fixture template: %v\n", err)
			code = 1
		}
	}()
	return m.Run()
}

func (s *Template) New(t testing.TB) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable PostgreSQL integration tests")
	}
	name, err := s.prepare(dsn)
	if err != nil {
		t.Fatalf("prepare disposable PostgreSQL template: %v", err)
	}
	return newDatabase(t, dsn, nil, name)
}

func (s *Template) prepare(dsn string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", errors.New("fixture template already closed")
	}
	if s.name != "" {
		if s.dsn != dsn {
			return "", errors.New("fixture template endpoint changed within test package")
		}
		return s.name, nil
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return "", errors.New("parse test PostgreSQL admin configuration")
	}
	name := "tnx_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	migrationURL, err := databaseURL(dsn, name)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout)
	defer cancel()
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return "", errors.New("create test PostgreSQL admin pool")
	}
	// Close owns only a successfully created, unique template. Register ownership
	// before migration so an error or panic never silently loses its cleanup.
	created := false
	ready := false
	defer func() {
		if ready {
			return
		}
		cleanupErr := cleanupDatabase(
			func(context.Context) error { return nil },
			func(ctx context.Context) error {
				if !created {
					return nil
				}
				_, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
				return err
			},
			func(ctx context.Context) error { return closePool(ctx, admin) },
		)
		if cleanupErr != nil {
			// Keep the owned name visible for external cleanup even if setup failed.
			fmt.Fprintf(os.Stderr, "cleanup failed PostgreSQL fixture template %s: %v\n", name, cleanupErr)
		}
	}()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		return "", fmt.Errorf("create fixture template %s: %w", name, err)
	}
	created = true
	if err := db.Up(migrationURL); err != nil {
		return "", fmt.Errorf("migrate fixture template %s: %w", name, err)
	}
	// db.Up closes its migration connection. Refuse all subsequent connections to
	// this pristine source; PostgreSQL can still copy it into independent children.
	if _, err := admin.Exec(ctx, "ALTER DATABASE "+pgx.Identifier{name}.Sanitize()+" ALLOW_CONNECTIONS false"); err != nil {
		return "", fmt.Errorf("seal fixture template %s: %w", name, err)
	}
	s.dsn, s.name, s.admin = dsn, name, admin
	ready = true
	return name, nil
}

// Close retires only this instance's owned template. It is safe to call repeatedly.
func (s *Template) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return cleanupDatabase(
		func(context.Context) error { return nil },
		func(ctx context.Context) error {
			if s.name == "" {
				return nil
			}
			_, err := s.admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{s.name}.Sanitize()+" WITH (FORCE)")
			return err
		},
		func(ctx context.Context) error { return closePool(ctx, s.admin) },
	)
}
