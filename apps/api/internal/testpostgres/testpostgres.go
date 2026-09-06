// Package testpostgres provides disposable PostgreSQL fixtures for tests only.
// Production code must not use it: New creates and drops a database on the
// explicit TUNNEX_TEST_DATABASE_URL admin endpoint.
package testpostgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

const fixtureTimeout = 90 * time.Second
const cleanupTimeout = 30 * time.Second

var ownedNamePattern = regexp.MustCompile(`^tnx_test_[0-9a-f]{32}$`)

// New owns a fresh, fully migrated database and a real concurrent pool. It skips
// when no explicit test admin endpoint is configured. Cleanup closes the child
// pool before dropping only this fixture's database, then closes the admin pool;
// failures are reported to the test, never hidden by row deletion or audit bypass.
func New(t testing.TB) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable PostgreSQL integration tests")
	}
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse test PostgreSQL admin configuration")
	}
	name := "tnx_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	migrationURL, err := databaseURL(dsn, name)
	if err != nil {
		t.Fatalf("prepare disposable PostgreSQL configuration: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), fixtureTimeout)
	t.Cleanup(cancel)
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal("create test PostgreSQL admin pool")
	}
	var pool *pgxpool.Pool
	created := false
	// Register before CREATE, migration, or child setup can fail. Only successful
	// CREATE grants cleanup ownership; an existing/colliding database is untouched.
	t.Cleanup(func() {
		cancel()
		err := cleanupDatabase(
			func(ctx context.Context) error { return closePool(ctx, pool) },
			func(ctx context.Context) error {
				if !created {
					return nil
				}
				_, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
				return err
			},
			func(ctx context.Context) error { return closePool(ctx, admin) },
		)
		if err != nil {
			t.Errorf("cleanup disposable PostgreSQL database %s: %v", name, err)
		}
	})
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create disposable PostgreSQL database %s: %v", name, err)
	}
	created = true
	if err := db.Up(migrationURL); err != nil {
		t.Fatalf("migrate disposable PostgreSQL database %s: %v", name, err)
	}
	childConfig := adminConfig.Copy()
	childConfig.ConnConfig.Database = name
	pool, err = pgxpool.NewWithConfig(ctx, childConfig)
	if err != nil {
		t.Fatal("create disposable PostgreSQL child pool")
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("connect disposable PostgreSQL database %s: %v", name, err)
	}
	return ctx, pool
}

// databaseURL preserves explicit connection settings in either URL or libpq
// keyword form. A copied pgx config's ConnString still names the original DB,
// and db.Up requires a URL, so neither string may be reused for migrations.
func databaseURL(dsn, name string) (string, error) {
	if !ownedNamePattern.MatchString(name) {
		return "", errors.New("refuse non-fixture database name")
	}
	var u *url.URL
	var err error
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err = url.Parse(dsn)
		if err != nil {
			return "", errors.New("invalid PostgreSQL URL")
		}
	} else {
		values, err := keywordSettings(dsn)
		if err != nil {
			return "", err
		}
		u = &url.URL{Scheme: "postgres", RawQuery: values.Encode()}
	}
	u.Path = "/" + name
	u.RawPath = ""
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("invalid PostgreSQL query parameters")
	}
	// Remove both aliases: a query-string DB can override the URL path.
	values.Del("dbname")
	values.Del("database")
	// These pgx-only client settings are not PostgreSQL connection parameters.
	for _, key := range []string{"pool_max_conns", "pool_min_conns", "pool_min_idle_conns", "pool_max_conn_lifetime", "pool_max_conn_lifetime_jitter", "pool_max_conn_idle_time", "pool_health_check_period", "statement_cache_capacity", "description_cache_capacity", "default_query_exec_mode"} {
		values.Del(key)
	}
	u.RawQuery = values.Encode()
	return u.String(), nil
}

var keywordPattern = regexp.MustCompile(`(?s)^[ \t\n\r\v\f]*([a-zA-Z_][a-zA-Z0-9_]*)[ \t\n\r\v\f]*=[ \t\n\r\v\f]*(?:'((?:[^'\\]|\\.)*)'|((?:[^'\\ \t\n\r\v\f]|\\.)*))`)

func keywordSettings(dsn string) (url.Values, error) {
	values := make(url.Values)
	for strings.TrimSpace(dsn) != "" {
		match := keywordPattern.FindStringSubmatch(dsn)
		if match == nil {
			return nil, errors.New("invalid PostgreSQL keyword connection string")
		}
		value := match[2] + match[3]
		// Match pgx's keyword decoding, including its preservation of escapes
		// other than backslash and quote, so migration uses the same credentials.
		value = strings.ReplaceAll(strings.ReplaceAll(value, `\\`, `\`), `\'`, `'`)
		values.Set(match[1], value)
		dsn = dsn[len(match[0]):]
	}
	return values, nil
}

func cleanupDatabase(closeChild, drop, closeAdmin func(context.Context) error) error {
	// Test/setup cancellation cannot prevent teardown from getting its own budget.
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	var errs []error
	if err := closeChild(ctx); err != nil {
		errs = append(errs, fmt.Errorf("close child pool (database retained): %w", err))
	} else if err := drop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("drop owned database: %w", err))
	}
	if err := closeAdmin(ctx); err != nil {
		errs = append(errs, fmt.Errorf("close admin pool: %w", err))
	}
	return errors.Join(errs...)
}

func closePool(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		pool.Close()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
