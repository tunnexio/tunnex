package testpostgres

import (
	"context"
	"errors"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestNewAtVersionPreservesParentSchema(t *testing.T) {
	ctx, parent := New(t)
	var parentName string
	var before int
	if err := parent.QueryRow(ctx, `SELECT current_database(), version FROM schema_migrations`).Scan(&parentName, &before); err != nil {
		t.Fatal(err)
	}
	if before <= 160 {
		t.Fatalf("parent fixture must be newer than historical schema: %d", before)
	}
	parentURL, err := databaseURL(os.Getenv("TUNNEX_TEST_DATABASE_URL"), parentName)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("historical child", func(t *testing.T) {
		t.Setenv("TUNNEX_TEST_DATABASE_URL", parentURL)
		childCtx, child := NewAtVersion(t, 160)
		var childName string
		var version int
		if err := child.QueryRow(childCtx, `SELECT current_database(), version FROM schema_migrations`).Scan(&childName, &version); err != nil {
			t.Fatal(err)
		}
		if childName == parentName || version != 160 {
			t.Fatalf("historical child has wrong database or schema: same database=%v, version=%d", childName == parentName, version)
		}
		for _, dsn := range []string{child.Config().ConnString(), child.Config().ConnConfig.ConnString()} {
			config, err := pgxpool.ParseConfig(dsn)
			if err != nil || config.ConnConfig.Database != childName {
				t.Fatal("returned fixture connection string does not target its owned child")
			}
		}
		// Callers such as the IPsec migration tests use the returned pool's DSN.
		// Exercise that exact path rather than reconstructing a safe URL here.
		if err := db.MigrateTo(child.Config().ConnString(), 162); err != nil {
			t.Fatal(err)
		}
		var dirty bool
		if err := child.QueryRow(childCtx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
			t.Fatal(err)
		}
		if version != 162 || dirty {
			t.Fatal("returned fixture connection string did not migrate its owned child")
		}
	})
	var after int
	if err := parent.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("child migration changed parent schema: before=%d after=%d", before, after)
	}
}

func TestNewRequiresExplicitEndpoint(t *testing.T) {
	t.Setenv("TUNNEX_TEST_DATABASE_URL", "")
	ran := false
	t.Run("unconfigured fixture", func(t *testing.T) {
		New(t)
		ran = true
	})
	if ran {
		t.Fatal("unconfigured fixture did not skip")
	}
}

func TestDatabaseURLTargetsOnlyOwnedName(t *testing.T) {
	const name = "tnx_test_0123456789abcdef0123456789abcdef"
	for _, dsn := range []string{
		"postgres://alice:secret@localhost:5432/shared?sslmode=disable",
		"postgresql://alice:secret@localhost:5432/shared?sslmode=disable&dbname=other&database=third",
		"host=localhost port=5432 user=alice password=secret dbname=shared sslmode=disable",
		"host = 'localhost' port=5432 user='alice' password='sec\\'ret\\\\value' dbname='shared' sslmode=disable application_name='fixture tests'",
		"host=localhost user=alice password=escaped\\ value dbname=shared sslmode=disable pool_max_conns=8",
	} {
		t.Run(dsn[:8], func(t *testing.T) {
			got, err := databaseURL(dsn, name)
			if err != nil {
				t.Fatal(err)
			}
			child, err := pgxpool.ParseConfig(got)
			if err != nil {
				t.Fatal(err)
			}
			if child.ConnConfig.Database != name {
				t.Fatalf("migration database=%q, want exact owned name", child.ConnConfig.Database)
			}
			admin, err := pgxpool.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			if child.ConnConfig.Host != admin.ConnConfig.Host || child.ConnConfig.Port != admin.ConnConfig.Port || child.ConnConfig.User != admin.ConnConfig.User || child.ConnConfig.Password != admin.ConnConfig.Password {
				t.Fatal("migration connection settings changed")
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatal(err)
			}
			if u.Query().Has("dbname") || u.Query().Has("database") || u.Query().Has("pool_max_conns") {
				t.Fatal("unsafe database override or pgx-only setting retained")
			}
		})
	}
	for _, name := range []string{"", "postgres", "tnx_test_", "tnx_test_0123456789abcdef0123456789abcdef;DROP DATABASE shared", "tnx_test_0123456789abcdef0123456789abcdeF", "tnx_test_0123456789abcdef0123456789abcdef\n"} {
		if _, err := databaseURL("postgres://localhost/shared", name); err == nil {
			t.Fatalf("accepted unsafe database name %q", name)
		}
	}
}

func TestKeywordSettingsPreserveEscapesAndRefuseMalformedInput(t *testing.T) {
	got, err := keywordSettings(`password='has\'quote\\slash' application_name=with\ space dbname=first dbname=last`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("password") != `has'quote\slash` || got.Get("application_name") != `with\ space` || got.Get("dbname") != "last" {
		t.Fatal("keyword settings or escaping changed")
	}
	for _, dsn := range []string{"not a connection string", "password='unterminated", "host=trailing\\", "=missing_key"} {
		if _, err := keywordSettings(dsn); err == nil {
			t.Fatalf("accepted malformed keyword string %q", dsn)
		}
	}
}

func TestDatabasePoolURLPreservesClientSettings(t *testing.T) {
	const name = "tnx_test_0123456789abcdef0123456789abcdef"
	for _, dsn := range []string{
		"postgres://alice:secret@localhost:5432/shared?sslmode=disable&connect_timeout=8&application_name=fixture&pool_max_conns=8&pool_min_conns=2&pool_min_idle_conns=1&pool_max_conn_lifetime=3m&pool_max_conn_lifetime_jitter=2s&pool_max_conn_idle_time=1m&pool_health_check_period=4s&statement_cache_capacity=12&description_cache_capacity=10&default_query_exec_mode=simple_protocol",
		"host=localhost port=5432 user=alice password=secret dbname=shared sslmode=disable connect_timeout=8 application_name=fixture pool_max_conns=8 pool_min_conns=2 pool_min_idle_conns=1 pool_max_conn_lifetime=3m pool_max_conn_lifetime_jitter=2s pool_max_conn_idle_time=1m pool_health_check_period=4s statement_cache_capacity=12 description_cache_capacity=10 default_query_exec_mode=simple_protocol",
	} {
		got, err := databasePoolURL(dsn, name)
		if err != nil {
			t.Fatal(err)
		}
		parent, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		child, err := pgxpool.ParseConfig(got)
		if err != nil {
			t.Fatal(err)
		}
		if child.ConnConfig.Database != name || child.MaxConns != parent.MaxConns || child.MinConns != parent.MinConns || child.MinIdleConns != parent.MinIdleConns || child.MaxConnLifetime != parent.MaxConnLifetime || child.MaxConnLifetimeJitter != parent.MaxConnLifetimeJitter || child.MaxConnIdleTime != parent.MaxConnIdleTime || child.HealthCheckPeriod != parent.HealthCheckPeriod {
			t.Fatal("owned pool URL changed database identity or pool settings")
		}
		a, b := parent.ConnConfig, child.ConnConfig
		if a.Host != b.Host || a.Port != b.Port || a.User != b.User || a.Password != b.Password || a.ConnectTimeout != b.ConnectTimeout || a.StatementCacheCapacity != b.StatementCacheCapacity || a.DescriptionCacheCapacity != b.DescriptionCacheCapacity || a.DefaultQueryExecMode != b.DefaultQueryExecMode || !reflect.DeepEqual(a.RuntimeParams, b.RuntimeParams) {
			t.Fatal("owned pool URL changed connection or pgx client settings")
		}
	}
}

func TestCleanupOrderAndObservableErrors(t *testing.T) {
	failure := errors.New("sentinel cleanup failure")
	for _, tc := range []struct {
		name     string
		failStep string
		want     []string
	}{
		{"success", "", []string{"child", "drop", "admin"}},
		{"child failure retains database", "child", []string{"child", "admin"}},
		{"drop failure closes admin", "drop", []string{"child", "drop", "admin"}},
		{"admin failure reported", "admin", []string{"child", "drop", "admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixtureCtx, cancel := context.WithCancel(context.Background())
			cancel()
			var cleanupCtx context.Context
			var calls []string
			step := func(name string) func(context.Context) error {
				return func(got context.Context) error {
					if cleanupCtx == nil {
						cleanupCtx = got
					}
					deadline, bounded := got.Deadline()
					if got == fixtureCtx || got != cleanupCtx || got.Err() != nil || !bounded || time.Until(deadline) > cleanupTimeout {
						t.Fatal("cleanup did not receive live bounded context")
					}
					calls = append(calls, name)
					if tc.failStep == name {
						return failure
					}
					return nil
				}
			}
			err := cleanupDatabase(step("child"), step("drop"), step("admin"))
			if !reflect.DeepEqual(calls, tc.want) {
				t.Fatalf("cleanup calls=%v, want %v", calls, tc.want)
			}
			if tc.failStep == "" && err != nil || tc.failStep != "" && !errors.Is(err, failure) {
				t.Fatalf("cleanup error=%v, failed step=%s", err, tc.failStep)
			}
			if tc.failStep == "child" && !strings.Contains(err.Error(), "database retained") {
				t.Fatal("child-close failure did not identify retained database")
			}
			if cleanupCtx.Err() != context.Canceled {
				t.Fatal("completed cleanup context was not canceled")
			}
		})
	}
}
