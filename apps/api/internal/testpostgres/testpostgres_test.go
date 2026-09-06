package testpostgres

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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
