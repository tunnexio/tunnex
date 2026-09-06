package dbcheck

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidateURL(t *testing.T) {
	for _, tc := range []struct {
		url     string
		tls, ok bool
	}{
		{"postgres://u:p@db.internal/cp?sslmode=verify-full", true, true},
		{"postgresql://u:p@db.internal:5432/cp?sslmode=verify-full", true, true},
		{"postgres://u:p@db/cp?sslmode=disable", false, true},
		{"postgres://u:p@db/cp?sslmode=require", true, false},
		{"postgres://u:p@db/cp", true, false},
		{"postgres://u:p@db", false, false},
		{"mysql://u:p@db/cp", false, false},
		{"postgres://secret%ZZ@db/cp", false, false},
		{"postgres://u:p@db/cp?sslmode=verify-full&sslmode=disable", true, false},
		{"postgres://u:p@db/cp?sslmode=verify-full&sslrootcert=%ZZ", true, false},
		{"postgres://u:p@db/cp?sslmode=verify-full#fragment", true, false},
		{"postgres://u:p@db/cp?host=somewhere-else", false, false},
	} {
		if got := ValidateURL(tc.url, tc.tls); (got == nil) != tc.ok {
			t.Errorf("valid=%v want %v", got == nil, tc.ok)
		}
	}
}

func TestRunAgainstPostgreSQL(t *testing.T) {
	raw := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("requires isolated migrated PostgreSQL test database")
	}
	for _, migration := range []bool{false, true} {
		if err := Run(context.Background(), raw, false, migration); err != nil {
			t.Fatal(err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	u.User = url.UserPassword("byodb_nonexistent_fixture_role", "must-not-appear-in-errors")
	err = Run(context.Background(), u.String(), false, true)
	if err == nil || !strings.HasPrefix(err.Error(), "database_auth_failed:") {
		t.Fatalf("expected redacted auth refusal, got %v", err)
	}
	if strings.Contains(err.Error(), "must-not-appear") {
		t.Fatal("credential leaked")
	}
}

func TestErrorsAreRedacted(t *testing.T) {
	for _, err := range []error{errors.New("password=TOPSECRET"), &net.DNSError{Err: "TOPSECRET"}, &pgconn.PgError{Code: "28P01", Message: "TOPSECRET"}} {
		if strings.Contains(SafeError(err), "TOPSECRET") {
			t.Fatal("credential leaked")
		}
	}
}

func TestDumpEnvironmentUsesPlainDatabaseAndOverridesAmbientTarget(t *testing.T) {
	env, err := DumpEnvironment("postgres://alice:p%24word@db.internal:5433/controlplane?sslmode=verify-full", []string{"PGHOST=wrong-host", "PGSERVICE=wrong-service", "PATH=/bin"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PGHOST=db.internal", "PGPORT=5433", "PGDATABASE=controlplane", "PGUSER=alice", "PGPASSWORD=p$word", "PGSSLMODE=verify-full", "PATH=/bin"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s", strings.Split(want, "=")[0])
		}
	}
	if strings.Contains(joined, "wrong-") || strings.Contains(joined, "postgres://") {
		t.Fatal("wrong backup target or unexpanded URI")
	}
}
