package dbcheck

import (
	"context"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
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
		{"postgres://u:p@db/cp?sslmode=verify-full&channel_binding=require", true, true},
		{"postgres://u:p@db/cp?sslmode=verify-full&channel_binding=prefer", true, true},
		{"postgres://u:p@db/cp?sslmode=verify-full&channel_binding=disable", true, true},
		{"postgres://u:p@db/cp?sslmode=verify-full&channel_binding=invalid", true, false},
		{"postgres://u:p@db/cp?sslmode=verify-full&channel_binding=", true, false},
	} {
		if got := ValidateURL(tc.url, tc.tls); (got == nil) != tc.ok {
			t.Errorf("valid=%v want %v", got == nil, tc.ok)
		}
	}
}

func TestBackupClientsMatchServerMajor(t *testing.T) {
	for _, version := range []int{160000, 160014, 170000, 170010, 180006} {
		for _, tool := range []string{"pg_dump", "pg_restore"} {
			path, err := NativeToolPath(version, tool)
			if err != nil || !strings.Contains(path, "/postgresql"+strconv.Itoa(version/10000)+"/"+tool) {
				t.Fatalf("version %d tool %s: %q %v", version, tool, path, err)
			}
		}
	}
	for _, version := range []int{-1, 0, 150099, 190000} {
		if _, err := NativeToolPath(version, "pg_dump"); err == nil {
			t.Fatalf("accepted unsupported version %d", version)
		}
	}
	if _, err := NativeToolPath(160000, "../../bin/sh"); err == nil {
		t.Fatal("accepted arbitrary tool")
	}
}

func TestBackupPreservesRequiredChannelBinding(t *testing.T) {
	env, err := DumpEnvironment("postgres://u:p@db/cp?sslmode=verify-full&channel_binding=require", []string{"PGCHANNELBINDING=disable"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "PGCHANNELBINDING=require") || strings.Contains(joined, "PGCHANNELBINDING=disable") {
		t.Fatal("backup dropped or downgraded channel binding")
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

func TestDumpEnvironmentPreservesEffectiveChannelBinding(t *testing.T) {
	t.Setenv("PGCHANNELBINDING", "require")
	for _, tc := range []struct{ query, want string }{
		{"", "require"}, {"&channel_binding=prefer", "prefer"}, {"&channel_binding=disable", "disable"},
	} {
		env, err := DumpEnvironment("postgres://fixture@localhost/fixture?sslmode=verify-full"+tc.query, []string{"PGCHANNELBINDING=disable"})
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, value := range env {
			if strings.HasPrefix(value, "PGCHANNELBINDING=") {
				count++
				if value != "PGCHANNELBINDING="+tc.want {
					t.Fatal("effective binding requirement changed")
				}
			}
		}
		if count != 1 {
			t.Fatal("missing or duplicate channel binding environment")
		}
	}
}

func TestDumpEnvironmentPreservesEffectiveTrust(t *testing.T) {
	t.Setenv("PGSSLROOTCERT", "")
	env, err := DumpEnvironment("postgres://fixture@localhost/fixture?sslmode=verify-full", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(env, "\n"), "PGSSLROOTCERT=system") {
		t.Fatal("system trust lost")
	}
	t.Setenv("PGSSLROOTCERT", "system")
	env, err = DumpEnvironment("postgres://fixture@localhost/fixture?sslmode=verify-full", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(env, "\n"), "PGSSLROOTCERT=system") {
		t.Fatal("environment trust lost")
	}
	t.Setenv("PGSSLROOTCERT", "/nonexistent/environment-root.crt")
	env, err = DumpEnvironment("postgres://fixture@localhost/fixture?sslmode=verify-full&sslrootcert=system", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(env, "\n"), "PGSSLROOTCERT=system") {
		t.Fatal("URL trust precedence lost")
	}
	env, err = DumpEnvironment("postgres://fixture@localhost/fixture?sslmode=verify-full&sslrootcert=", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(env, "\n"), "PGSSLROOTCERT=system") {
		t.Fatal("explicit empty URL must override ambient root")
	}
}
