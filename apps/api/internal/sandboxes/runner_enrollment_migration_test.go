package sandboxes

import (
	"net/url"
	"os"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestRunnerEnrollmentMigrationPreservesPublishedAuthority(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 195)
	var before string
	if err := pool.QueryRow(ctx, `SELECT row_to_json(a)::text FROM app_access_installation_authority a WHERE singleton`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("fixture endpoint")
	}
	u.Path = "/" + pool.Config().ConnConfig.Database
	if err = db.Up(u.String()); err != nil {
		t.Fatal(err)
	}
	var present bool
	if err = pool.QueryRow(ctx, `SELECT to_regclass('public.sandbox_runner_enrollments') IS NOT NULL AND to_regclass('public.sandbox_runner_workloads') IS NOT NULL AND to_regclass('public.sandbox_runner_qualification_reports') IS NOT NULL`).Scan(&present); err != nil || !present {
		t.Fatal("enrollment schema absent", err)
	}
	down, err := db.MigrationsFS.ReadFile("migrations/0196_sandbox_runner_enrollments.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	var after string
	if err = pool.QueryRow(ctx, `SELECT row_to_json(a)::text FROM app_access_installation_authority a WHERE singleton`).Scan(&after); err != nil || before != after {
		t.Fatal("published authority changed", err)
	}
	if err = pool.QueryRow(ctx, `SELECT to_regclass('public.sandboxes') IS NOT NULL AND to_regclass('public.sandbox_runner_enrollments') IS NULL`).Scan(&present); err != nil || !present {
		t.Fatal("downgrade crossed enrollment-owned schema", err)
	}
}
