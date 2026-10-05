package sandboxes

import (
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"net/url"
	"os"
	"testing"
)

func TestSandboxMigrationsPreserveOccupiedDevPredecessor(t *testing.T) {
	// Published main already owns versions through 180, including irreversible
	// App Access authority. Start at that real predecessor; never downgrade a
	// fully migrated fixture through retained installation authority.
	ctx, pool := testpostgres.NewAtVersion(t, 180)
	endpoint, err := url.Parse(os.Getenv("TUNNEX_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal("invalid test endpoint")
	}
	endpoint.Path = "/" + pool.Config().ConnConfig.Database
	migrationURL := endpoint.String()
	var authorityBefore string
	if err := pool.QueryRow(ctx, `SELECT row_to_json(a)::text FROM app_access_installation_authority a WHERE singleton`).Scan(&authorityBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE existing_predecessor_marker(value text PRIMARY KEY); INSERT INTO existing_predecessor_marker VALUES('preserved')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Up(migrationURL); err != nil {
		t.Fatal(err)
	}
	var version int
	var dirty bool
	var marker string
	if err := pool.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatal(err)
	}
	if version != 195 || dirty {
		t.Fatal(fmt.Sprintf("unexpected version %d dirty=%v", version, dirty))
	}
	if err := pool.QueryRow(ctx, `SELECT value FROM existing_predecessor_marker`).Scan(&marker); err != nil || marker != "preserved" {
		t.Fatal("existing schema changed", err)
	}
	var authorityAfter string
	if err := pool.QueryRow(ctx, `SELECT row_to_json(a)::text FROM app_access_installation_authority a WHERE singleton`).Scan(&authorityAfter); err != nil || authorityAfter != authorityBefore {
		t.Fatal("published installation authority changed", err)
	}
	var present bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.sandboxes') IS NOT NULL AND to_regclass('public.sandbox_terminal_identities') IS NOT NULL AND to_regclass('public.sandbox_start_epochs') IS NOT NULL`).Scan(&present); err != nil || !present {
		t.Fatal("sandbox migrations skipped", err)
	}
}
