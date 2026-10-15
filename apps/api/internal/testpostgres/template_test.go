package testpostgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestTemplateAtVersionKeepsBaselineAndParentIndependent(t *testing.T) {
	ctx, parent := New(t)
	var parentVersion int
	var parentDirty bool
	if err := parent.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&parentVersion, &parentDirty); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TUNNEX_TEST_DATABASE_URL", parent.Config().ConnString())
	template := NewTemplateAtVersion(160)
	t.Cleanup(func() {
		if err := template.Close(); err != nil {
			t.Errorf("retire historical template: %v", err)
		}
	})
	// Race first preparation without t.Parallel: this test temporarily points the
	// fixture environment at its own parent, which parallel tests may not do.
	type prepared struct {
		name string
		err  error
	}
	ready := make(chan prepared, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			name, err := template.prepare(parent.Config().ConnString())
			ready <- prepared{name, err}
		}()
	}
	close(start)
	for range 2 {
		got := <-ready
		if got.err != nil || got.name != template.name {
			t.Fatal("concurrent preparation did not share one historical template")
		}
	}
	var names sync.Map
	t.Run("independent upgraded clones", func(t *testing.T) {
		for range 2 {
			t.Run("child", func(t *testing.T) {
				childCtx, child := template.New(t)
				var name string
				var version int
				var dirty bool
				if err := child.QueryRow(childCtx, `SELECT current_database(), version, dirty FROM schema_migrations`).Scan(&name, &version, &dirty); err != nil {
					t.Fatal(err)
				}
				if version != 160 || dirty {
					t.Fatal("historical clone did not start at its clean baseline")
				}
				if _, duplicate := names.LoadOrStore(name, true); duplicate {
					t.Fatal("concurrent fixtures shared a child database")
				}
				if err := db.MigrateTo(child.Config().ConnString(), 162); err != nil {
					t.Fatal(err)
				}
				if _, err := child.Exec(childCtx, `CREATE TABLE fixture_child_only(value text); INSERT INTO fixture_child_only VALUES ('private child')`); err != nil {
					t.Fatal(err)
				}
			})
		}
	})
	childCtx, child := template.New(t)
	var version int
	var dirty, allowsConnections bool
	var leakedTable *string
	if err := child.QueryRow(childCtx, `SELECT version, dirty, to_regclass('fixture_child_only')::text, (SELECT datallowconn FROM pg_database WHERE datname=$1) FROM schema_migrations`, template.name).Scan(&version, &dirty, &leakedTable, &allowsConnections); err != nil {
		t.Fatal(err)
	}
	if version != 160 || dirty || leakedTable != nil || allowsConnections {
		t.Fatal("child migration or data changed the sealed historical baseline")
	}
	if err := parent.QueryRow(ctx, `SELECT version, dirty, to_regclass('fixture_child_only')::text FROM schema_migrations`).Scan(&version, &dirty, &leakedTable); err != nil {
		t.Fatal(err)
	}
	if version != parentVersion || dirty != parentDirty || leakedTable != nil {
		t.Fatal("historical template or child migration changed parent schema or data")
	}
	names.Range(func(name, _ any) bool {
		var exists bool
		if err := parent.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("historical clone remained after child cleanup")
		}
		return true
	})
}

func TestTemplateClonesAreIndependentSealedAndRetired(t *testing.T) {
	var template Template
	t.Cleanup(func() {
		if err := template.Close(); err != nil {
			t.Errorf("retire template: %v", err)
		}
	})
	ctx, first := template.New(t)
	var firstName string
	var firstVersion int
	if err := first.QueryRow(ctx, `SELECT current_database(), version FROM schema_migrations`).Scan(&firstName, &firstVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Exec(ctx, `CREATE TABLE fixture_isolation(value text); INSERT INTO fixture_isolation VALUES ('first child only')`); err != nil {
		t.Fatal(err)
	}
	var secondName string
	t.Run("independent child", func(t *testing.T) {
		childCtx, second := template.New(t)
		var secondVersion int
		var isolation *string
		if err := second.QueryRow(childCtx, `SELECT current_database(), version, to_regclass('fixture_isolation')::text FROM schema_migrations`).Scan(&secondName, &secondVersion, &isolation); err != nil {
			t.Fatal(err)
		}
		if firstName == secondName || secondName == template.name || firstName == template.name || firstVersion != secondVersion || isolation != nil {
			t.Fatal("template or test child state leaked between fixtures")
		}
	})
	var childExists, allowsConnections bool
	if err := first.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1), (SELECT datallowconn FROM pg_database WHERE datname=$2)`, secondName, template.name).Scan(&childExists, &allowsConnections); err != nil {
		t.Fatal(err)
	}
	if childExists || allowsConnections {
		t.Fatal("child teardown retained database or template permitted connections")
	}
	var cloneNames sync.Map
	t.Run("concurrent independent clones", func(t *testing.T) {
		for range 2 {
			t.Run("clone", func(t *testing.T) {
				t.Parallel()
				childCtx, child := template.New(t)
				var name string
				if err := child.QueryRow(childCtx, `SELECT current_database()`).Scan(&name); err != nil {
					t.Fatal(err)
				}
				if name == firstName || name == template.name {
					t.Fatal("concurrent clone reused existing fixture")
				}
				if _, duplicate := cloneNames.LoadOrStore(name, true); duplicate {
					t.Fatal("concurrent clones shared a database")
				}
			})
		}
	})
	cloneNames.Range(func(name, _ any) bool {
		var exists bool
		if err := first.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			t.Fatal("concurrent clone database retained after child cleanup")
		}
		return true
	})
	templateURL, err := databaseURL(os.Getenv("TUNNEX_TEST_DATABASE_URL"), template.name)
	if err != nil {
		t.Fatal(err)
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), fixtureTimeout)
	defer cancel()
	conn, err := pgx.Connect(connectCtx, templateURL)
	if err == nil {
		_ = conn.Close(connectCtx)
		t.Fatal("sealed source template accepted a test connection")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("source template refusal did not report disabled connections: %v", err)
	}
	if err := template.Close(); err != nil {
		t.Fatal(err)
	}
	var templateExists bool
	if err := first.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)`, template.name).Scan(&templateExists); err != nil {
		t.Fatal(err)
	}
	if templateExists {
		t.Fatal("package-owned source template retained after Close")
	}
	if _, err := template.prepare(os.Getenv("TUNNEX_TEST_DATABASE_URL")); err == nil {
		t.Fatal("closed source template recreated")
	}
	if err := template.Close(); err != nil {
		t.Fatalf("repeated cleanup: %v", err)
	}
}

func TestTemplateRequiresExplicitEndpoint(t *testing.T) {
	t.Setenv("TUNNEX_TEST_DATABASE_URL", "")
	var template Template
	ran := false
	t.Run("unconfigured fixture", func(t *testing.T) {
		template.New(t)
		ran = true
	})
	if ran || template.name != "" || template.admin != nil {
		t.Fatal("unconfigured template did not skip before creating state")
	}
	if err := template.Close(); err != nil {
		t.Fatal(err)
	}
}
