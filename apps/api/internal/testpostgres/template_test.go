package testpostgres

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

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
