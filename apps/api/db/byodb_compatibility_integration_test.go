package db_test

import (
	"context"
	"os"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/dbcheck"
)

// Run only against an explicitly provisioned empty compatibility fixture.
func TestBYODBVersionCompatibility(t *testing.T) {
	raw := os.Getenv("TUNNEX_COMPAT_DATABASE_URL")
	if raw == "" {
		t.Skip("requires dedicated empty PG16/17/18 TLS fixture")
	}
	if err := dbcheck.Run(context.Background(), raw, true, true); err != nil {
		t.Fatal(err)
	}
	if err := db.Up(raw); err != nil {
		t.Fatal(dbcheck.SafeError(err))
	}
	v, dirty, ok, err := db.Version(raw)
	if err != nil || !ok || dirty || v == 0 {
		t.Fatal("migration version is not clean")
	}
	if err := db.DownOne(raw); err != nil {
		t.Fatal(dbcheck.SafeError(err))
	}
	if err := db.Up(raw); err != nil {
		t.Fatal(dbcheck.SafeError(err))
	}
	got, dirty, ok, err := db.Version(raw)
	if err != nil || !ok || dirty || got != v {
		t.Fatal("up/down/up did not converge")
	}
	if err := dbcheck.Run(context.Background(), raw, true, false); err != nil {
		t.Fatal(err)
	}
}
