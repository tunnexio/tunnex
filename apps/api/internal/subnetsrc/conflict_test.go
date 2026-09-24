package subnetsrc

import (
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"testing"
)

func TestProviderConflict(t *testing.T) {
	for _, e := range []*pgconn.PgError{{Code: "23503", ConstraintName: "ipsec_provider_local_subnet_fk"}, {Code: "23514", ConstraintName: "ipsec_provider_conflict"}, {Code: "40001"}, {Code: "40P01"}} {
		var typed *apierr.Error
		if !errors.As(ProviderConflict(e), &typed) || typed.Status != 409 {
			t.Fatalf("expected scoped conflict for %s", e.Code)
		}
	}
	for _, e := range []error{nil, errors.New("unrelated"), &pgconn.PgError{Code: "23503", ConstraintName: "other"}} {
		if ProviderConflict(e) != e {
			t.Fatal("unrelated error changed")
		}
	}
}
