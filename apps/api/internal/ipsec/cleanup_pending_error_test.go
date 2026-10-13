package ipsec

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCleanupPendingDatabaseErrorTranslation(t *testing.T) {
	for _, err := range []error{
		&pgconn.PgError{Code: "23514", ConstraintName: "ipsec_runtime_cleanup_pending", Message: "private synthetic detail"},
		fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: "23514", ConstraintName: "ipsec_runtime_cleanup_pending"}),
	} {
		if got := createError(err); !errors.Is(got, ErrCleanupInProgress) {
			t.Fatal("dedicated pending-cleanup constraint not translated", got)
		}
	}
	for _, tc := range []struct {
		code, constraint string
		want             error
	}{
		{"23514", "unknown_constraint", ErrConnectionUnavailable},
		{"99999", "ipsec_runtime_cleanup_pending", ErrConnectionUnavailable},
		{"23514", "ipsec_runtime_binding", ErrConnectionConflict},
		{"23514", "ipsec_provider_conflict", ErrConnectionConflict},
		{"23505", "other_unique", ErrConnectionConflict},
	} {
		if got := createError(&pgconn.PgError{Code: tc.code, ConstraintName: tc.constraint}); !errors.Is(got, tc.want) {
			t.Fatalf("%s/%s changed existing translation: %v", tc.code, tc.constraint, got)
		}
	}
}
