package ipsecguard

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

func TestResourceConflict(t *testing.T) {
	for _, name := range []string{"ipsec_connections_site_id_org_id_fkey", "ipsec_connections_gateway_node_id_org_id_site_id_fkey"} {
		for _, wrapped := range []bool{false, true} {
			var input error = &pgconn.PgError{Code: "23503", ConstraintName: name, Message: "private detail", Detail: "secret"}
			if wrapped {
				input = fmt.Errorf("query failed: %w", input)
			}
			got := ResourceConflict(input)
			var typed *apierr.Error
			if !errors.As(got, &typed) || typed.Status != 409 || typed.Code != "ipsec_connection_in_use" {
				t.Fatalf("%s wrapped=%v: %v", name, wrapped, got)
			}
			if strings.Contains(got.Error(), "secret") || strings.Contains(got.Error(), "private") || strings.Contains(got.Error(), name) {
				t.Fatalf("leaked database details: %v", got)
			}
		}
	}
	for _, input := range []error{nil, errors.New("other"), &pgconn.PgError{Code: "23503", ConstraintName: "unrelated_fkey"}, &pgconn.PgError{Code: "23514", ConstraintName: "ipsec_connections_site_id_org_id_fkey"}, &pgconn.PgError{Code: "23503", ConstraintName: "ipsec_connections_org_id_fkey"}} {
		if got := ResourceConflict(input); got != input {
			t.Fatalf("unrelated error changed: %v -> %v", input, got)
		}
	}
}
