// Package ipsecguard maps the IPsec ownership boundary without coupling existing
// site and gateway services to the connection store.
package ipsecguard

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// ResourceConflict recognizes only schema 158's live resource references. The
// database enforces this boundary atomically against concurrent connection writes.
// Other errors retain their existing classification; no driver details escape.
func ResourceConflict(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23503" {
		return err
	}
	switch pg.ConstraintName {
	case "ipsec_connections_site_id_org_id_fkey", "ipsec_connections_gateway_node_id_org_id_site_id_fkey":
		return apierr.Conflict("ipsec_connection_in_use", "Delete the IPsec connection before removing its site or gateway.")
	default:
		return err
	}
}
