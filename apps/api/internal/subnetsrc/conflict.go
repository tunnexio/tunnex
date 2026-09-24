package subnetsrc

import (
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// ProviderConflict maps only provider boundaries and transaction retry failures.
// It never exposes driver details or changes unrelated database classifications.
func ProviderConflict(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	if pg.Code == "23503" && pg.ConstraintName == "ipsec_provider_local_subnet_fk" {
		return apierr.Conflict("ipsec_subnet_in_use", "Delete the IPsec connection before removing its approved local subnet.")
	}
	if pg.Code == "23514" && pg.ConstraintName == "ipsec_provider_conflict" {
		return apierr.Conflict("ipsec_range_conflict", "The range conflicts with an IPsec configuration reservation.")
	}
	if pg.Code == "40001" || pg.Code == "40P01" {
		return apierr.Conflict("range_changed", "Network ranges changed concurrently; refresh and retry.")
	}
	return err
}
