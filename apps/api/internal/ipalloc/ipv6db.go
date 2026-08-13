package ipalloc

import (
	"context"
	"errors"
	"os"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnsureOrgIPv6Pool returns the persisted IPv6 /64 for an organization. The
// row is created lazily for organizations that predate the IPv6 pool
// migration; this keeps existing installations IPv4-only until the operator
// configures a valid deployment pool, without deriving different prefixes at
// each call site.
func EnsureOrgIPv6Pool(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (string, error) {
	if pool == nil {
		return "", nil
	}
	var cidr string
	err := pool.QueryRow(ctx, `SELECT pool_cidr FROM org_ipv6_pools WHERE org_id = $1`, orgID).Scan(&cidr)
	if err == nil {
		return cidr, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" { // migration not applied yet
			return "", nil
		}
		if !errors.As(err, &pgErr) {
			return "", err
		}
		return "", err
	}
	raw := os.Getenv("TUNNEX_IPV6_POOL_CIDR")
	if raw == "" {
		return "", nil
	}
	cidr, err = IPv6OrgPoolCIDR(raw, orgID)
	if err != nil {
		return "", err
	}
	if _, err = pool.Exec(ctx, `
		INSERT INTO org_ipv6_pools (org_id, pool_cidr)
		VALUES ($1, $2)
		ON CONFLICT (org_id) DO NOTHING`, orgID, cidr); err != nil {
		return "", err
	}
	return cidr, nil
}
