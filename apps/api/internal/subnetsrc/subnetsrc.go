// Package subnetsrc adapts *sqlc.Queries to subnetguard.RangeSource — the ONE adapter every disjointness
// caller uses, so the org's VIP ranges (and every future range class) are queried for free and can't be
// silently omitted (the validator-input-filtering law, S10.3 F2).
package subnetsrc

import (
	"context"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/subnetguard"
)

// Source wraps a querier (a *sqlc.Queries, or its tx-scoped clone) as a subnetguard.RangeSource.
type Source struct{ Q *sqlc.Queries }

func (s Source) SiteSubnetCIDRs(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	rows, err := s.Q.ListSiteSubnetsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Cidr.String())
	}
	return out, nil
}

func (s Source) PoolCIDR(ctx context.Context, orgID uuid.UUID) (string, error) {
	o, err := s.Q.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return "", err
	}
	return o.PoolCidr, nil
}

func (s Source) VIPRangeCIDRs(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	return s.Q.ListVIPRangesForOrg(ctx, orgID)
}

// IPsecReservations includes every live address reservation, including disabled configurations.
func (s Source) IPsecReservations(ctx context.Context, orgID uuid.UUID) ([]subnetguard.IPsecReservation, error) {
	rows, err := s.Q.ListIPsecProviderReservations(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]subnetguard.IPsecReservation, 0, len(rows))
	for _, r := range rows {
		out = append(out, subnetguard.IPsecReservation{CIDR: r.Cidr, Class: subnetguard.OverlapClass(r.Class)})
	}
	return out, nil
}
