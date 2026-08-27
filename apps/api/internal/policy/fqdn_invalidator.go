package policy

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
)

// FQDNInvalidator is the post-commit bridge from Lane 2 persistence to the
// desired-policy push path. It intentionally performs no compilation and no
// resolver work: a durable generation transition first commits, then affected
// nodes are signalled to re-fetch the compiler's authoritative snapshot.
type FQDNInvalidator struct {
	pool   *pgxpool.Pool
	notify Notifier
}

func NewFQDNInvalidator(pool *pgxpool.Pool, notify Notifier) *FQDNInvalidator {
	return &FQDNInvalidator{pool: pool, notify: notify}
}

func (h *FQDNInvalidator) InvalidateFQDN(ctx context.Context, work fqdnresolver.Work) {
	if h == nil || h.pool == nil || h.notify == nil {
		return
	}
	ids, err := sqlc.New(h.pool).ListActiveNodeIDsForOrg(ctx, work.OrgID)
	if err != nil || len(ids) == 0 {
		return
	}
	h.notify.NotifyMany(ids)
}
