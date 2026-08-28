package policy

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
)

// FQDNInvalidator is the post-commit bridge from Lane 2 persistence to the
// desired-policy push path. It intentionally performs no compilation and no
// resolver work: a durable generation transition first commits, then affected
// nodes are signalled to re-fetch the compiler's authoritative snapshot.
type FQDNInvalidator struct {
	pool          *pgxpool.Pool
	notify        Notifier
	activeNodeIDs func(context.Context, uuid.UUID) ([]uuid.UUID, error)
}

func NewFQDNInvalidator(pool *pgxpool.Pool, notify Notifier) *FQDNInvalidator {
	return &FQDNInvalidator{
		pool:   pool,
		notify: notify,
		activeNodeIDs: func(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
			return sqlc.New(pool).ListActiveNodeIDsForOrg(ctx, orgID)
		},
	}
}

func (h *FQDNInvalidator) InvalidateFQDN(ctx context.Context, work fqdnresolver.Work) {
	h.InvalidateOrg(ctx, work.OrgID)
}

// InvalidateOrg wakes every active node whose desired policy may change for an
// organization-wide FQDN enforcement setting transition. The caller invokes it
// only after the opt-in transaction commits, so a failed transaction can never
// withdraw a live generation or create a spurious desired-state fetch.
func (h *FQDNInvalidator) InvalidateOrg(ctx context.Context, orgID uuid.UUID) {
	if h == nil || h.activeNodeIDs == nil || h.notify == nil {
		return
	}
	ids, err := h.activeNodeIDs(ctx, orgID)
	if err != nil || len(ids) == 0 {
		return
	}
	h.notify.NotifyMany(ids)
}
