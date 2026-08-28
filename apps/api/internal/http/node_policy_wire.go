package http

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

// NewNodePolicyProvider wires the one-binary policy engine as the node desired-state
// source. Resolver-backed answers are read only from Lane 2's durable selected-context
// snapshot; the named entitlement and organization opt-in remain fail-closed compiler
// inputs rather than DNS transport decisions.
func NewNodePolicyProvider(pool *pgxpool.Pool, licences *licence.Manager) nodes.PolicyProvider {
	return policy.NewService(pool).WithFQDNGenerations(
		fqdnresolver.NewPostgresStore(pool),
		func() bool { return licence.Has(licences.Evaluate(time.Now()).Tier, licence.FeatFQDNResources) },
	)
}
