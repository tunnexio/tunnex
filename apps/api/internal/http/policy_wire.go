package http

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/nodepush"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
)

// NewPolicyPort builds the enterprise Zero Trust policy port. The push hub is wired so
// every policy mutation signals the org's gateways to re-fetch + recompile within the
// <5s spec (S7.2). policy.Service returns sqlc rows, matching policyPort directly.
func NewPolicyPort(pool *pgxpool.Pool, hub *nodepush.Hub) policyPort {
	svc := policy.NewService(pool)
	svc.SetNotifier(hub)
	return svc
}

// StartPolicyGrantSweeper runs the S7.5.4 temporary-grant expiry sweep (enterprise
// only): a lapsed grant's /32 is pushed off every org gateway promptly (the compiler
// filter is the correctness backstop; this is promptness). No-op in the open build.
// mayTick gates the sweep on scheduler leadership (S13.1 review #10): it DELETES expired grants, audits each, and
// pushes affected orgs, so N replicas means N concurrent delete-and-push cycles over the same rows.
func StartPolicyGrantSweeper(ctx context.Context, pool *pgxpool.Pool, hub *nodepush.Hub, mayTick func() bool) {
	svc := policy.NewService(pool)
	svc.SetNotifier(hub)
	go svc.StartGrantExpirySweeper(ctx, mayTick)
}
