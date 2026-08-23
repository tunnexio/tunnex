package http

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
)

// JIT access is wired into the single Tunnex binary. The handlers apply the
// Scale feature entitlement and organization opt-in before use.
func NewAgentAccessPort(pool *pgxpool.Pool, pusher agentaccess.Pusher) agentAccessPort {
	return agentaccess.New(pool, pusher)
}

func StartAgentAccessSweeper(ctx context.Context, pool *pgxpool.Pool, pusher agentaccess.Pusher, mayTick func() bool) {
	go agentaccess.New(pool, pusher).StartExpirySweeper(ctx, mayTick)
}
