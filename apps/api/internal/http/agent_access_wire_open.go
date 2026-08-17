//go:build !enterprise

package http

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
)

func NewAgentAccessPort(_ *pgxpool.Pool, _ agentaccess.Pusher) agentAccessPort { return nil }

func StartAgentAccessSweeper(_ context.Context, _ *pgxpool.Pool, _ agentaccess.Pusher, _ func() bool) {
}
