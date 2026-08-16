//go:build enterprise

package http

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/agenttemplates"
)

func NewAgentTemplatePort(pool *pgxpool.Pool, pusher agenttemplates.Pusher) agentTemplatePort {
	return agenttemplates.New(pool, pusher)
}
