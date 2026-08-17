//go:build !enterprise

package http

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/agenttemplates"
)

func NewAgentTemplatePort(_ *pgxpool.Pool, _ agenttemplates.Pusher) agentTemplatePort { return nil }
