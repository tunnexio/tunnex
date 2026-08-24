package http

import (
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/agenttemplates"
)

// Agent policy templates are part of the single Tunnex binary. Availability is
// controlled by the organization opt-in and the handler's permission and plan
// checks, never by a compile-time edition selection.
func NewAgentTemplatePort(pool *pgxpool.Pool, pusher agenttemplates.Pusher) agentTemplatePort {
	return agenttemplates.New(pool, pusher)
}
