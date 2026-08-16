package http

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
)

// accessLogAdapter is the enterprise access-log query port: keyset reads over the PG
// hot-window + the shared Health snapshot. Org-scoped by construction (every query takes
// org_id — querylint-enforced). (S7.5.1b) the JSONL source-of-truth verbatim export is deferred.
type accessLogAdapter struct {
	q      *sqlc.Queries
	health *accesslog.Health
}

// NewAccessLogPort builds the enterprise port. The Health is SHARED with the flow-event
// Ingester (constructed in main) so the retention signals the ingest side records are the
// same ones this endpoint surfaces.
func NewAccessLogPort(pool *pgxpool.Pool, health *accesslog.Health) accessLogPort {
	return &accessLogAdapter{q: sqlc.New(pool), health: health}
}

func (a *accessLogAdapter) List(ctx context.Context, orgID uuid.UUID, agentID *uuid.UUID, deniesOnly bool, cursorTS time.Time, cursorID uuid.UUID, limit int32) ([]accesslog.Event, error) {
	if agentID != nil {
		argID := pgtype.UUID{Bytes: *agentID, Valid: true}
		var rows []sqlc.AccessEvent
		var err error
		if deniesOnly {
			rows, err = a.q.ListAccessDeniesByAgent(ctx, sqlc.ListAccessDeniesByAgentParams{OrgID: orgID, SrcAgentID: argID, BeforeCreatedAt: cursorTS, BeforeID: cursorID, PageLimit: limit})
		} else {
			rows, err = a.q.ListAccessEventsByAgent(ctx, sqlc.ListAccessEventsByAgentParams{OrgID: orgID, SrcAgentID: argID, BeforeCreatedAt: cursorTS, BeforeID: cursorID, PageLimit: limit})
		}
		if err != nil {
			return nil, err
		}
		out := make([]accesslog.Event, len(rows))
		for i, r := range rows {
			out[i] = accesslog.FromRow(r)
		}
		return out, nil
	}
	if deniesOnly {
		rows, err := a.q.ListAccessDenies(ctx, sqlc.ListAccessDeniesParams{OrgID: orgID, BeforeCreatedAt: cursorTS, BeforeID: cursorID, PageLimit: limit})
		if err != nil {
			return nil, err
		}
		out := make([]accesslog.Event, len(rows))
		for i, r := range rows {
			out[i] = accesslog.FromRow(r)
		}
		return out, nil
	}
	rows, err := a.q.ListAccessEvents(ctx, sqlc.ListAccessEventsParams{OrgID: orgID, BeforeCreatedAt: cursorTS, BeforeID: cursorID, PageLimit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]accesslog.Event, len(rows))
	for i, r := range rows {
		out[i] = accesslog.FromRow(r)
	}
	return out, nil
}

func (a *accessLogAdapter) Health() accesslog.Snapshot { return a.health.Snapshot() }
