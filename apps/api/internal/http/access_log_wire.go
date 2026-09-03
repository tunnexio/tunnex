package http

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/accesslog"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
)

// accessLogAdapter is the enterprise access-log query port: keyset reads over the PG
// hot-window + the shared Health snapshot. Org-scoped by construction (every query takes
// org_id — querylint-enforced). (S7.5.1b) the JSONL source-of-truth verbatim export is deferred.
type accessLogAdapter struct {
	q      *sqlc.Queries
	pool   *pgxpool.Pool
	health *accesslog.Health
}

// NewAccessLogPort builds the enterprise port. The Health is SHARED with the flow-event
// Ingester (constructed in main) so the retention signals the ingest side records are the
// same ones this endpoint surfaces.
func NewAccessLogPort(pool *pgxpool.Pool, health *accesslog.Health) accessLogPort {
	return &accessLogAdapter{q: sqlc.New(pool), pool: pool, health: health}
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

// Collectors returns server-scoped instrumentation state for every active
// gateway in one organization. Event absence is deliberately not used as a
// health signal: an active collector on a quiet network is healthy, while an
// older gateway that never reported the capability remains unknown.
func (a *accessLogAdapter) Collectors(ctx context.Context, orgID uuid.UUID) ([]accessLogCollectorStatus, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT n.id,
		       n.name,
		       n.policy_reported_at,
		       COALESCE(NULLIF(n.capabilities ->> 'flow_log_state', ''), 'unknown') AS flow_log_state,
		       NULLIF(n.capabilities ->> 'flow_log_last_observed_at', '')::timestamptz AS flow_log_last_observed_at,
		       NULLIF(n.capabilities ->> 'flow_log_last_delivered_at', '')::timestamptz AS flow_log_last_delivered_at,
		       max(e.created_at) AS last_event_at
		FROM nodes n
		LEFT JOIN access_events e
		  ON e.org_id = n.org_id AND e.node_id = n.id
		WHERE n.org_id = $1 AND n.status = 'active'
		GROUP BY n.id, n.name, n.policy_reported_at, flow_log_state
		ORDER BY n.name, n.id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]accessLogCollectorStatus, 0)
	for rows.Next() {
		var item accessLogCollectorStatus
		if err := rows.Scan(&item.NodeID, &item.Name, &item.LastReportedAt, &item.State, &item.LastObservedAt, &item.LastDeliveredAt, &item.LastEventAt); err != nil {
			return nil, err
		}
		switch item.State {
		case "active", "disabled", "source_error", "delivery_error":
		default:
			item.State = "unknown"
		}
		// A stored active/error value is not a live heartbeat. Use the same
		// report-freshness contract as the rest of gateway health so an offline
		// gateway cannot remain reassuringly green forever. Fresh legacy agents
		// still report as unknown rather than stale.
		if item.LastReportedAt == nil || time.Since(*item.LastReportedAt) >= nodes.ReportFreshnessWindow {
			item.State = "stale"
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
