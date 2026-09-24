package ipsec

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrConnectionUnavailable = errors.New("IPsec connection unavailable")
	ErrConnectionNotFound    = errors.New("IPsec connection not found")
	ErrConnectionConflict    = errors.New("IPsec connection revision changed")
	ErrConnectionInvalid     = errors.New("IPsec connection request invalid")
)

// Connection is an explicit ordinary-reader projection. It has no tunnel or
// credential metadata and must never be replaced by a persistence-row DTO.
type Connection struct {
	ApplicationState        string     `json:"application_state"`
	CleanupState            string     `json:"cleanup_state"`
	ID                      uuid.UUID  `json:"id"`
	OrgID                   uuid.UUID  `json:"org_id"`
	Name                    string     `json:"name"`
	SiteID                  *uuid.UUID `json:"site_id"`
	GatewayNodeID           *uuid.UUID `json:"gateway_node_id"`
	HistoricalSiteID        uuid.UUID  `json:"historical_site_id"`
	HistoricalGatewayNodeID uuid.UUID  `json:"historical_gateway_node_id"`
	DesiredRevision         int64      `json:"desired_revision"`
	DesiredIntent           string     `json:"desired_intent"`
	DeletedAt               *time.Time `json:"deleted_at"`
	FinalizedAt             *time.Time `json:"finalized_at"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

type ConnectionStore struct {
	pool          *pgxpool.Pool
	runtimePolicy RuntimePolicyCompiler
}

func NewConnectionStore(pool *pgxpool.Pool) *ConnectionStore { return &ConnectionStore{pool: pool} }

const connectionColumns = `c.id,c.org_id,c.name,c.site_id,c.gateway_node_id,c.historical_site_id,c.historical_gateway_node_id,c.desired_revision,c.desired_intent,c.deleted_at,c.finalized_at,c.created_at,c.updated_at,
 CASE WHEN c.desired_intent='enabled' THEN CASE WHEN EXISTS(SELECT 1 FROM ipsec_runtime_state r WHERE r.connection_id=c.id AND r.applied_revision=c.desired_revision) THEN 'applied' ELSE 'pending' END ELSE 'not_applied' END,
 CASE WHEN EXISTS(SELECT 1 FROM ipsec_runtime_state r WHERE r.connection_id=c.id AND r.current_cleanup_id IS NOT NULL) THEN 'pending' WHEN EXISTS(SELECT 1 FROM ipsec_retained_guards r WHERE r.connection_id=c.id) THEN 'retained_guard' ELSE 'not_required' END`

func scanConnection(row pgx.Row) (Connection, error) {
	var c Connection
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.SiteID, &c.GatewayNodeID, &c.HistoricalSiteID, &c.HistoricalGatewayNodeID, &c.DesiredRevision, &c.DesiredIntent, &c.DeletedAt, &c.FinalizedAt, &c.CreatedAt, &c.UpdatedAt, &c.ApplicationState, &c.CleanupState)
	return c, err
}

// Read requires an already-authorized org:view scope.
func (s *ConnectionStore) Read(ctx context.Context, org, id uuid.UUID) (Connection, error) {
	if s == nil || s.pool == nil {
		return Connection{}, ErrConnectionUnavailable
	}
	c, err := scanConnection(s.pool.QueryRow(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c JOIN organizations o ON o.id=c.org_id WHERE c.org_id=$1 AND c.id=$2 AND o.deleted_at IS NULL`, org, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, ErrConnectionNotFound
	}
	if err != nil {
		return Connection{}, ErrConnectionUnavailable
	}
	return c, nil
}

// List is internal-only until the public API specifies pagination. The read-only
// snapshot consistently distinguishes a missing organization from an empty one.
// Tombstones remain visible; callers must not label stored records as live links.
func (s *ConnectionStore) List(ctx context.Context, org uuid.UUID) ([]Connection, error) {
	if s == nil || s.pool == nil {
		return nil, ErrConnectionUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, ErrConnectionUnavailable
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var live uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL`, org).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConnectionNotFound
	}
	if err != nil {
		return nil, ErrConnectionUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c WHERE c.org_id=$1 ORDER BY c.created_at,c.id`, org)
	if err != nil {
		return nil, ErrConnectionUnavailable
	}
	defer rows.Close()
	result := make([]Connection, 0)
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, ErrConnectionUnavailable
		}
		result = append(result, c)
	}
	if rows.Err() != nil {
		return nil, ErrConnectionUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, ErrConnectionUnavailable
	}
	return result, nil
}

// ConnectionPage is a bounded, redacted page. NextCursor is the last returned
// identity only when another record existed in this request's snapshot.
type ConnectionPage struct {
	Items      []Connection `json:"items"`
	NextCursor *uuid.UUID   `json:"next_cursor,omitempty"`
}

// ListPage uses ID keyset ordering, not mutable names or timestamps. A cursor is
// only a position; every page independently enforces the authorized organization.
// Each call has a consistent live-org snapshot, not a snapshot across requests.
func (s *ConnectionStore) ListPage(ctx context.Context, org uuid.UUID, after *uuid.UUID, limit int) (ConnectionPage, error) {
	if limit < 1 || limit > 100 {
		return ConnectionPage{}, ErrConnectionInvalid
	}
	if s == nil || s.pool == nil {
		return ConnectionPage{}, ErrConnectionUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ConnectionPage{}, ErrConnectionUnavailable
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var live uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id=$1 AND deleted_at IS NULL`, org).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionPage{}, ErrConnectionNotFound
	}
	if err != nil {
		return ConnectionPage{}, ErrConnectionUnavailable
	}
	rows, err := tx.Query(ctx, `SELECT `+connectionColumns+` FROM ipsec_connections c WHERE c.org_id=$1 AND ($2::uuid IS NULL OR c.id>$2::uuid) ORDER BY c.id LIMIT $3`, org, after, limit+1)
	if err != nil {
		return ConnectionPage{}, ErrConnectionUnavailable
	}
	defer rows.Close()
	result := ConnectionPage{Items: make([]Connection, 0, limit)}
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return ConnectionPage{}, ErrConnectionUnavailable
		}
		result.Items = append(result.Items, c)
	}
	if rows.Err() != nil {
		return ConnectionPage{}, ErrConnectionUnavailable
	}
	if len(result.Items) > limit {
		cursor := result.Items[limit-1].ID
		result.NextCursor = &cursor
		result.Items = result.Items[:limit]
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectionPage{}, ErrConnectionUnavailable
	}
	return result, nil
}

// Delete requires verified-human ipsec:manage authorization, an authoritative
// actor, and an authorized org scope. It only finalizes schema158 never-delivered
// disabled records; a future runtime schema needs a separate cleanup state gate.
// Lock range advisory key, org, then connection: settings/site/gateway eligibility is intentionally not
// read, since withdrawal must work with opt-in off or a revoked gateway. Existing
// foreign keys serialize destructive ownership changes until references release.
func (s *ConnectionStore) Delete(ctx context.Context, org, actor, id uuid.UUID, expectedRevision int64) (Connection, error) {
	return s.changeIntent(ctx, org, actor, id, expectedRevision, "deleted")
}
