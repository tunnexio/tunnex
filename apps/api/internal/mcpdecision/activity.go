package mcpdecision

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/mcptoolapproval"
)

// DefaultActivityRetentionDays applies to an organization that has saved no retention setting.
const DefaultActivityRetentionDays = 30

const (
	// ActivityRetentionInterval is how often the leader sweeps.
	ActivityRetentionInterval = 15 * time.Minute
	activityDeleteBatch       = 5000
	activityMaxBatchesPerOrg  = 40
)

// ErrCursor means a page cursor was not one this service issued.
var ErrCursor = errors.New("invalid MCP activity cursor")

// ListActivity returns one page of an agent's MCP activity, newest first, and the cursor of the next page
// ("" when there is none).
func (s *Service) ListActivity(ctx context.Context, orgID, deviceID uuid.UUID, limit int, cursor string) ([]sqlc.AgentMcpToolActivity, string, error) {
	if orgID == uuid.Nil || deviceID == uuid.Nil {
		return nil, "", ErrInvalid
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	params := sqlc.ListAgentMCPToolActivityParams{OrgID: orgID, DeviceID: deviceID, PageLimit: int32(limit) + 1}
	if cursor != "" {
		at, id, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", ErrCursor
		}
		params.BeforeOccurredAt, params.BeforeID = pgtype.Timestamptz{Time: at, Valid: true}, pgtype.UUID{Bytes: id, Valid: true}
	}
	rows, err := s.q.ListAgentMCPToolActivity(ctx, params)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = encodeCursor(last.OccurredAt, last.ID)
	}
	return rows, next, nil
}

func encodeCursor(at time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id.String()))
}

func decodeCursor(cursor string) (time.Time, uuid.UUID, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return time.Time{}, uuid.Nil, ErrCursor
	}
	when, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	parsed, err := uuid.Parse(id)
	return when, parsed, err
}

// SweepResult is what one retention pass did.
type SweepResult struct {
	Organizations    int
	DeletedRows      int64
	ExpiredApprovals int
	MorePending      bool
}

// Sweep deletes activity older than each organization's retention period, in bounded batches, and expires
// step-up requests nobody answered. It is safe to run on more than one replica (batches skip locked rows),
// but the caller runs it on the leader only.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var out SweepResult
	if s.approvals != nil {
		expired, err := s.approvals.ExpireDue(ctx, 1000)
		if err != nil && !errors.Is(err, mcptoolapproval.ErrInvalid) {
			return out, err
		}
		out.ExpiredApprovals = expired
	}
	orgs, err := s.q.ListOrganizationsWithAgentMCPToolActivity(ctx)
	if err != nil {
		return out, err
	}
	now := s.now().UTC()
	for _, orgID := range orgs {
		days := int32(DefaultActivityRetentionDays)
		setting, err := s.q.GetAgentMCPToolActivityRetention(ctx, orgID)
		if err == nil {
			days = setting.RetentionDays
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return out, err
		}
		cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
		out.Organizations++
		for batch := 0; ; batch++ {
			if batch == activityMaxBatchesPerOrg {
				out.MorePending = true
				break
			}
			deleted, err := s.q.DeleteAgentMCPToolActivityBatch(ctx, sqlc.DeleteAgentMCPToolActivityBatchParams{OrgID: orgID, Cutoff: cutoff, BatchLimit: activityDeleteBatch})
			if err != nil {
				return out, err
			}
			out.DeletedRows += deleted
			if deleted < activityDeleteBatch {
				break
			}
		}
	}
	return out, nil
}
