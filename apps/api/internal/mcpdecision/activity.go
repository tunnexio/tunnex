package mcpdecision

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// ActivityFilter narrows an agent's MCP activity. The zero value keeps everything.
type ActivityFilter struct {
	// Decision is "allow", "deny" or empty for both.
	Decision string
	// ApprovedOnly keeps calls that ran on an approval.
	ApprovedOnly bool
	From, To     *time.Time
	// Server is the server name of an MCP profile; empty for every server.
	Server string
}

// ActivityRow is one activity row with the approval it ran on, if any.
type ActivityRow = sqlc.ListAgentMCPToolActivityFilteredRow

// ExportLimit is the most rows one CSV export carries.
const ExportLimit = 10000

// AuditActivityExported is written for every CSV export.
const AuditActivityExported = "agent.mcp_tool_activity.exported"

func (s *Service) filterParams(ctx context.Context, orgID, deviceID uuid.UUID, filter ActivityFilter) (sqlc.ListAgentMCPToolActivityFilteredParams, bool, error) {
	params := sqlc.ListAgentMCPToolActivityFilteredParams{OrgID: orgID, DeviceID: deviceID, ApprovedOnly: filter.ApprovedOnly}
	switch filter.Decision {
	case "":
	case "allow", "deny":
		decision := filter.Decision
		params.Decision = &decision
	default:
		return params, false, ErrInvalid
	}
	if filter.From != nil {
		params.OccurredFrom = pgtype.Timestamptz{Time: *filter.From, Valid: true}
	}
	if filter.To != nil {
		params.OccurredTo = pgtype.Timestamptz{Time: *filter.To, Valid: true}
	}
	if filter.Server != "" {
		// Activity stores the address a call went to. The name is the profile's, so a profile that no
		// longer exists matches nothing.
		profile, err := s.q.GetActiveAgentMCPProfileByServerName(ctx, sqlc.GetActiveAgentMCPProfileByServerNameParams{OrgID: orgID, ServerName: filter.Server})
		if errors.Is(err, pgx.ErrNoRows) {
			return params, false, nil
		}
		if err != nil {
			return params, false, err
		}
		endpoint := strings.TrimSpace(profile.Endpoint)
		params.Endpoint = &endpoint
	}
	return params, true, nil
}

// ListActivityFiltered returns one page of an agent's MCP activity that matches the filter, newest first,
// each row with who approved it and when, and the cursor of the next page ("" when there is none).
func (s *Service) ListActivityFiltered(ctx context.Context, orgID, deviceID uuid.UUID, filter ActivityFilter, limit int, cursor string) ([]ActivityRow, string, error) {
	if orgID == uuid.Nil || deviceID == uuid.Nil {
		return nil, "", ErrInvalid
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	params, matches, err := s.filterParams(ctx, orgID, deviceID, filter)
	if err != nil || !matches {
		return []ActivityRow{}, "", err
	}
	params.PageLimit = int32(limit) + 1
	if cursor != "" {
		at, id, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", ErrCursor
		}
		params.BeforeOccurredAt, params.BeforeID = pgtype.Timestamptz{Time: at, Valid: true}, pgtype.UUID{Bytes: id, Valid: true}
	}
	rows, err := s.q.ListAgentMCPToolActivityFiltered(ctx, params)
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

// ExportActivity returns up to ExportLimit rows that match the filter, newest first, and records who
// exported them. truncated is true when more rows matched than were returned.
func (s *Service) ExportActivity(ctx context.Context, orgID, deviceID, actorID uuid.UUID, filter ActivityFilter) (rows []ActivityRow, truncated bool, err error) {
	if orgID == uuid.Nil || deviceID == uuid.Nil || actorID == uuid.Nil {
		return nil, false, ErrInvalid
	}
	params, matches, err := s.filterParams(ctx, orgID, deviceID, filter)
	if err != nil {
		return nil, false, err
	}
	if matches {
		params.PageLimit = ExportLimit + 1
		if rows, err = s.q.ListAgentMCPToolActivityFiltered(ctx, params); err != nil {
			return nil, false, err
		}
		if len(rows) > ExportLimit {
			rows, truncated = rows[:ExportLimit], true
		}
	}
	metadata := map[string]any{"row_count": len(rows), "truncated": truncated, "approved_only": filter.ApprovedOnly}
	if filter.Decision != "" {
		metadata["decision"] = filter.Decision
	}
	if filter.Server != "" {
		metadata["server"] = filter.Server
	}
	if filter.From != nil {
		metadata["from"] = filter.From.UTC().Format(time.RFC3339)
	}
	if filter.To != nil {
		metadata["to"] = filter.To.UTC().Format(time.RFC3339)
	}
	raw, _ := json.Marshal(metadata)
	if _, err := s.pool.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,$3,'agent',$4,$5)`, orgID, actorID, AuditActivityExported, deviceID.String(), raw); err != nil {
		// An export that cannot be recorded is not handed out.
		return nil, false, err
	}
	return rows, truncated, nil
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
