package mcptoolapproval

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
)

// ErrCursor means a page cursor was not one this service issued.
var ErrCursor = errors.New("invalid MCP approval cursor")

// InboxItem is one request in the organization's Approvals inbox: the request, the agent that is asking
// and that agent's owner.
type InboxItem struct {
	Request    Request
	AgentName  string
	OwnerEmail *string
}

// ListOrganization pages the requests of every current agent of the organization, newest first.
// onlyPending keeps the ones still waiting for a decision. Requests past their lifetime are expired first,
// so the inbox shows what a decision would see.
func (s *Service) ListOrganization(ctx context.Context, orgID uuid.UUID, onlyPending bool, limit int, cursor string) ([]InboxItem, string, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil {
		return nil, "", ErrInvalid
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	params := sqlc.ListOrganizationMCPToolApprovalRequestsParams{OrgID: orgID, OnlyPending: onlyPending, PageLimit: int32(limit) + 1}
	if cursor != "" {
		at, id, err := decodeCursor(cursor)
		if err != nil {
			return nil, "", ErrCursor
		}
		params.BeforeRequestedAt, params.BeforeID = pgtype.Timestamptz{Time: at, Valid: true}, pgtype.UUID{Bytes: id, Valid: true}
	}
	if _, err := s.expire(ctx, &orgID, nil, 1000); err != nil {
		return nil, "", err
	}
	rows, err := sqlc.New(s.pool).ListOrganizationMCPToolApprovalRequests(ctx, params)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = encodeCursor(last.RequestedAt, last.ID)
	}
	out := make([]InboxItem, 0, len(rows))
	for _, row := range rows {
		r := Request{ID: row.ID, OrgID: row.OrgID, DeviceID: row.DeviceID, PolicyVersion: row.PolicyVersion, Endpoint: row.Endpoint, ServerName: row.ServerName, ToolName: row.ToolName,
			InputSchemaHash: row.InputSchemaHash, RequestDigest: row.RequestDigest, State: row.State, RequestedAt: row.RequestedAt, ExpiresAt: row.ExpiresAt,
			Arguments: row.Arguments, ArgumentsTruncated: row.ArgumentsTruncated, PolicySource: row.PolicySource}
		// The single-agent list marks "never" with the epoch; keep one convention for both.
		r.ApprovedAt, r.DeniedAt, r.ConsumedAt = time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC()
		if row.ApprovedAt.Valid {
			r.ApprovedAt = row.ApprovedAt.Time
		}
		if row.DeniedAt.Valid {
			r.DeniedAt = row.DeniedAt.Time
		}
		if row.ConsumedAt.Valid {
			r.ConsumedAt = row.ConsumedAt.Time
		}
		if row.ApprovedByUserID.Valid {
			r.ApprovedByUserID = row.ApprovedByUserID.Bytes
		}
		if row.DeniedByUserID.Valid {
			r.DeniedByUserID = row.DeniedByUserID.Bytes
		}
		if row.PolicyGroupID.Valid {
			r.PolicyGroupID = row.PolicyGroupID.Bytes
		}
		if row.ToolDefinitionHash != nil {
			r.ToolDefinitionHash = *row.ToolDefinitionHash
		}
		out = append(out, InboxItem{Request: r, AgentName: row.AgentName, OwnerEmail: row.OwnerEmail})
	}
	return out, next, nil
}

// CountPending is the number of requests of current agents still waiting for a decision.
func (s *Service) CountPending(ctx context.Context, orgID uuid.UUID) (int, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil {
		return 0, ErrInvalid
	}
	n, err := sqlc.New(s.pool).CountPendingOrganizationMCPToolApprovalRequests(ctx, orgID)
	return int(n), err
}

// States a held call can learn while it waits.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateDenied   = "denied"
	StateExpired  = "expired"
)

// State reports where one agent's request stands, for a call the gateway is holding open. It never
// changes the request: approved here still has to be consumed by the decision that follows. A request
// that was already used, or is past its lifetime, is expired. ErrNotFound when the request is not that
// agent's.
func (s *Service) State(ctx context.Context, orgID, deviceID, requestID uuid.UUID) (string, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || requestID == uuid.Nil {
		return "", ErrInvalid
	}
	row, err := sqlc.New(s.pool).GetAgentMCPToolApprovalRequestState(ctx, sqlc.GetAgentMCPToolApprovalRequestStateParams{ID: requestID, OrgID: orgID, DeviceID: deviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	switch {
	case row.State == StateDenied:
		return StateDenied, nil
	case row.State != StatePending && row.State != StateApproved, !row.ExpiresAt.After(s.now().UTC()):
		return StateExpired, nil
	}
	return row.State, nil
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
