// Package mcptoolapproval owns one-use F16 step-up approvals.
package mcptoolapproval

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const lifetime = 5 * time.Minute

var (
	ErrInvalid  = errors.New("invalid MCP tool approval")
	ErrNotFound = errors.New("MCP tool approval not found")
	ErrConflict = errors.New("MCP tool approval conflicts with current state")
)

type Request struct {
	ID               uuid.UUID
	OrgID            uuid.UUID
	DeviceID         uuid.UUID
	PolicyVersion    int64
	Endpoint         string
	ServerName       string
	ToolName         string
	InputSchemaHash  string
	RequestDigest    string
	State            string
	RequestedAt      time.Time
	ExpiresAt        time.Time
	ApprovedByUserID uuid.UUID
	ApprovedAt       time.Time
	ConsumedAt       time.Time
}

type Identity struct {
	PolicyVersion                                                  int64
	Endpoint, ServerName, ToolName, InputSchemaHash, RequestDigest string
}

type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool, now: time.Now} }

// Permit returns true exactly once after an authorized human has approved the
// exact runtime request. Otherwise it records/reuses a pending request.
func (s *Service) Permit(ctx context.Context, orgID, deviceID uuid.UUID, in Identity) (Request, bool, error) {
	if !valid(orgID, deviceID, in) {
		return Request{}, false, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, false, err
	}
	defer tx.Rollback(ctx)
	now := s.now().UTC()
	var r Request
	err = scan(tx.QueryRow(ctx, `SELECT id,org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,state,requested_at,expires_at,COALESCE(approved_by_user_id,'00000000-0000-0000-0000-000000000000'),COALESCE(approved_at,'epoch'),COALESCE(consumed_at,'epoch')
FROM agent_mcp_tool_approval_requests WHERE org_id=$1 AND device_id=$2 AND policy_version=$3 AND endpoint=$4 AND server_name=$5 AND tool_name=$6 AND input_schema_hash=$7 AND request_digest=$8 AND state IN ('pending','approved') FOR UPDATE`,
		orgID, deviceID, in.PolicyVersion, in.Endpoint, in.ServerName, in.ToolName, in.InputSchemaHash, in.RequestDigest), &r)
	if errors.Is(err, pgx.ErrNoRows) {
		err = scan(tx.QueryRow(ctx, `INSERT INTO agent_mcp_tool_approval_requests (org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,state,requested_at,expires_at,COALESCE(approved_by_user_id,'00000000-0000-0000-0000-000000000000'),COALESCE(approved_at,'epoch'),COALESCE(consumed_at,'epoch')`, orgID, deviceID, in.PolicyVersion, in.Endpoint, in.ServerName, in.ToolName, in.InputSchemaHash, in.RequestDigest, now.Add(lifetime)), &r)
		if err != nil {
			return Request{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Request{}, false, err
		}
		return r, false, nil
	}
	if err != nil {
		return Request{}, false, err
	}
	if !r.ExpiresAt.After(now) {
		_, err = tx.Exec(ctx, `UPDATE agent_mcp_tool_approval_requests SET state='expired' WHERE id=$1 AND state IN ('pending','approved')`, r.ID)
		if err != nil {
			return Request{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Request{}, false, err
		}
		return r, false, nil
	}
	if r.State != "approved" {
		if err := tx.Commit(ctx); err != nil {
			return Request{}, false, err
		}
		return r, false, nil
	}
	if _, err = tx.Exec(ctx, `UPDATE agent_mcp_tool_approval_requests SET state='consumed', consumed_at=$2 WHERE id=$1 AND state='approved'`, r.ID, now); err != nil {
		return Request{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Request{}, false, err
	}
	r.State, r.ConsumedAt = "consumed", now
	return r, true, nil
}

func (s *Service) Approve(ctx context.Context, orgID, deviceID, requestID, actorID uuid.UUID) (Request, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || requestID == uuid.Nil || actorID == uuid.Nil {
		return Request{}, ErrInvalid
	}
	var r Request
	err := scan(s.pool.QueryRow(ctx, `UPDATE agent_mcp_tool_approval_requests SET state='approved',approved_by_user_id=$4,approved_at=now() WHERE id=$1 AND org_id=$2 AND device_id=$3 AND state='pending' AND expires_at>now() RETURNING id,org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,state,requested_at,expires_at,COALESCE(approved_by_user_id,'00000000-0000-0000-0000-000000000000'),COALESCE(approved_at,'epoch'),COALESCE(consumed_at,'epoch')`, requestID, orgID, deviceID, actorID), &r)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrConflict
	}
	return r, err
}

func (s *Service) List(ctx context.Context, orgID, deviceID uuid.UUID) ([]Request, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil {
		return nil, ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT id,org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,state,requested_at,expires_at,COALESCE(approved_by_user_id,'00000000-0000-0000-0000-000000000000'),COALESCE(approved_at,'epoch'),COALESCE(consumed_at,'epoch')
FROM agent_mcp_tool_approval_requests WHERE org_id=$1 AND device_id=$2 ORDER BY requested_at DESC LIMIT 100`, orgID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		var r Request
		if err := scan(rows, &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func valid(orgID, deviceID uuid.UUID, in Identity) bool {
	return orgID != uuid.Nil && deviceID != uuid.Nil && in.PolicyVersion > 0 && len(in.Endpoint) > 0 && len(in.ServerName) > 0 && len(in.ToolName) > 0 && len(in.InputSchemaHash) > 0 && len(in.RequestDigest) == 64
}
func scan(row pgx.Row, r *Request) error {
	return row.Scan(&r.ID, &r.OrgID, &r.DeviceID, &r.PolicyVersion, &r.Endpoint, &r.ServerName, &r.ToolName, &r.InputSchemaHash, &r.RequestDigest, &r.State, &r.RequestedAt, &r.ExpiresAt, &r.ApprovedByUserID, &r.ApprovedAt, &r.ConsumedAt)
}
