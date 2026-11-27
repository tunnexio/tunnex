// Package mcptoolapproval owns one-use F16 step-up approvals.
package mcptoolapproval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const lifetime = 5 * time.Minute

// MaxStoredArguments is the most canonical JSON kept with a request so an approver can read it. A larger
// call is still bound by its digest; its arguments are not stored and the request says so.
const MaxStoredArguments = 4 << 10

// SystemActor attributes the rows a call itself causes (requested, expired, consumed).
const SystemActor = "mcp-gateway"

// Outcomes of asking whether a step-up call may run.
const (
	OutcomeAllowed = "allowed"
	OutcomePending = "pending"
	OutcomeDenied  = "denied"
)

var (
	ErrInvalid  = errors.New("invalid MCP tool approval")
	ErrNotFound = errors.New("MCP tool approval not found")
	ErrConflict = errors.New("MCP tool approval conflicts with current state")
)

type Request struct {
	ID                 uuid.UUID
	OrgID              uuid.UUID
	DeviceID           uuid.UUID
	PolicyVersion      int64
	Endpoint           string
	ServerName         string
	ToolName           string
	InputSchemaHash    string
	RequestDigest      string
	State              string
	RequestedAt        time.Time
	ExpiresAt          time.Time
	ApprovedByUserID   uuid.UUID
	ApprovedAt         time.Time
	ConsumedAt         time.Time
	DeniedByUserID     uuid.UUID
	DeniedAt           time.Time
	Arguments          json.RawMessage
	ArgumentsTruncated bool
	ToolDefinitionHash string
}

type Identity struct {
	PolicyVersion                                                  int64
	Endpoint, ServerName, ToolName, InputSchemaHash, RequestDigest string
	// ToolDefinitionHash and Arguments describe the call to the approver. They are not part of the match:
	// the policy version already fixes the definition and the digest already fixes the arguments.
	ToolDefinitionHash string
	Arguments          json.RawMessage
}

type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool, now: time.Now} }

// CanonicalArguments returns the call's arguments as canonical JSON: an object with sorted keys, no
// insignificant whitespace, and number literals kept exactly. Absent or null arguments are the empty
// object. Anything that is not a JSON object is refused.
func CanonicalArguments(arguments json.RawMessage) ([]byte, error) {
	trimmed := bytes.TrimSpace(arguments)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return []byte(`{}`), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value map[string]interface{}
	if err := decoder.Decode(&value); err != nil || value == nil || decoder.More() {
		return nil, ErrInvalid
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, ErrInvalid
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// CanonicalDigest binds an approval to one exact call: the method, the tool and the canonical arguments.
// Two calls that differ only in key order or whitespace share a digest, so a repeat of a pending call
// finds the existing request instead of adding a row.
func CanonicalDigest(method, tool string, arguments json.RawMessage) (digest string, canonical []byte, err error) {
	canonical, err = CanonicalArguments(arguments)
	if err != nil {
		return "", nil, err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(method))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(tool))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), canonical, nil
}

const columns = `id,org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,state,requested_at,expires_at,COALESCE(approved_by_user_id,'00000000-0000-0000-0000-000000000000'),COALESCE(approved_at,'epoch'),COALESCE(consumed_at,'epoch'),COALESCE(denied_by_user_id,'00000000-0000-0000-0000-000000000000'),COALESCE(denied_at,'epoch'),arguments,arguments_truncated,COALESCE(tool_definition_hash,'')`

// Permit returns true exactly once after an authorized human has approved the
// exact runtime request. Otherwise it records/reuses a pending request.
func (s *Service) Permit(ctx context.Context, orgID, deviceID uuid.UUID, in Identity) (Request, bool, error) {
	r, outcome, err := s.Decide(ctx, orgID, deviceID, in)
	return r, outcome == OutcomeAllowed, err
}

// Decide answers one step-up call.
//
//   - approved and unexpired: the approval is consumed and the call may run, once;
//   - pending: the existing request is returned, never a second row;
//   - denied by an approver and not yet past its lifetime: the denial stands and no new request is opened;
//   - otherwise a new pending request is recorded.
//
// Every state change writes its audit row in the same transaction.
func (s *Service) Decide(ctx context.Context, orgID, deviceID uuid.UUID, in Identity) (Request, string, error) {
	if s == nil || s.pool == nil || !valid(orgID, deviceID, in) {
		return Request{}, "", ErrInvalid
	}
	var arguments *string
	truncated := false
	if len(in.Arguments) > 0 {
		canonical, err := CanonicalArguments(in.Arguments)
		if err != nil {
			return Request{}, "", ErrInvalid
		}
		if len(canonical) > MaxStoredArguments {
			truncated = true
		} else {
			text := string(canonical)
			arguments = &text
		}
	}
	var definition *string
	if in.ToolDefinitionHash != "" {
		if len(in.ToolDefinitionHash) != 64 {
			return Request{}, "", ErrInvalid
		}
		definition = &in.ToolDefinitionHash
	}
	// A concurrent identical call can win the insert; the second attempt then finds its row.
	for attempt := 0; ; attempt++ {
		r, outcome, err := s.decide(ctx, orgID, deviceID, in, arguments, truncated, definition)
		var pgErr *pgconn.PgError
		if attempt == 0 && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return r, outcome, err
	}
}

func (s *Service) decide(ctx context.Context, orgID, deviceID uuid.UUID, in Identity, arguments *string, truncated bool, definition *string) (Request, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := s.now().UTC()
	match := []any{orgID, deviceID, in.PolicyVersion, in.Endpoint, in.ServerName, in.ToolName, in.InputSchemaHash, in.RequestDigest}
	const where = ` FROM agent_mcp_tool_approval_requests WHERE org_id=$1 AND device_id=$2 AND policy_version=$3 AND endpoint=$4 AND server_name=$5 AND tool_name=$6 AND input_schema_hash=$7 AND request_digest=$8`
	var r Request
	err = scan(tx.QueryRow(ctx, `SELECT `+columns+where+` AND state IN ('pending','approved') FOR UPDATE`, match...), &r)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Request{}, "", err
	}
	live := err == nil
	if live && !r.ExpiresAt.After(now) {
		if _, err = tx.Exec(ctx, `UPDATE agent_mcp_tool_approval_requests SET state='expired' WHERE id=$1 AND state IN ('pending','approved')`, r.ID); err != nil {
			return Request{}, "", err
		}
		if err := audit(ctx, tx, r, "agent.mcp_tool_approval.expired", uuid.Nil); err != nil {
			return Request{}, "", err
		}
		live = false
	}
	if live && r.State == "approved" {
		if _, err = tx.Exec(ctx, `UPDATE agent_mcp_tool_approval_requests SET state='consumed', consumed_at=$2 WHERE id=$1 AND state='approved'`, r.ID, now); err != nil {
			return Request{}, "", err
		}
		r.State, r.ConsumedAt = "consumed", now
		if err := audit(ctx, tx, r, "agent.mcp_tool_approval.consumed", uuid.Nil); err != nil {
			return Request{}, "", err
		}
		return r, OutcomeAllowed, tx.Commit(ctx)
	}
	if live {
		return r, OutcomePending, tx.Commit(ctx)
	}
	// An approver's denial stands for the rest of the request's lifetime: the same call does not reopen it.
	err = scan(tx.QueryRow(ctx, `SELECT `+columns+where+` AND state='denied' AND expires_at>$9 ORDER BY requested_at DESC LIMIT 1`, append(match, now)...), &r)
	if err == nil {
		return r, OutcomeDenied, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Request{}, "", err
	}
	err = scan(tx.QueryRow(ctx, `INSERT INTO agent_mcp_tool_approval_requests (org_id,device_id,policy_version,endpoint,server_name,tool_name,input_schema_hash,request_digest,expires_at,arguments,arguments_truncated,tool_definition_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12) RETURNING `+columns,
		append(match, now.Add(lifetime), arguments, truncated, definition)...), &r)
	if err != nil {
		return Request{}, "", err
	}
	if err := audit(ctx, tx, r, "agent.mcp_tool_approval.requested", uuid.Nil); err != nil {
		return Request{}, "", err
	}
	return r, OutcomePending, tx.Commit(ctx)
}

func (s *Service) Approve(ctx context.Context, orgID, deviceID, requestID, actorID uuid.UUID) (Request, error) {
	return s.resolve(ctx, orgID, deviceID, requestID, actorID, `state='approved',approved_by_user_id=$4,approved_at=now()`, "agent.mcp_tool_approval.approved")
}

// Deny refuses a pending request. The call it describes stays refused until the request's lifetime ends.
func (s *Service) Deny(ctx context.Context, orgID, deviceID, requestID, actorID uuid.UUID) (Request, error) {
	return s.resolve(ctx, orgID, deviceID, requestID, actorID, `state='denied',denied_by_user_id=$4,denied_at=now()`, "agent.mcp_tool_approval.denied")
}

func (s *Service) resolve(ctx context.Context, orgID, deviceID, requestID, actorID uuid.UUID, set, action string) (Request, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil || requestID == uuid.Nil || actorID == uuid.Nil {
		return Request{}, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Request{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var r Request
	err = scan(tx.QueryRow(ctx, `UPDATE agent_mcp_tool_approval_requests SET `+set+` WHERE id=$1 AND org_id=$2 AND device_id=$3 AND state='pending' AND expires_at>now() RETURNING `+columns, requestID, orgID, deviceID, actorID), &r)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, ErrConflict
	}
	if err != nil {
		return Request{}, err
	}
	if err := audit(ctx, tx, r, action, actorID); err != nil {
		return Request{}, err
	}
	return r, tx.Commit(ctx)
}

func (s *Service) List(ctx context.Context, orgID, deviceID uuid.UUID) ([]Request, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || deviceID == uuid.Nil {
		return nil, ErrInvalid
	}
	// What an approver sees is what a decision would see: a request past its lifetime is expired first.
	if _, err := s.expire(ctx, &orgID, &deviceID, 1000); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+columns+`
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

// ExpireDue moves every request past its lifetime to expired and records each one, so an unanswered
// request leaves a trace even when the agent never retries. It returns how many it expired.
func (s *Service) ExpireDue(ctx context.Context, limit int) (int, error) {
	if s == nil || s.pool == nil || limit < 1 {
		return 0, ErrInvalid
	}
	return s.expire(ctx, nil, nil, limit)
}

func (s *Service) expire(ctx context.Context, orgID, deviceID *uuid.UUID, limit int) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// lint:cross-org the background sweep passes no organization; every row it touches is audited under its own org_id.
	rows, err := tx.Query(ctx, `UPDATE agent_mcp_tool_approval_requests SET state='expired' WHERE id IN (
 SELECT id FROM agent_mcp_tool_approval_requests
 WHERE state IN ('pending','approved') AND expires_at<=$1
   AND ($2::uuid IS NULL OR org_id=$2) AND ($3::uuid IS NULL OR device_id=$3)
 ORDER BY expires_at LIMIT $4 FOR UPDATE SKIP LOCKED) RETURNING `+columns, s.now().UTC(), orgID, deviceID, limit)
	if err != nil {
		return 0, err
	}
	var expired []Request
	for rows.Next() {
		var r Request
		if err := scan(rows, &r); err != nil {
			rows.Close()
			return 0, err
		}
		expired = append(expired, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range expired {
		if err := audit(ctx, tx, r, "agent.mcp_tool_approval.expired", uuid.Nil); err != nil {
			return 0, err
		}
	}
	return len(expired), tx.Commit(ctx)
}

// audit records one approval event. Arguments are never copied into the audit log: the row names the
// request and its digest, and the request itself holds the arguments for as long as it exists.
func audit(ctx context.Context, tx pgx.Tx, r Request, action string, actorID uuid.UUID) error {
	metadata, _ := json.Marshal(map[string]any{"request_id": r.ID.String(), "endpoint": r.Endpoint, "server_name": r.ServerName, "tool_name": r.ToolName, "policy_version": r.PolicyVersion, "request_digest": r.RequestDigest})
	if actorID != uuid.Nil {
		_, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_user_id, action, target_type, target_id, metadata) VALUES ($1,$2,$3,'agent',$4,$5)`, r.OrgID, actorID, action, r.DeviceID.String(), metadata)
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_logs (org_id, actor_system, action, target_type, target_id, metadata) VALUES ($1,$2,$3,'agent',$4,$5)`, r.OrgID, SystemActor, action, r.DeviceID.String(), metadata)
	return err
}

func valid(orgID, deviceID uuid.UUID, in Identity) bool {
	return orgID != uuid.Nil && deviceID != uuid.Nil && in.PolicyVersion > 0 && len(in.Endpoint) > 0 && len(in.ServerName) > 0 && len(in.ToolName) > 0 && len(in.InputSchemaHash) > 0 && len(in.RequestDigest) == 64
}

func scan(row pgx.Row, r *Request) error {
	var arguments []byte
	err := row.Scan(&r.ID, &r.OrgID, &r.DeviceID, &r.PolicyVersion, &r.Endpoint, &r.ServerName, &r.ToolName, &r.InputSchemaHash, &r.RequestDigest, &r.State, &r.RequestedAt, &r.ExpiresAt, &r.ApprovedByUserID, &r.ApprovedAt, &r.ConsumedAt, &r.DeniedByUserID, &r.DeniedAt, &arguments, &r.ArgumentsTruncated, &r.ToolDefinitionHash)
	r.Arguments = arguments
	return err
}
