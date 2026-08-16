package agentaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/pgerr"
)

const (
	MinDuration     = 5 * time.Minute
	MaxDuration     = 24 * time.Hour
	DefaultDuration = time.Hour
	sweepInterval   = time.Minute
)

var (
	ErrInvalid  = errors.New("invalid agent access request")
	ErrNotFound = errors.New("agent access request not found")
	ErrConflict = errors.New("agent access request conflicts with current state")
	ErrDisabled = errors.New("agent JIT access is disabled")
)

type Pusher interface {
	PushOrgNodes(context.Context, uuid.UUID)
}

type Service struct {
	pool   *pgxpool.Pool
	pusher Pusher
	now    func() time.Time
}

func New(pool *pgxpool.Pool, pusher Pusher) *Service {
	return &Service{pool: pool, pusher: pusher, now: time.Now}
}

type Destination struct {
	Kind string
	ID   uuid.UUID
}

type CreateInput struct {
	DeviceID       uuid.UUID
	Destination    Destination
	Reason         string
	Duration       time.Duration
	IdempotencyKey string
}

type DecisionInput struct {
	IdempotencyKey string
	Reason         string
}

type Setting struct {
	Enabled  bool
	Pending  int64
	Approved int64
}

func (s *Service) Setting(ctx context.Context, orgID uuid.UUID) (Setting, error) {
	var out Setting
	err := s.pool.QueryRow(ctx, `SELECT agent_jit_access_enabled,
		(SELECT count(*) FROM agent_access_requests WHERE org_id=$1 AND state='pending'),
		(SELECT count(*) FROM agent_access_requests WHERE org_id=$1 AND state='approved')
		FROM organizations WHERE id=$1 AND deleted_at IS NULL`, orgID).Scan(&out.Enabled, &out.Pending, &out.Approved)
	if err != nil {
		return Setting{}, classify(err)
	}
	return out, nil
}

func (s *Service) SetEnabled(ctx context.Context, orgID, actor uuid.UUID, enabled bool) (bool, error) {
	if s == nil || s.pool == nil || orgID == uuid.Nil || actor == uuid.Nil {
		return false, ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	if !enabled {
		n, err := q.CountLiveAgentAccessRequests(ctx, orgID)
		if err != nil {
			return false, err
		}
		if n != 0 {
			return false, ErrConflict
		}
	}
	org, err := q.SetOrganizationAgentJITAccessEnabled(ctx, sqlc.SetOrganizationAgentJITAccessEnabledParams{ID: orgID, AgentJitAccessEnabled: enabled})
	if err != nil {
		return false, classify(err)
	}
	if err := writeHumanAudit(ctx, q, orgID, actor, "org.agent_jit_access_enabled", "organization", orgID, map[string]any{"enabled": enabled}); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return org.AgentJitAccessEnabled, nil
}

func (s *Service) Create(ctx context.Context, orgID, actor uuid.UUID, in CreateInput) (sqlc.AgentAccessRequest, bool, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	if err := validateCreate(orgID, actor, in); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	hash := parameterHash(struct {
		DeviceID        uuid.UUID
		Kind            string
		DestinationID   uuid.UUID
		Reason          string
		DurationSeconds int64
	}{in.DeviceID, in.Destination.Kind, in.Destination.ID, in.Reason, int64(in.Duration / time.Second)})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	if prior, replay, err := replayOperation(ctx, q, orgID, "create", in.IdempotencyKey, hash); err != nil || replay {
		return prior, replay, err
	}
	if err := requireEnabled(ctx, tx, orgID); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := requireAgent(ctx, tx, orgID, in.DeviceID, false); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := requireDestination(ctx, tx, orgID, in.Destination); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	dst := destinationParams(in.Destination)
	row, err := q.CreateAgentAccessRequest(ctx, sqlc.CreateAgentAccessRequestParams{
		OrgID: orgID, DeviceID: in.DeviceID, DstKind: in.Destination.Kind,
		DstResourceID: dst.resource, DstGroupID: dst.group, DstSiteID: dst.site,
		DstK8sServiceID: dst.k8s, Reason: in.Reason,
		RequestedDurationSeconds: int32(in.Duration / time.Second), RequestedByUserID: actor,
	})
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if err := recordOperation(ctx, q, row, "create", in.IdempotencyKey, hash); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := recordHumanTransition(ctx, q, row, actor, "agent_access.requested", nil); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	return row, false, nil
}

func (s *Service) Approve(ctx context.Context, orgID, requestID, actor uuid.UUID, key string) (sqlc.AgentAccessRequest, bool, error) {
	return s.approve(ctx, orgID, requestID, actor, key)
}

func (s *Service) approve(ctx context.Context, orgID, requestID, actor uuid.UUID, key string) (sqlc.AgentAccessRequest, bool, error) {
	if orgID == uuid.Nil || requestID == uuid.Nil || actor == uuid.Nil || !validKey(key) {
		return sqlc.AgentAccessRequest{}, false, ErrInvalid
	}
	hash := parameterHash(struct{ RequestID uuid.UUID }{requestID})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	if prior, replay, err := replayOperation(ctx, q, orgID, "approve", key, hash); err != nil || replay {
		return prior, replay, err
	}
	if err := requireEnabled(ctx, tx, orgID); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	row, err := q.GetAgentAccessRequestForUpdate(ctx, sqlc.GetAgentAccessRequestForUpdateParams{ID: requestID, OrgID: orgID})
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if row.State != "pending" {
		return sqlc.AgentAccessRequest{}, false, ErrConflict
	}
	if err := requireAgent(ctx, tx, orgID, row.DeviceID, true); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	destination := destinationFromRow(row)
	if err := requireDestination(ctx, tx, orgID, destination); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	now := s.now().UTC()
	expires := now.Add(time.Duration(row.RequestedDurationSeconds) * time.Second)
	dst := destinationParams(destination)
	rule, err := q.CreatePolicyRule(ctx, sqlc.CreatePolicyRuleParams{
		OrgID: orgID, SrcKind: "agent", SrcDeviceID: pgUUID(row.DeviceID),
		DstKind: destination.Kind, DstResourceID: dst.resource, DstGroupID: dst.group,
		DstSiteID: dst.site, DstK8sServiceID: dst.k8s,
		ExpiresAt: pgtype.Timestamptz{Time: expires, Valid: true},
	})
	if err != nil {
		if pgerr.IsUnique(err) {
			return sqlc.AgentAccessRequest{}, false, ErrConflict
		}
		return sqlc.AgentAccessRequest{}, false, err
	}
	row, err = q.ApproveAgentAccessRequest(ctx, sqlc.ApproveAgentAccessRequestParams{
		ID: requestID, OrgID: orgID, ApprovedByUserID: pgUUID(actor),
		ApprovedAt: pgTime(now), ApprovedExpiresAt: pgTime(expires), PolicyRuleID: pgUUID(rule.ID),
	})
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if err := recordOperation(ctx, q, row, "approve", key, hash); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	meta := map[string]any{"policy_rule_id": rule.ID.String(), "expires_at": expires.Format(time.RFC3339)}
	if err := recordHumanTransition(ctx, q, row, actor, "agent_access.approved", meta); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := writeHumanAudit(ctx, q, orgID, actor, "policy.rule_created", "policy_rule", rule.ID, map[string]any{"managed_by": "agent_access_request", "request_id": row.ID.String(), "expires_at": expires.Format(time.RFC3339)}); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	s.push(ctx, orgID)
	return row, false, nil
}

func (s *Service) Reject(ctx context.Context, orgID, requestID, actor uuid.UUID, in DecisionInput) (sqlc.AgentAccessRequest, bool, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 500 {
		return sqlc.AgentAccessRequest{}, false, ErrInvalid
	}
	return s.terminalPending(ctx, orgID, requestID, actor, "reject", in.IdempotencyKey, in.Reason)
}

func (s *Service) Cancel(ctx context.Context, orgID, requestID, actor uuid.UUID, key string) (sqlc.AgentAccessRequest, bool, error) {
	return s.terminalPending(ctx, orgID, requestID, actor, "cancel", key, "")
}

func (s *Service) terminalPending(ctx context.Context, orgID, requestID, actor uuid.UUID, operation, key, reason string) (sqlc.AgentAccessRequest, bool, error) {
	if orgID == uuid.Nil || requestID == uuid.Nil || actor == uuid.Nil || !validKey(key) {
		return sqlc.AgentAccessRequest{}, false, ErrInvalid
	}
	hash := parameterHash(struct {
		RequestID uuid.UUID
		Reason    string
	}{requestID, reason})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	if prior, replay, err := replayOperation(ctx, q, orgID, operation, key, hash); err != nil || replay {
		return prior, replay, err
	}
	locked, err := q.GetAgentAccessRequestForUpdate(ctx, sqlc.GetAgentAccessRequestForUpdateParams{ID: requestID, OrgID: orgID})
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if locked.State != "pending" {
		return sqlc.AgentAccessRequest{}, false, ErrConflict
	}
	now := s.now().UTC()
	var row sqlc.AgentAccessRequest
	if operation == "reject" {
		row, err = q.RejectAgentAccessRequest(ctx, sqlc.RejectAgentAccessRequestParams{ID: requestID, OrgID: orgID, RejectedByUserID: pgUUID(actor), RejectedAt: pgTime(now), RejectionReason: &reason})
	} else {
		row, err = q.CancelAgentAccessRequest(ctx, sqlc.CancelAgentAccessRequestParams{ID: requestID, OrgID: orgID, CancelledByUserID: pgUUID(actor), CancelledAt: pgTime(now)})
	}
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if err := recordOperation(ctx, q, row, operation, key, hash); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	action := "agent_access.cancelled"
	meta := map[string]any(nil)
	if operation == "reject" {
		action, meta = "agent_access.rejected", map[string]any{"reason": reason}
	}
	if err := recordHumanTransition(ctx, q, row, actor, action, meta); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	return row, false, nil
}

func (s *Service) Revoke(ctx context.Context, orgID, requestID, actor uuid.UUID, key string) (sqlc.AgentAccessRequest, bool, error) {
	if orgID == uuid.Nil || requestID == uuid.Nil || actor == uuid.Nil || !validKey(key) {
		return sqlc.AgentAccessRequest{}, false, ErrInvalid
	}
	hash := parameterHash(struct{ RequestID uuid.UUID }{requestID})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	if prior, replay, err := replayOperation(ctx, q, orgID, "revoke", key, hash); err != nil || replay {
		return prior, replay, err
	}
	locked, err := q.GetAgentAccessRequestForUpdate(ctx, sqlc.GetAgentAccessRequestForUpdateParams{ID: requestID, OrgID: orgID})
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if locked.State != "approved" || !locked.PolicyRuleID.Valid {
		return sqlc.AgentAccessRequest{}, false, ErrConflict
	}
	if n, err := q.DeletePolicyRule(ctx, sqlc.DeletePolicyRuleParams{ID: locked.PolicyRuleID.Bytes, OrgID: orgID}); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	} else if n != 1 {
		return sqlc.AgentAccessRequest{}, false, ErrConflict
	}
	now := s.now().UTC()
	row, err := q.RevokeAgentAccessRequest(ctx, sqlc.RevokeAgentAccessRequestParams{ID: requestID, OrgID: orgID, RevokedByUserID: pgUUID(actor), RevokedAt: pgTime(now)})
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, classify(err)
	}
	if err := recordOperation(ctx, q, row, "revoke", key, hash); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	meta := map[string]any{"policy_rule_id": uuid.UUID(locked.PolicyRuleID.Bytes).String()}
	if err := recordHumanTransition(ctx, q, row, actor, "agent_access.revoked", meta); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := writeHumanAudit(ctx, q, orgID, actor, "policy.rule_deleted", "policy_rule", locked.PolicyRuleID.Bytes, map[string]any{"cause": "agent_access_revoked", "request_id": row.ID.String()}); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	s.push(ctx, orgID)
	return row, false, nil
}

func (s *Service) Get(ctx context.Context, orgID, requestID uuid.UUID) (sqlc.AgentAccessRequest, []sqlc.AgentAccessRequestEvent, error) {
	q := sqlc.New(s.pool)
	row, err := q.GetAgentAccessRequest(ctx, sqlc.GetAgentAccessRequestParams{ID: requestID, OrgID: orgID})
	if err != nil {
		return sqlc.AgentAccessRequest{}, nil, classify(err)
	}
	events, err := q.ListAgentAccessRequestEvents(ctx, sqlc.ListAgentAccessRequestEventsParams{OrgID: orgID, RequestID: requestID})
	return row, events, err
}

func (s *Service) List(ctx context.Context, orgID uuid.UUID, state *string, deviceID *uuid.UUID, before *time.Time, beforeID *uuid.UUID, pageSize int32) ([]sqlc.AgentAccessRequest, error) {
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	device := pgtype.UUID{}
	if deviceID != nil {
		device = pgUUID(*deviceID)
	}
	beforeTime := pgtype.Timestamptz{}
	beforeUUID := pgtype.UUID{}
	if before != nil && beforeID != nil {
		beforeTime = pgTime(*before)
		beforeUUID = pgUUID(*beforeID)
	}
	return sqlc.New(s.pool).ListAgentAccessRequests(ctx, sqlc.ListAgentAccessRequestsParams{
		OrgID: orgID, State: state, DeviceID: device,
		BeforeRequestedAt: beforeTime, BeforeID: beforeUUID, PageSize: pageSize,
	})
}

func (s *Service) ListForActor(ctx context.Context, orgID, actor uuid.UUID, state *string, deviceID *uuid.UUID, before *time.Time, beforeID *uuid.UUID, pageSize int32) ([]sqlc.AgentAccessRequest, error) {
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}
	device := pgtype.UUID{}
	if deviceID != nil {
		device = pgUUID(*deviceID)
	}
	beforeTime := pgtype.Timestamptz{}
	beforeUUID := pgtype.UUID{}
	if before != nil && beforeID != nil {
		beforeTime = pgTime(*before)
		beforeUUID = pgUUID(*beforeID)
	}
	return sqlc.New(s.pool).ListAgentAccessRequestsForActor(ctx, sqlc.ListAgentAccessRequestsForActorParams{
		OrgID: orgID, State: state, DeviceID: device,
		BeforeRequestedAt: beforeTime, BeforeID: beforeUUID, ActorID: actor, PageSize: pageSize,
	})
}

func (s *Service) Describe(ctx context.Context, row sqlc.AgentAccessRequest) (string, string, error) {
	var agentName string
	if err := s.pool.QueryRow(ctx, `SELECT name FROM devices WHERE id=$1 AND org_id=$2 AND kind='agent'`, row.DeviceID, row.OrgID).Scan(&agentName); err != nil {
		return "", "", classify(err)
	}
	dst := destinationFromRow(row)
	table := map[string]string{"resource": "resources", "group": "user_groups", "site": "sites", "k8s_service": "k8s_services"}[dst.Kind]
	var destinationName string
	if err := s.pool.QueryRow(ctx, `SELECT name FROM `+table+` WHERE id=$1 AND org_id=$2`, dst.ID, row.OrgID).Scan(&destinationName); err != nil {
		return "", "", classify(err)
	}
	return agentName, destinationName, nil
}

func (s *Service) SweepExpired(ctx context.Context) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)
	due, err := q.ListDueAgentAccessRequestsForUpdate(ctx)
	if err != nil {
		return 0, err
	}
	orgs := map[uuid.UUID]struct{}{}
	for _, locked := range due {
		if !locked.PolicyRuleID.Valid {
			return 0, fmt.Errorf("approved request %s has no policy rule", locked.ID)
		}
		if n, err := q.DeletePolicyRule(ctx, sqlc.DeletePolicyRuleParams{ID: locked.PolicyRuleID.Bytes, OrgID: locked.OrgID}); err != nil {
			return 0, fmt.Errorf("delete JIT rule for %s: %w", locked.ID, err)
		} else if n != 1 {
			return 0, fmt.Errorf("delete JIT rule for %s: expected one row, got %d", locked.ID, n)
		}
		row, err := q.ExpireAgentAccessRequest(ctx, sqlc.ExpireAgentAccessRequestParams{ID: locked.ID, OrgID: locked.OrgID})
		if err != nil {
			return 0, err
		}
		meta := map[string]any{"policy_rule_id": uuid.UUID(locked.PolicyRuleID.Bytes).String(), "cause": "approved_window_elapsed"}
		if err := recordSystemTransition(ctx, q, row, "agent-access-expiry", "agent_access.expired", meta); err != nil {
			return 0, err
		}
		if err := writeSystemAudit(ctx, q, locked.OrgID, "agent-access-expiry", "policy.rule_deleted", "policy_rule", locked.PolicyRuleID.Bytes, map[string]any{"cause": "agent_access_expired", "request_id": locked.ID.String()}); err != nil {
			return 0, err
		}
		orgs[locked.OrgID] = struct{}{}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	for orgID := range orgs {
		s.push(ctx, orgID)
	}
	return len(due), nil
}

// CloseForDeviceTx composes F10 with the canonical agent lifecycle. The caller
// owns the device transaction and row lock; every pending request is cancelled
// and every approved rule is deleted/revoked before suspend, revoke, or removal
// can commit. The caller performs the single post-commit org push.
func CloseForDeviceTx(ctx context.Context, q *sqlc.Queries, orgID, deviceID, actor uuid.UUID, cause string) (int, error) {
	rows, err := q.ListLiveAgentAccessRequestsByDeviceForUpdate(ctx, sqlc.ListLiveAgentAccessRequestsByDeviceForUpdateParams{
		OrgID: orgID, DeviceID: deviceID,
	})
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	for _, locked := range rows {
		meta := map[string]any{"cause": cause, "device_id": deviceID.String()}
		switch locked.State {
		case "pending":
			row, err := q.CancelAgentAccessRequest(ctx, sqlc.CancelAgentAccessRequestParams{
				ID: locked.ID, OrgID: orgID, CancelledByUserID: pgUUID(actor), CancelledAt: pgTime(now),
			})
			if err != nil {
				return 0, classify(err)
			}
			if err := recordHumanTransition(ctx, q, row, actor, "agent_access.cancelled", meta); err != nil {
				return 0, err
			}
		case "approved":
			if !locked.PolicyRuleID.Valid {
				return 0, fmt.Errorf("approved request %s has no policy rule", locked.ID)
			}
			if n, err := q.DeletePolicyRule(ctx, sqlc.DeletePolicyRuleParams{ID: locked.PolicyRuleID.Bytes, OrgID: orgID}); err != nil {
				return 0, err
			} else if n != 1 {
				return 0, fmt.Errorf("approved request %s policy rule missing", locked.ID)
			}
			row, err := q.RevokeAgentAccessRequest(ctx, sqlc.RevokeAgentAccessRequestParams{
				ID: locked.ID, OrgID: orgID, RevokedByUserID: pgUUID(actor), RevokedAt: pgTime(now),
			})
			if err != nil {
				return 0, classify(err)
			}
			meta["policy_rule_id"] = uuid.UUID(locked.PolicyRuleID.Bytes).String()
			if err := recordHumanTransition(ctx, q, row, actor, "agent_access.revoked", meta); err != nil {
				return 0, err
			}
			if err := writeHumanAudit(ctx, q, orgID, actor, "policy.rule_deleted", "policy_rule", locked.PolicyRuleID.Bytes, map[string]any{
				"cause": cause, "request_id": row.ID.String(),
			}); err != nil {
				return 0, err
			}
		}
	}
	return len(rows), nil
}

func (s *Service) StartExpirySweeper(ctx context.Context, mayTick func() bool) {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if mayTick == nil || mayTick() {
				_, _ = s.SweepExpired(ctx)
			}
		}
	}
}

func validateCreate(orgID, actor uuid.UUID, in CreateInput) error {
	if orgID == uuid.Nil || actor == uuid.Nil || in.DeviceID == uuid.Nil || in.Destination.ID == uuid.Nil || !validDestinationKind(in.Destination.Kind) || !validKey(in.IdempotencyKey) || in.Reason == "" || len(in.Reason) > 500 || in.Duration < MinDuration || in.Duration > MaxDuration || in.Duration%time.Second != 0 {
		return ErrInvalid
	}
	return nil
}

func validKey(v string) bool { return len(v) >= 1 && len(v) <= 128 }

func validDestinationKind(v string) bool {
	switch v {
	case "resource", "group", "site", "k8s_service":
		return true
	default:
		return false
	}
}

func requireEnabled(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) error {
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT agent_jit_access_enabled FROM organizations WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, orgID).Scan(&enabled); err != nil {
		return classify(err)
	}
	if !enabled {
		return ErrDisabled
	}
	return nil
}

func requireAgent(ctx context.Context, tx pgx.Tx, orgID, deviceID uuid.UUID, activeOnly bool) error {
	var status, kind string
	var deleted pgtype.Timestamptz
	if err := tx.QueryRow(ctx, `SELECT status,kind,deleted_at FROM devices WHERE id=$1 AND org_id=$2 FOR SHARE`, deviceID, orgID).Scan(&status, &kind, &deleted); err != nil {
		return classify(err)
	}
	if kind != "agent" || deleted.Valid || (activeOnly && status != "active") || (!activeOnly && status != "active" && status != "suspended") {
		return ErrConflict
	}
	return nil
}

func requireDestination(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, dst Destination) error {
	table := map[string]string{"resource": "resources", "group": "user_groups", "site": "sites", "k8s_service": "k8s_services"}[dst.Kind]
	if table == "" {
		return ErrInvalid
	}
	var one int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM `+table+` WHERE id=$1 AND org_id=$2`, dst.ID, orgID).Scan(&one); err != nil {
		return classify(err)
	}
	return nil
}

type destinationColumns struct{ resource, group, site, k8s pgtype.UUID }

func destinationParams(dst Destination) destinationColumns {
	var out destinationColumns
	switch dst.Kind {
	case "resource":
		out.resource = pgUUID(dst.ID)
	case "group":
		out.group = pgUUID(dst.ID)
	case "site":
		out.site = pgUUID(dst.ID)
	case "k8s_service":
		out.k8s = pgUUID(dst.ID)
	}
	return out
}

func destinationFromRow(row sqlc.AgentAccessRequest) Destination {
	switch row.DstKind {
	case "resource":
		return Destination{Kind: row.DstKind, ID: row.DstResourceID.Bytes}
	case "group":
		return Destination{Kind: row.DstKind, ID: row.DstGroupID.Bytes}
	case "site":
		return Destination{Kind: row.DstKind, ID: row.DstSiteID.Bytes}
	default:
		return Destination{Kind: row.DstKind, ID: row.DstK8sServiceID.Bytes}
	}
}

func parameterHash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func replayOperation(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, operation, key, hash string) (sqlc.AgentAccessRequest, bool, error) {
	op, err := q.GetAgentAccessOperation(ctx, sqlc.GetAgentAccessOperationParams{OrgID: orgID, Operation: operation, IdempotencyKey: key})
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.AgentAccessRequest{}, false, nil
	}
	if err != nil {
		return sqlc.AgentAccessRequest{}, false, err
	}
	if op.ParameterHash != hash {
		return sqlc.AgentAccessRequest{}, false, ErrConflict
	}
	row, err := q.GetAgentAccessRequest(ctx, sqlc.GetAgentAccessRequestParams{ID: op.RequestID, OrgID: orgID})
	return row, err == nil, classify(err)
}

func recordOperation(ctx context.Context, q *sqlc.Queries, row sqlc.AgentAccessRequest, operation, key, hash string) error {
	n, err := q.InsertAgentAccessOperation(ctx, sqlc.InsertAgentAccessOperationParams{OrgID: row.OrgID, RequestID: row.ID, Operation: operation, IdempotencyKey: key, ParameterHash: hash})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func recordHumanTransition(ctx context.Context, q *sqlc.Queries, row sqlc.AgentAccessRequest, actor uuid.UUID, action string, meta map[string]any) error {
	b, err := json.Marshal(metaOrEmpty(meta))
	if err != nil {
		return err
	}
	if _, err := q.InsertAgentAccessRequestEvent(ctx, sqlc.InsertAgentAccessRequestEventParams{OrgID: row.OrgID, RequestID: row.ID, State: row.State, ActorUserID: pgUUID(actor), Metadata: b}); err != nil {
		return err
	}
	return writeHumanAudit(ctx, q, row.OrgID, actor, action, "agent_access_request", row.ID, meta)
}

func recordSystemTransition(ctx context.Context, q *sqlc.Queries, row sqlc.AgentAccessRequest, actorSystem, action string, meta map[string]any) error {
	b, err := json.Marshal(metaOrEmpty(meta))
	if err != nil {
		return err
	}
	if _, err := q.InsertAgentAccessRequestEvent(ctx, sqlc.InsertAgentAccessRequestEventParams{OrgID: row.OrgID, RequestID: row.ID, State: row.State, ActorSystem: &actorSystem, Metadata: b}); err != nil {
		return err
	}
	return writeSystemAudit(ctx, q, row.OrgID, actorSystem, action, "agent_access_request", row.ID, meta)
}

func writeHumanAudit(ctx context.Context, q *sqlc.Queries, orgID, actor uuid.UUID, action, targetType string, targetID uuid.UUID, meta map[string]any) error {
	b, err := json.Marshal(metaOrEmpty(meta))
	if err != nil {
		return err
	}
	tt, ti := targetType, targetID.String()
	_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{OrgID: pgUUID(orgID), ActorUserID: pgUUID(actor), Action: action, TargetType: &tt, TargetID: &ti, Metadata: b})
	return err
}

func writeSystemAudit(ctx context.Context, q *sqlc.Queries, orgID uuid.UUID, actorSystem, action, targetType string, targetID uuid.UUID, meta map[string]any) error {
	b, err := json.Marshal(metaOrEmpty(meta))
	if err != nil {
		return err
	}
	tt, ti := targetType, targetID.String()
	_, err = q.InsertSystemAuditLog(ctx, sqlc.InsertSystemAuditLogParams{OrgID: pgUUID(orgID), ActorSystem: &actorSystem, Action: action, TargetType: &tt, TargetID: &ti, Metadata: b})
	return err
}

func metaOrEmpty(meta map[string]any) map[string]any {
	if meta == nil {
		return map[string]any{}
	}
	return meta
}
func pgUUID(v uuid.UUID) pgtype.UUID        { return pgtype.UUID{Bytes: v, Valid: v != uuid.Nil} }
func pgTime(v time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: v, Valid: true} }

func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Service) push(ctx context.Context, orgID uuid.UUID) {
	if s.pusher != nil {
		s.pusher.PushOrgNodes(ctx, orgID)
	}
}
