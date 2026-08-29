package k8s

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

const (
	auditConnectorPoolPromotion = "k8s.connector_pool.promoted"
	auditConnectorPoolFailback  = "k8s.connector_pool.failed_back"
	maxConnectorPoolAuditReason = 512
)

var (
	ErrInvalidConnectorPoolDecision = errors.New("invalid connector pool transition decision")
	ErrConnectorPoolNotFound        = errors.New("connector pool not found in org/site scope")
)

// ConnectorPoolPromotionRequest is an already-evaluated pure-model
// transition. It is deliberately not a health input: this slice serializes a
// decision and persists its active-state change, but does not schedule ticks
// or claim that the generation fences any external data plane.
type ConnectorPoolPromotionRequest struct {
	OrgID, SiteID, PoolID uuid.UUID
	ExpectedActiveID      uuid.UUID
	ExpectedGeneration    int64
	Decision              Decision
}

// ConnectorPoolPromotionResult reports whether this request changed the
// persisted pool. Conflict is a safe no-op: a newer pool state or membership
// view won before this decision reached the transaction.
type ConnectorPoolPromotionResult struct {
	Pool     sqlc.K8sConnectorPool
	Applied  bool
	Conflict bool
}

// ApplyConnectorPoolDecision serializes a pure-model promotion/failback. It
// locks the exact org/site/pool and all current members, rechecks the observed
// active state and generation, then uses the active-only CAS as a final stale
// writer backstop. The audit append shares that transaction, so a failed audit
// cannot leave an unaudited promotion behind.
func (s *Service) ApplyConnectorPoolDecision(ctx context.Context, req ConnectorPoolPromotionRequest) (ConnectorPoolPromotionResult, error) {
	fromID, toID, reason, err := validateConnectorPoolPromotionRequest(req)
	if err != nil {
		return ConnectorPoolPromotionResult{}, err
	}

	var result ConnectorPoolPromotionResult
	err = s.withTx(ctx, func(q *sqlc.Queries) error {
		pool, err := q.GetK8sConnectorPoolForPromotion(ctx, sqlc.GetK8sConnectorPoolForPromotionParams{
			OrgID: req.OrgID, SiteID: req.SiteID, PoolID: req.PoolID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConnectorPoolNotFound
		}
		if err != nil {
			return err
		}

		members, err := q.ListK8sConnectorPoolMembersForPromotion(ctx, sqlc.ListK8sConnectorPoolMembersForPromotionParams{
			OrgID: req.OrgID, SiteID: req.SiteID, PoolID: req.PoolID,
		})
		if err != nil {
			return err
		}
		if pool.ActiveNodeID != req.ExpectedActiveID || pool.Generation != req.ExpectedGeneration ||
			!hasConnectorPoolMember(members, fromID) || !hasConnectorPoolMember(members, toID) {
			result.Conflict = true
			result.Pool = pool
			return nil
		}
		if req.Decision.Transition == FailedBack && pool.PreferredNodeID != toID {
			result.Conflict = true
			result.Pool = pool
			return nil
		}
		if req.Decision.Transition == Promoted && pool.PreferredNodeID == toID {
			return fmt.Errorf("%w: generic promotion cannot select the preferred connector", ErrInvalidConnectorPoolDecision)
		}

		next, err := q.SetK8sConnectorPoolState(ctx, sqlc.SetK8sConnectorPoolStateParams{
			ActiveNodeID: toID, OrgID: req.OrgID, SiteID: req.SiteID, PoolID: req.PoolID,
			ExpectedGeneration: req.ExpectedGeneration, ExpectedActiveNodeID: req.ExpectedActiveID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			result.Conflict = true
			result.Pool = pool
			return nil
		}
		if err != nil {
			return err
		}
		action := auditConnectorPoolPromotion
		if req.Decision.Transition == FailedBack {
			action = auditConnectorPoolFailback
		}
		if err := s.audit(ctx, q, req.OrgID, uuid.Nil, "connector-ha", reason,
			"k8s_connector_pool", req.PoolID.String(), action, map[string]any{
				"old_node_id":         fromID.String(),
				"new_node_id":         toID.String(),
				"reason":              reason,
				"transition":          req.Decision.Transition,
				"expected_generation": req.ExpectedGeneration,
				"generation":          next.Generation,
			}); err != nil {
			return err
		}
		result = ConnectorPoolPromotionResult{Pool: next, Applied: true}
		return nil
	})
	return result, err
}

func validateConnectorPoolPromotionRequest(req ConnectorPoolPromotionRequest) (uuid.UUID, uuid.UUID, string, error) {
	if req.OrgID == uuid.Nil || req.SiteID == uuid.Nil || req.PoolID == uuid.Nil || req.ExpectedActiveID == uuid.Nil || req.ExpectedGeneration <= 0 {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("%w: missing pool scope or expected state", ErrInvalidConnectorPoolDecision)
	}
	if req.Decision.Transition != Promoted && req.Decision.Transition != FailedBack {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("%w: %q is not a persisted transition", ErrInvalidConnectorPoolDecision, req.Decision.Transition)
	}
	reason := strings.TrimSpace(req.Decision.Reason)
	if reason == "" || len(reason) > maxConnectorPoolAuditReason {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("%w: audit reason must be non-empty and at most %d bytes", ErrInvalidConnectorPoolDecision, maxConnectorPoolAuditReason)
	}
	fromID, err := uuid.Parse(req.Decision.FromID)
	if err != nil || fromID != req.ExpectedActiveID {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("%w: decision source does not match expected active", ErrInvalidConnectorPoolDecision)
	}
	toID, err := uuid.Parse(req.Decision.ToID)
	if err != nil || toID == fromID || req.Decision.Pool.ActiveID != req.Decision.ToID || req.Decision.Pool.Generation != uint64(req.ExpectedGeneration+1) {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("%w: decision target or generation is inconsistent", ErrInvalidConnectorPoolDecision)
	}
	return fromID, toID, reason, nil
}

func hasConnectorPoolMember(members []sqlc.K8sConnectorPoolMember, id uuid.UUID) bool {
	for _, member := range members {
		if member.NodeID == id {
			return true
		}
	}
	return false
}
