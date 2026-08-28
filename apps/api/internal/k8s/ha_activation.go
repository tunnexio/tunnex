package k8s

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

type HASettings struct {
	Enabled              bool
	Revision             int64
	ActualState          string
	ReasonCode           string
	UpdatedAt            *time.Time
	DeploymentReady      bool
	SchedulerState       string
	SchedulerReasonCodes []string
}

type HAOperatorStatus struct {
	DeploymentReady      bool
	SchedulerState       string
	SchedulerReasonCodes []string
}

type HAOperatorStatusSource interface {
	HandoffHAOperatorStatus(context.Context, uuid.UUID) (HAOperatorStatus, error)
}

func validHAOperatorStatus(status HAOperatorStatus) bool {
	switch status.SchedulerState {
	case "disabled", "blocked", "follower", "leader_idle", "leader_operating", "degraded":
		return true
	default:
		return false
	}
}

func (s *Service) withHAOperatorStatus(ctx context.Context, orgID uuid.UUID, out HASettings) HASettings {
	status := s.loadHAOperatorStatus(ctx, orgID)
	out.DeploymentReady = status.DeploymentReady
	out.SchedulerState = status.SchedulerState
	out.SchedulerReasonCodes = status.SchedulerReasonCodes
	return out
}

type ConnectorPoolHAStatus struct {
	PoolID              uuid.UUID
	ClusterID           uuid.UUID
	ActiveNodeID        uuid.UUID
	RequestedMode       string
	ActualMode          string
	PromotionGeneration int64
	MembershipEpoch     *int64
	TransitionRevision  int64
	ReasonCode          string
	RequestedAt         *time.Time
	AchievedAt          *time.Time
}

func (s *Service) GetHASettings(ctx context.Context, orgID uuid.UUID) (HASettings, error) {
	var out HASettings
	var updated time.Time
	err := s.pool.QueryRow(ctx, `SELECT enabled,revision,updated_at FROM k8s_ha_settings WHERE org_id=$1`, orgID).Scan(&out.Enabled, &out.Revision, &updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.withHAOperatorStatus(ctx, orgID, HASettings{ActualState: "disabled", ReasonCode: "opt_in_disabled"}), nil
	}
	if err != nil {
		return out, err
	}
	out.UpdatedAt = &updated
	if out.Enabled {
		out.ActualState, out.ReasonCode = "enabled", "enabled"
		return s.withHAOperatorStatus(ctx, orgID, out), nil
	}
	var pending, blocked int
	if err := s.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE actual_mode='drain_pending'),
		count(*) FILTER (WHERE actual_mode='blocked')
		FROM k8s_connector_pool_ha_transitions WHERE org_id=$1`, orgID).Scan(&pending, &blocked); err != nil {
		return out, err
	}
	switch {
	case blocked > 0:
		out.ActualState, out.ReasonCode = "blocked", "pool_drain_blocked"
	case pending > 0:
		out.ActualState, out.ReasonCode = "drain_pending", "pool_drain_pending"
	default:
		out.ActualState, out.ReasonCode = "disabled", "opt_in_disabled"
	}
	return s.withHAOperatorStatus(ctx, orgID, out), nil
}

func (s *Service) SetHASettings(ctx context.Context, orgID, actorUserID uuid.UUID, cause string, enabled bool, expectedRevision int64) (HASettings, error) {
	if actorUserID == uuid.Nil {
		return HASettings{}, apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if expectedRevision < 0 {
		return HASettings{}, apierr.BadRequest("invalid_expected_revision", "expected_revision cannot be negative")
	}
	if cause == "" {
		cause = "operator request"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return HASettings{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var organizationExists int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM organizations WHERE id=$1 FOR UPDATE`, orgID).Scan(&organizationExists); errors.Is(err, pgx.ErrNoRows) {
		return HASettings{}, apierr.NotFound("organization_not_found", "no such organization")
	} else if err != nil {
		return HASettings{}, err
	}
	changed := false
	var currentEnabled bool
	var currentRevision int64
	err = tx.QueryRow(ctx, `SELECT enabled,revision FROM k8s_ha_settings WHERE org_id=$1 FOR UPDATE`, orgID).Scan(&currentEnabled, &currentRevision)
	oldEnabled, oldRevision := currentEnabled, currentRevision
	if errors.Is(err, pgx.ErrNoRows) {
		if expectedRevision != 0 {
			return HASettings{}, apierr.Conflict("k8s_ha_settings_revision_conflict", "the HA setting changed; reload and retry")
		}
		// Missing is the durable OFF default. Writing OFF to that state must not
		// manufacture a settings row, revision, or audit event.
		if !enabled {
			if err := tx.Commit(ctx); err != nil {
				return HASettings{}, err
			}
			return s.GetHASettings(ctx, orgID)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_ha_settings(org_id,enabled,revision,actor_user_id,cause) VALUES($1,$2,1,$3,$4)`, orgID, enabled, actorUserID, cause); err != nil {
			return HASettings{}, err
		}
		currentEnabled, currentRevision = enabled, 1
		changed = true
	} else if err != nil {
		return HASettings{}, err
	} else if currentEnabled == enabled && (expectedRevision == currentRevision || expectedRevision+1 == currentRevision) {
		// Exact retry of a committed transition is idempotent and does not emit a
		// second audit or revision. A no-op read at current revision is also safe.
	} else {
		if expectedRevision != currentRevision {
			return HASettings{}, apierr.Conflict("k8s_ha_settings_revision_conflict", "the HA setting changed; reload and retry")
		}
		currentRevision++
		if _, err := tx.Exec(ctx, `UPDATE k8s_ha_settings SET enabled=$2,revision=$3,actor_user_id=$4,actor_system=NULL,cause=$5 WHERE org_id=$1`, orgID, enabled, currentRevision, actorUserID, cause); err != nil {
			return HASettings{}, err
		}
		changed = true
		if !enabled {
			type poolOptOutAudit struct {
				poolID            uuid.UUID
				requested, actual string
				revision          int64
			}
			rows, err := tx.Query(ctx, `SELECT pool_id,requested_mode,actual_mode,transition_revision
				FROM k8s_connector_pool_ha_transitions
				WHERE org_id=$1 AND (requested_mode <> 'legacy' OR actual_mode <> 'legacy')
				ORDER BY pool_id FOR UPDATE`, orgID)
			if err != nil {
				return HASettings{}, err
			}
			var optOuts []poolOptOutAudit
			for rows.Next() {
				var item poolOptOutAudit
				if err := rows.Scan(&item.poolID, &item.requested, &item.actual, &item.revision); err != nil {
					rows.Close()
					return HASettings{}, err
				}
				optOuts = append(optOuts, item)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return HASettings{}, err
			}
			rows.Close()
			if _, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions
				SET requested_mode='legacy',actual_mode=CASE WHEN actual_mode='legacy' THEN 'legacy' ELSE 'drain_pending' END,
				    transition_revision=transition_revision+1,reason_code=CASE WHEN actual_mode='legacy' THEN 'legacy' ELSE 'organization_opt_out' END,
				    actor_user_id=$2,actor_system=NULL,cause=$3,requested_at=now(),achieved_at=CASE WHEN actual_mode='legacy' THEN now() ELSE NULL END
				WHERE org_id=$1 AND (requested_mode <> 'legacy' OR actual_mode <> 'legacy')`, orgID, actorUserID, cause); err != nil {
				return HASettings{}, err
			}
			for _, item := range optOuts {
				newActual := "drain_pending"
				if item.actual == "legacy" {
					newActual = "legacy"
				}
				if err := s.audit(ctx, sqlc.New(tx), orgID, actorUserID, "", cause, "k8s_connector_pool", item.poolID.String(), "k8s.connector_pool_ha_mode_requested", map[string]any{
					"old_requested_mode": item.requested, "new_requested_mode": "legacy",
					"old_actual_mode": item.actual, "new_actual_mode": newActual,
					"old_transition_revision": item.revision, "new_transition_revision": item.revision + 1,
				}); err != nil {
					return HASettings{}, err
				}
			}
		}
	}
	if changed {
		if err := s.audit(ctx, sqlc.New(tx), orgID, actorUserID, "", cause, "organization", orgID.String(), "k8s.ha_setting_changed", map[string]any{
			"old_enabled": oldEnabled, "new_enabled": currentEnabled,
			"old_revision": oldRevision, "new_revision": currentRevision,
		}); err != nil {
			return HASettings{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return HASettings{}, err
	}
	return s.GetHASettings(ctx, orgID)
}

func (s *Service) ListConnectorPoolHAStatus(ctx context.Context, orgID uuid.UUID) ([]ConnectorPoolHAStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.id,p.cluster_id,p.active_node_id,p.generation,
		COALESCE(t.requested_mode,'legacy'),COALESCE(t.actual_mode,'legacy'),
		h.membership_epoch,COALESCE(t.transition_revision,0),COALESCE(t.reason_code,'legacy'),t.requested_at,t.achieved_at
		FROM k8s_connector_pools p
		JOIN k8s_clusters c ON c.id=p.cluster_id AND c.org_id=p.org_id AND c.site_id=p.site_id AND c.connector_pool_id=p.id
		LEFT JOIN k8s_connector_pool_health_states h ON h.pool_id=p.id AND h.org_id=p.org_id
		LEFT JOIN k8s_connector_pool_ha_transitions t ON t.pool_id=p.id AND t.org_id=p.org_id
		WHERE p.org_id=$1 ORDER BY p.id`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ConnectorPoolHAStatus, 0)
	for rows.Next() {
		var item ConnectorPoolHAStatus
		if err := rows.Scan(&item.PoolID, &item.ClusterID, &item.ActiveNodeID, &item.PromotionGeneration,
			&item.RequestedMode, &item.ActualMode, &item.MembershipEpoch, &item.TransitionRevision,
			&item.ReasonCode, &item.RequestedAt, &item.AchievedAt); err != nil {
			return nil, err
		}
		if item.TransitionRevision == 0 {
			item.ReasonCode = "legacy"
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) SetConnectorPoolHAMode(ctx context.Context, orgID, poolID, actorUserID uuid.UUID, cause, requestedMode string, expectedRevision int64) (ConnectorPoolHAStatus, error) {
	if actorUserID == uuid.Nil {
		return ConnectorPoolHAStatus{}, apierr.Forbidden("human_actor_required", "a verified human organization member is required")
	}
	if requestedMode != "legacy" && requestedMode != "fenced_ha" {
		return ConnectorPoolHAStatus{}, apierr.BadRequest("invalid_k8s_ha_mode", "requested_mode must be legacy or fenced_ha")
	}
	if cause == "" {
		cause = "operator request"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ConnectorPoolHAStatus{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var siteID, clusterID, activeNodeID uuid.UUID
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT site_id,cluster_id,active_node_id,generation FROM k8s_connector_pools WHERE id=$1 AND org_id=$2 FOR UPDATE`, poolID, orgID).Scan(&siteID, &clusterID, &activeNodeID, &generation); errors.Is(err, pgx.ErrNoRows) {
		return ConnectorPoolHAStatus{}, apierr.NotFound("connector_pool_not_found", "no such connector pool in this organization")
	} else if err != nil {
		return ConnectorPoolHAStatus{}, err
	}
	var enabled bool
	if err := tx.QueryRow(ctx, `SELECT enabled FROM k8s_ha_settings WHERE org_id=$1 FOR SHARE`, orgID).Scan(&enabled); errors.Is(err, pgx.ErrNoRows) {
		enabled = false
	} else if err != nil {
		return ConnectorPoolHAStatus{}, err
	}
	if requestedMode == "fenced_ha" && !enabled {
		return ConnectorPoolHAStatus{}, apierr.Conflict("k8s_ha_opt_in_required", "enable Kubernetes connector HA for the organization first")
	}
	var epoch *int64
	if err := tx.QueryRow(ctx, `SELECT membership_epoch FROM k8s_connector_pool_health_states WHERE pool_id=$1 FOR SHARE`, poolID).Scan(&epoch); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ConnectorPoolHAStatus{}, err
	}
	var currentRequested, currentActual string
	var currentRevision int64
	changed := false
	err = tx.QueryRow(ctx, `SELECT requested_mode,actual_mode,transition_revision FROM k8s_connector_pool_ha_transitions WHERE pool_id=$1 FOR UPDATE`, poolID).Scan(&currentRequested, &currentActual, &currentRevision)
	oldRequested, oldActual, oldRevision := currentRequested, currentActual, currentRevision
	newActual, newRevision := currentActual, currentRevision
	if errors.Is(err, pgx.ErrNoRows) {
		oldRequested, oldActual, oldRevision = "legacy", "legacy", 0
		if expectedRevision != 0 {
			return ConnectorPoolHAStatus{}, apierr.Conflict("k8s_ha_transition_revision_conflict", "the pool HA transition changed; reload and retry")
		}
		if requestedMode == "legacy" {
			if err := tx.Commit(ctx); err != nil {
				return ConnectorPoolHAStatus{}, err
			}
			return s.GetConnectorPoolHAStatus(ctx, orgID, poolID)
		}
		actual, reason := "legacy", "legacy"
		var achieved any = time.Now().UTC()
		if requestedMode == "fenced_ha" {
			actual, reason, achieved = "bootstrap_pending", "base_authority_pending", nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO k8s_connector_pool_ha_transitions
			(pool_id,org_id,site_id,cluster_id,requested_mode,actual_mode,active_node_id,promotion_generation,membership_epoch,transition_revision,reason_code,actor_user_id,cause,achieved_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$13)`, poolID, orgID, siteID, clusterID, requestedMode, actual, activeNodeID, generation, epoch, reason, actorUserID, cause, achieved); err != nil {
			return ConnectorPoolHAStatus{}, err
		}
		newActual, newRevision = actual, 1
		changed = true
	} else if err != nil {
		return ConnectorPoolHAStatus{}, err
	} else if currentRequested == requestedMode && (expectedRevision == currentRevision || expectedRevision+1 == currentRevision) {
		// Exact committed retry/no-op.
	} else {
		if expectedRevision != currentRevision {
			return ConnectorPoolHAStatus{}, apierr.Conflict("k8s_ha_transition_revision_conflict", "the pool HA transition changed; reload and retry")
		}
		actual, reason := "drain_pending", "legacy_drain_requested"
		if requestedMode == "fenced_ha" {
			actual, reason = "bootstrap_pending", "base_authority_pending"
		}
		if _, err := tx.Exec(ctx, `UPDATE k8s_connector_pool_ha_transitions SET
			requested_mode=$2,actual_mode=$3,active_node_id=$4,promotion_generation=$5,membership_epoch=$6,
			transition_revision=transition_revision+1,reason_code=$7,actor_user_id=$8,actor_system=NULL,cause=$9,
			requested_at=now(),achieved_at=NULL,achieved_authority_revision=NULL WHERE pool_id=$1`,
			poolID, requestedMode, actual, activeNodeID, generation, epoch, reason, actorUserID, cause); err != nil {
			return ConnectorPoolHAStatus{}, err
		}
		newActual, newRevision = actual, currentRevision+1
		changed = true
	}
	if changed {
		if err := s.audit(ctx, sqlc.New(tx), orgID, actorUserID, "", cause, "k8s_connector_pool", poolID.String(), "k8s.connector_pool_ha_mode_requested", map[string]any{
			"old_requested_mode": oldRequested, "new_requested_mode": requestedMode,
			"old_actual_mode": oldActual, "new_actual_mode": newActual,
			"old_transition_revision": oldRevision, "new_transition_revision": newRevision,
		}); err != nil {
			return ConnectorPoolHAStatus{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ConnectorPoolHAStatus{}, err
	}
	return s.GetConnectorPoolHAStatus(ctx, orgID, poolID)
}

func (s *Service) GetConnectorPoolHAStatus(ctx context.Context, orgID, poolID uuid.UUID) (ConnectorPoolHAStatus, error) {
	list, err := s.ListConnectorPoolHAStatus(ctx, orgID)
	if err != nil {
		return ConnectorPoolHAStatus{}, err
	}
	for _, item := range list {
		if item.PoolID == poolID {
			return item, nil
		}
	}
	return ConnectorPoolHAStatus{}, apierr.NotFound("connector_pool_not_found", "no such connector pool in this organization")
}
