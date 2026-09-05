package nodes

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
	"github.com/tunnexio/tunnex/apps/api/internal/leader"
)

type HandoffHAActivationRuntimeConfig struct {
	Enabled   bool
	Cadence   time.Duration
	MaxAckAge time.Duration
}

// HandoffHAActivationRuntime is the bounded deployment-level bootstrap loop.
// It discovers only explicit bootstrap_pending rows and reconciles them on the
// exact shared scheduler-leader connection. OFF construction and Start are
// inert; organization settings cannot start it.
type HandoffHAActivationRuntime struct {
	config     HandoffHAActivationRuntimeConfig
	pool       *pgxpool.Pool
	elector    *leader.Elector
	source     HandoffBootstrapPlanSource
	issuer     HandoffBootstrapEnvelopeIssuer
	reader     HandoffBootstrapLeaderAttestationReader
	transition HandoffOwnershipModeTransition
	migration  *PostgresHandoffSchedulerMigrationGate
	mu         sync.Mutex
	cancel     context.CancelFunc
	done       chan struct{}
}

func NewHandoffHAActivationRuntime(config HandoffHAActivationRuntimeConfig, pool *pgxpool.Pool, elector *leader.Elector, source HandoffBootstrapPlanSource, issuer HandoffBootstrapEnvelopeIssuer, reader HandoffBootstrapLeaderAttestationReader, transition HandoffOwnershipModeTransition) *HandoffHAActivationRuntime {
	return &HandoffHAActivationRuntime{config: config, pool: pool, elector: elector, source: source, issuer: issuer, reader: reader, transition: transition, migration: NewPostgresHandoffSchedulerMigrationGate(pool)}
}

func (r *HandoffHAActivationRuntime) Start(parent context.Context) bool {
	if r == nil || parent == nil || !r.config.Enabled || r.config.Cadence < 100*time.Millisecond || r.config.MaxAckAge <= 0 || r.pool == nil || r.elector == nil ||
		!handoffActivationDependencyPresent(r.source) || !handoffActivationDependencyPresent(r.issuer) || !handoffActivationDependencyPresent(r.reader) || !handoffActivationDependencyPresent(r.transition) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done != nil || parent.Err() != nil {
		return r.done != nil
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	r.cancel, r.done = cancel, done
	go r.run(ctx, done)
	return true
}

func (r *HandoffHAActivationRuntime) run(ctx context.Context, done chan struct{}) {
	defer func() {
		close(done)
		r.mu.Lock()
		if r.done == done {
			r.cancel, r.done = nil, nil
		}
		r.mu.Unlock()
	}()
	ticker := time.NewTicker(r.config.Cadence)
	defer ticker.Stop()
	for {
		r.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *HandoffHAActivationRuntime) reconcile(ctx context.Context) {
	if r.migration == nil || !r.migration.ready(ctx) {
		return
	}
	pid, ok := r.elector.ConfirmLeaderEpoch(ctx, r.pool)
	if !ok {
		return
	}
	_, err := r.elector.WithLeaderSession(ctx, pid, func(conn *pgxpool.Conn) error {
		epoch := k8s.HandoffLeadershipEpoch{BackendPID: pid, LockKey: leader.SchedulerLockKey}
		scopes, err := pendingHandoffHAScopes(ctx, conn)
		if err != nil {
			return err
		}
		for _, scope := range scopes {
			reconciler := NewHandoffBootstrapReconciler(HandoffBootstrapConfig{Enabled: true, MaxAckAge: r.config.MaxAckAge, Scope: scope}, r.source, r.issuer, r.reader, r.transition)
			if _, err := reconciler.ReconcileWithLeadership(ctx, time.Now().UTC(), epoch, conn); err != nil {
				return err
			}
		}
		// Fences survive a serving-lease expiry, but traffic intentionally does
		// not.  Keep every already-achieved fenced pool supplied with a newer
		// same-owner serving/prepared pair.  The source and issuer both re-lock
		// the exact topology on this leader session, so a concurrent membership,
		// generation, Service UID, or active-owner change refuses the renewal.
		renewals, err := fencedHandoffHAScopes(ctx, conn)
		if err != nil {
			return err
		}
		if err := r.reconcileFencedPools(ctx, time.Now().UTC(), epoch, conn, renewals); err != nil {
			slog.Default().Warn("k8s_ha_fenced_pool_reconcile_failed", "error", err)
		}
		if drain, ok := r.transition.(interface {
			ReconcileHandoffOwnershipDrainWithLeadership(context.Context, time.Time, k8s.HandoffLeadershipEpoch, *pgxpool.Conn, k8s.HandoffPoolScope) (bool, error)
		}); ok {
			drains, err := pendingHandoffHADrainScopes(ctx, conn)
			if err != nil {
				return err
			}
			for _, scope := range drains {
				if _, err := drain.ReconcileHandoffOwnershipDrainWithLeadership(ctx, time.Now().UTC(), epoch, conn, scope); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		slog.Default().Warn("k8s_ha_activation_reconcile_failed", "error", err)
	}
}

func (r *HandoffHAActivationRuntime) reconcileFencedPools(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, scopes []k8s.HandoffPoolScope) error {
	if len(scopes) == 0 {
		return nil
	}
	plans := make([]HandoffBootstrapPlan, 0, len(scopes))
	for _, scope := range scopes {
		plan, found, err := r.source.LoadHandoffBootstrapPlanWithLeadership(ctx, now, scope, epoch, conn)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		plans = append(plans, plan)
	}
	if len(plans) == 0 {
		return nil
	}
	maintainer, ok := r.transition.(HandoffOrdinaryBaseAuthorityMaintainer)
	if !ok || !handoffActivationDependencyPresent(maintainer) {
		return ErrHandoffHATransitionRefused
	}
	// Authority is one scope-complete node batch across every armed pool. It
	// must land before any renewed serving/prepared envelopes can expose a
	// changed pool domain to a later failover.
	accepted, err := maintainer.MaintainHandoffOrdinaryBaseAuthorityWithLeadership(ctx, now, epoch, conn, plans)
	if err != nil {
		return err
	}
	if !accepted {
		// Issuance is not acceptance. The node must durably ACK this exact full
		// base before any serving/prepared lease derived from it is renewed. The
		// next scheduler tick replays the authority and observes the receipt.
		return nil
	}
	for _, plan := range plans {
		if err := r.reconcileFencedPlanLease(ctx, epoch, conn, plan); err != nil {
			return err
		}
	}
	return nil
}

func (r *HandoffHAActivationRuntime) reconcileFencedLease(ctx context.Context, now time.Time, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, scope k8s.HandoffPoolScope) error {
	plan, found, err := r.source.LoadHandoffBootstrapPlanWithLeadership(ctx, now, scope, epoch, conn)
	if err != nil || !found {
		return err
	}
	return r.reconcileFencedPlanLease(ctx, epoch, conn, plan)
}

func (r *HandoffHAActivationRuntime) reconcileFencedPlanLease(ctx context.Context, epoch k8s.HandoffLeadershipEpoch, conn *pgxpool.Conn, plan HandoffBootstrapPlan) error {
	// Prepare every standby before extending the serving owner's authority. If
	// topology changes between per-envelope transactions, a partial attempt can
	// leave extra non-serving preparation but cannot refresh serving alone.
	envelopes := make([]PoolVIPOwnershipDeliveryEnvelopeV3, 0, 1+len(plan.StandbyEnvelopes))
	envelopes = append(envelopes, plan.StandbyEnvelopes...)
	envelopes = append(envelopes, plan.CurrentOwnerEnvelope)
	for _, envelope := range envelopes {
		if err := r.issuer.IssueHandoffBootstrapEnvelopeWithLeadership(ctx, epoch, conn, envelope); err != nil {
			return err
		}
	}
	return nil
}

func pendingHandoffHAScopes(ctx context.Context, conn *pgxpool.Conn) ([]k8s.HandoffPoolScope, error) {
	rows, err := conn.Query(ctx, `SELECT t.org_id,t.site_id,t.cluster_id,t.pool_id
		FROM k8s_connector_pool_ha_transitions t
		JOIN k8s_ha_settings s ON s.org_id=t.org_id AND s.enabled=true
		JOIN k8s_connector_pools p ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		WHERE t.requested_mode='fenced_ha' AND t.actual_mode='bootstrap_pending'
		ORDER BY t.org_id,t.site_id,t.pool_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []k8s.HandoffPoolScope
	for rows.Next() {
		var scope k8s.HandoffPoolScope
		if err := rows.Scan(&scope.OrgID, &scope.SiteID, &scope.ClusterID, &scope.PoolID); err != nil {
			return nil, err
		}
		if scope.OrgID == uuid.Nil || scope.SiteID == uuid.Nil || scope.ClusterID == uuid.Nil || scope.PoolID == uuid.Nil {
			continue
		}
		out = append(out, scope)
	}
	return out, rows.Err()
}

func fencedHandoffHAScopes(ctx context.Context, conn *pgxpool.Conn) ([]k8s.HandoffPoolScope, error) {
	rows, err := conn.Query(ctx, `SELECT t.org_id,t.site_id,t.cluster_id,t.pool_id
		FROM k8s_connector_pool_ha_transitions t
		JOIN k8s_ha_settings s ON s.org_id=t.org_id AND s.enabled=true
		JOIN k8s_connector_pools p ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		WHERE t.requested_mode='fenced_ha' AND t.actual_mode='fenced_ha'
		  AND t.active_node_id=p.active_node_id AND t.promotion_generation=p.generation
		  AND NOT EXISTS (
			SELECT 1 FROM k8s_connector_handoff_operations o
			WHERE o.org_id=t.org_id AND o.site_id=t.site_id AND o.cluster_id=t.cluster_id AND o.pool_id=t.pool_id
			  AND o.phase NOT IN ('complete','failed')
		  )
		ORDER BY t.org_id,t.site_id,t.pool_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []k8s.HandoffPoolScope
	for rows.Next() {
		var scope k8s.HandoffPoolScope
		if err := rows.Scan(&scope.OrgID, &scope.SiteID, &scope.ClusterID, &scope.PoolID); err != nil {
			return nil, err
		}
		if validHandoffBootstrapScope(scope) {
			out = append(out, scope)
		}
	}
	return out, rows.Err()
}

func pendingHandoffHADrainScopes(ctx context.Context, conn *pgxpool.Conn) ([]k8s.HandoffPoolScope, error) {
	rows, err := conn.Query(ctx, `SELECT t.org_id,t.site_id,t.cluster_id,t.pool_id
		FROM k8s_connector_pool_ha_transitions t
		JOIN k8s_connector_pools p ON p.id=t.pool_id AND p.org_id=t.org_id AND p.site_id=t.site_id AND p.cluster_id=t.cluster_id
		WHERE t.requested_mode='legacy' AND t.actual_mode='drain_pending'
		ORDER BY t.org_id,t.site_id,t.pool_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []k8s.HandoffPoolScope
	for rows.Next() {
		var scope k8s.HandoffPoolScope
		if err := rows.Scan(&scope.OrgID, &scope.SiteID, &scope.ClusterID, &scope.PoolID); err != nil {
			return nil, err
		}
		out = append(out, scope)
	}
	return out, rows.Err()
}

func (r *HandoffHAActivationRuntime) Stop(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.mu.Unlock()
	if cancel == nil || done == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *HandoffHAActivationRuntime) Running() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done != nil
}
