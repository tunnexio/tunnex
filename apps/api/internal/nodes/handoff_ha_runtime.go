package nodes

import (
	"context"
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
	_, _ = r.elector.WithLeaderSession(ctx, pid, func(conn *pgxpool.Conn) error {
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
