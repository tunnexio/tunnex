package aigateway

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"

	"github.com/google/uuid"
)

// Maintain is called by the existing elected scheduler. Healthy contact is a
// token exchange, including idle renewal; inference traffic is not required.
// Every cleanup candidate is rechecked after the same locks used by renewal.
func (s *Workloads) Maintain(ctx context.Context, limit int) error {
	if !s.ready() {
		return aiUnavailable()
	}
	if limit < 1 || limit > 1000 {
		return policyInvalid()
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	now := time.Now()
	if !s.lastMaintenance.IsZero() && now.Sub(s.lastMaintenance) > time.Minute {
		s.recoverySince = now
	}
	s.lastMaintenance = now
	fail := func() error { s.recoverySince = time.Now(); return aiUnavailable() }
	rows, err := s.policies.pool.Query(ctx, `SELECT org_id,id FROM ai_workloads WHERE applied_revision<>revision OR status IN ('pending','error') ORDER BY last_reconcile_at NULLS FIRST,id LIMIT $1`, limit)
	if err != nil {
		return fail()
	}
	type ref struct{ org, id uuid.UUID }
	pending := []ref{}
	for rows.Next() {
		var v ref
		if rows.Scan(&v.org, &v.id) != nil {
			rows.Close()
			return fail()
		}
		pending = append(pending, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail()
	}
	for _, v := range pending {
		if _, err = s.Reconcile(ctx, v.org, v.id); err != nil {
			return fail()
		}
	}
	if _, err = s.policies.pool.Exec(ctx, `DELETE FROM ai_workload_tokens WHERE token_hash IN (SELECT token_hash FROM ai_workload_tokens WHERE expires_at<=now() ORDER BY expires_at LIMIT $1)`, limit); err != nil {
		return fail()
	}
	if _, err = s.policies.pool.Exec(ctx, `DELETE FROM ai_workload_assertions WHERE (instance_id,jti) IN (SELECT instance_id,jti FROM ai_workload_assertions WHERE expires_at<=now() ORDER BY expires_at LIMIT $1)`, limit); err != nil {
		return fail()
	}
	// A fresh control-plane process waits for clients to renew before deciding
	// that previously disconnected ephemeral instances are abandoned.
	if now.Sub(s.recoverySince) < 10*time.Minute {
		return nil
	}
	rows, err = s.policies.pool.Query(ctx, `SELECT org_id,workload_id,id FROM ai_workload_instances WHERE ephemeral AND state='active' AND last_contact_at<now()-interval '24 hours' ORDER BY last_contact_at,id LIMIT $1`, limit)
	if err != nil {
		return fail()
	}
	instances := []workloadInstance{}
	for rows.Next() {
		var i workloadInstance
		if rows.Scan(&i.org, &i.workload, &i.id) != nil {
			rows.Close()
			return fail()
		}
		instances = append(instances, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail()
	}
	for _, i := range instances {
		if err = s.retireIdle(ctx, i); err != nil {
			return fail()
		}
	}
	return nil
}
func (s *Workloads) retireIdle(ctx context.Context, candidate workloadInstance) error {
	tx, err := s.policies.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackAI(tx)
	var id uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM ai_workloads WHERE org_id=$1 AND id=$2 FOR SHARE`, candidate.org, candidate.workload).Scan(&id); err != nil {
		return err
	}
	var generation int64
	// UPDATE re-evaluates last_contact_at after a concurrent issuer releases its
	// instance lock. A stale candidate snapshot never overrides fresh renewal.
	err = tx.QueryRow(ctx, `UPDATE ai_workload_instances SET state='retired' WHERE org_id=$1 AND workload_id=$2 AND id=$3 AND state='active' AND ephemeral AND last_contact_at<now()-interval '24 hours' RETURNING key_generation`, candidate.org, candidate.workload, candidate.id).Scan(&generation)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	candidate.generation = generation
	if err = auditWorkloadSystem(ctx, tx, candidate, "ai_workload.instance_idle_retired"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
