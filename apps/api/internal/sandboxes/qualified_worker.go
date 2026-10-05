package sandboxes

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"time"
)

// QualificationWorker drives one explicitly assigned fixture organization.
// It enables no public creation. Resume retains the confirmed enrollment identity.
// All external work remains serial and uses the existing durable lifecycle lease.
type QualificationWorker struct {
	Store    *Store
	OrgID    uuid.UUID
	Initial  *InitialLaunchCoordinator
	Provider sandboxruntime.Provider
	Cleanup  CleanupNetwork
}

func (w *QualificationWorker) Run(ctx context.Context, report func(uuid.UUID, error)) error {
	if w == nil || w.Store == nil || w.OrgID == uuid.Nil || w.Initial == nil || w.Provider == nil || w.Cleanup == nil {
		return ErrDisabled
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := w.batch(ctx, report); err != nil && report != nil {
			report(uuid.Nil, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func (w *QualificationWorker) batch(ctx context.Context, report func(uuid.UUID, error)) error {
	if err := w.Store.SweepDelegations(ctx, w.OrgID, 20); err != nil {
		return err
	}

	var count int
	if err := w.Store.pool.QueryRow(ctx, `SELECT count(*) FROM sandboxes WHERE org_id=$1 AND observed_state<>'deleted'`, w.OrgID).Scan(&count); err != nil {
		return err
	}
	// More than one retained sandbox closes initial provisioning, but cleanup is
	// still allowed. The qualification budget cannot silently create a second VM.
	if count <= 1 {
		rows, err := w.Store.pool.Query(ctx, `SELECT id FROM sandboxes WHERE org_id=$1 AND desired_state='started' AND (generation=1 AND observed_state IN ('creating','starting') OR generation>1 AND observed_state IN ('stopped','starting')) AND expires_at>now() ORDER BY id LIMIT 1`, w.OrgID)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, id := range ids {
			work, cancel := context.WithTimeout(ctx, 30*time.Second)
			var generation int64
			err = w.Store.pool.QueryRow(work, `SELECT generation FROM sandboxes WHERE id=$1 AND org_id=$2`, id, w.OrgID).Scan(&generation)
			if err == nil {
				if generation == 1 {
					err = w.Initial.Reconcile(work, id)
				} else {
					err = (&ResumeCoordinator{Initial: w.Initial}).Reconcile(work, id)
				}
			}
			cancel()
			if err != nil && report != nil {
				report(id, err)
			}
		}
	}
	rows, err := w.Store.pool.Query(ctx, `SELECT id FROM sandboxes WHERE org_id=$1 AND observed_state<>'deleted' AND (desired_state IN ('stopped','deleted') OR expires_at<=now()) AND NOT(desired_state='stopped' AND observed_state='stopped' AND expires_at>now()) ORDER BY id LIMIT 20`, w.OrgID)
	if err != nil {
		return err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		work, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = w.Store.ReconcileCleanup(work, id, w.Provider, w.Cleanup)
		cancel()
		if err != nil && report != nil {
			report(id, err)
		}
	}
	return nil
}
