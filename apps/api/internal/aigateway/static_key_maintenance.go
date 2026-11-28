package aigateway

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// StaticKeyExpiry describes one expiry reminder (founder decision 7).
type StaticKeyExpiry struct {
	Org, Workload, Key uuid.UUID
	Name, WorkloadName string
	ExpiresAt          time.Time
	DaysLeft           int
}

// StaticKeyExpiryNotifier delivers a reminder through the alert outbox.
type StaticKeyExpiryNotifier func(context.Context, StaticKeyExpiry) error

// Maintain runs on the elected scheduler with the workload maintenance. It
// disables engine keys of revoked or expired keys, retries engine keys that
// failed, and sends each expiry reminder (14 and 3 days) once.
func (s *StaticKeys) Maintain(ctx context.Context, limit int, notify StaticKeyExpiryNotifier) error {
	if !s.ready() {
		return aiUnavailable()
	}
	if limit < 1 || limit > 1000 {
		return policyInvalid()
	}
	failed := s.disableEngineKeys(ctx, limit)
	if err := s.retryEngineKeys(ctx, limit); err != nil {
		failed = err
	}
	if notify != nil {
		for _, window := range []struct {
			days   int
			column string
		}{{3, "expiry_alert_3_at"}, {14, "expiry_alert_14_at"}} {
			if err := s.remindExpiry(ctx, limit, window.days, window.column, notify); err != nil {
				failed = err
			}
		}
	}
	return failed
}

func (s *StaticKeys) retryEngineKeys(ctx context.Context, limit int) error {
	// lint:cross-org elected maintenance sweep across tenants; each key is then
	// re-read and changed under its own organization and workload.
	rows, err := s.w.policies.pool.Query(ctx, `SELECT k.org_id,k.workload_id,k.id FROM ai_workload_static_keys k JOIN ai_workloads w ON w.org_id=k.org_id AND w.id=k.workload_id
 WHERE k.status IN ('pending','error') AND k.revoked_at IS NULL AND k.expires_at>now() AND w.enabled AND w.status='applied' ORDER BY k.updated_at,k.id LIMIT $1`, limit)
	if err != nil {
		return aiUnavailable()
	}
	type ref struct{ org, workload, id uuid.UUID }
	refs := []ref{}
	for rows.Next() {
		var v ref
		if rows.Scan(&v.org, &v.workload, &v.id) != nil {
			rows.Close()
			return aiUnavailable()
		}
		refs = append(refs, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	var failed error
	for _, v := range refs {
		if err := s.retryEngineKey(ctx, v.org, v.workload, v.id); err != nil {
			failed = err
		}
	}
	return failed
}

func (s *StaticKeys) retryEngineKey(ctx context.Context, org, workload, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := s.w.policies.pool.Begin(ctx)
	if err != nil {
		return aiUnavailable()
	}
	defer rollbackAI(tx)
	w, err := lockWorkloadForKeys(ctx, tx, org, workload)
	if err != nil {
		return err
	}
	k, err := lockStaticKey(ctx, tx, org, workload, id)
	if err != nil {
		return err
	}
	if !w.Enabled || k.RevokedAt != nil || !k.ExpiresAt.After(time.Now()) {
		return nil
	}
	k = s.ensureEngineKey(ctx, tx, w, k)
	if tx.Commit(ctx) != nil {
		return aiUnavailable()
	}
	if k.Status != "applied" {
		return aiUnavailable()
	}
	return nil
}

func (s *StaticKeys) remindExpiry(ctx context.Context, limit, days int, column string, notify StaticKeyExpiryNotifier) error {
	// column is one of two constants above, never caller input.
	// lint:cross-org elected maintenance sweep across tenants; every update
	// below is scoped to the row's own organization and workload.
	rows, err := s.w.policies.pool.Query(ctx, `SELECT k.org_id,k.workload_id,k.id,k.name,w.name,k.expires_at FROM ai_workload_static_keys k JOIN ai_workloads w ON w.org_id=k.org_id AND w.id=k.workload_id
 WHERE k.revoked_at IS NULL AND k.expires_at>now() AND k.expires_at<=now()+make_interval(days=>$2) AND k.`+column+` IS NULL ORDER BY k.expires_at,k.id LIMIT $1`, limit, days)
	if err != nil {
		return aiUnavailable()
	}
	items := []StaticKeyExpiry{}
	for rows.Next() {
		v := StaticKeyExpiry{DaysLeft: days}
		if rows.Scan(&v.Org, &v.Workload, &v.Key, &v.Name, &v.WorkloadName, &v.ExpiresAt) != nil {
			rows.Close()
			return aiUnavailable()
		}
		items = append(items, v)
	}
	rows.Close()
	if rows.Err() != nil {
		return aiUnavailable()
	}
	var failed error
	for _, v := range items {
		// Mark first so a delivery retry never sends a second reminder; a
		// failed publish is reported and the console badge still shows.
		// The 3-day reminder also settles the 14-day one, so a short-lived key
		// gets one reminder, not two.
		set := column + `=now()`
		if column == "expiry_alert_3_at" {
			set += `,expiry_alert_14_at=coalesce(expiry_alert_14_at,now())`
		}
		// lint:cross-org the WHERE clause in the next literal scopes by org_id.
		res, err := s.w.policies.pool.Exec(ctx, `UPDATE ai_workload_static_keys SET `+set+` WHERE org_id=$1 AND workload_id=$2 AND id=$3 AND `+column+` IS NULL`, v.Org, v.Workload, v.Key)
		if err != nil {
			failed = aiUnavailable()
			continue
		}
		if res.RowsAffected() != 1 {
			continue
		}
		if notify(ctx, v) != nil {
			failed = aiUnavailable()
		}
	}
	return failed
}
