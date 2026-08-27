package fqdnresolver

// The persistence port is deliberately separate from Resolver.  A resolver is
// allowed to return only DNS observations; it never gets authority to choose a
// site, gateway, or active generation.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrSuperseded = errors.New("fqdn resolver work was superseded")

// Work is server-derived work for one resource. Context is never accepted from
// an API client or a DNS transport: Due reads the selected (site,gateway) pair
// stored by Lane 1 and Publish/Withdraw check it again while holding the row.
type Work struct {
	OrgID, ResourceID  uuid.UUID
	Hostname           string
	Context            Context
	ExpectedGeneration int64
}

// Store is the Lane 1 storage seam consumed by the scheduler.
type Store interface {
	Due(context.Context, time.Time, int) ([]Work, error)
	Publish(context.Context, Work, Generation) error
	Withdraw(context.Context, Work, WithdrawalCause, time.Time) error
}

// AfterCommit receives durable lifecycle changes.  It is intentionally a small
// port: the scheduler must not import the policy compiler or audit implementation
// (both are owned by later lanes).  Calls happen only after the serializable
// transaction has committed; a callback failure cannot make a published answer
// appear to have been rolled back.
type AfterCommit interface {
	Published(context.Context, Work, Generation)
	Withdrawn(context.Context, Work, WithdrawalCause, time.Time)
}

// AuditHook and PolicyHook are separately owned consumers of a durable answer
// transition.  Lane 3 can implement either (or both) without this package
// importing its compiler, notifier, or audit writer.
type AuditHook interface {
	FQDNPublished(context.Context, Work, Generation)
	FQDNWithdrawn(context.Context, Work, WithdrawalCause, time.Time)
}
type PolicyHook interface {
	InvalidateFQDN(context.Context, Work)
}

// Hooks adapts optional audit and policy/push consumers to AfterCommit.
type Hooks struct {
	Audit  AuditHook
	Policy PolicyHook
}

func (h Hooks) Published(ctx context.Context, w Work, g Generation) {
	if h.Audit != nil {
		h.Audit.FQDNPublished(ctx, w, g)
	}
	if h.Policy != nil {
		h.Policy.InvalidateFQDN(ctx, w)
	}
}
func (h Hooks) Withdrawn(ctx context.Context, w Work, c WithdrawalCause, at time.Time) {
	if h.Audit != nil {
		h.Audit.FQDNWithdrawn(ctx, w, c, at)
	}
	if h.Policy != nil {
		h.Policy.InvalidateFQDN(ctx, w)
	}
}

type PostgresStore struct {
	pool       *pgxpool.Pool
	retryAfter time.Duration
	after      AfterCommit
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool, retryAfter: MinTTL}
}

// WithAfterCommit attaches audit/policy-invalidation delivery without coupling
// this lifecycle package to its eventual consumer implementation.
func (s *PostgresStore) WithAfterCommit(after AfterCommit) *PostgresStore {
	s.after = after
	return s
}

// Due returns only resources with a server-selected active Site/Gateway pair.
// A missing pair is a draft, not an invitation to use a public resolver.
func (s *PostgresStore) Due(ctx context.Context, now time.Time, limit int) ([]Work, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
SELECT r.org_id,r.id,r.fqdn,r.resolver_site_id,r.resolver_node_id,
       COALESCE((SELECT max(g.generation) FROM fqdn_resource_answer_generations g WHERE g.org_id=r.org_id AND g.resource_id=r.id),0)
FROM fqdn_resources r
JOIN organizations o ON o.id=r.org_id AND o.deleted_at IS NULL AND o.fqdn_resources_enabled
WHERE r.resolver_site_id IS NOT NULL AND r.resolver_node_id IS NOT NULL
  AND (
    NOT EXISTS (SELECT 1 FROM fqdn_resource_answer_generations g WHERE g.org_id=r.org_id AND g.resource_id=r.id)
    OR EXISTS (
      SELECT 1 FROM fqdn_resource_answer_generations g
      WHERE g.org_id=r.org_id AND g.resource_id=r.id AND g.state='active'
        AND g.activated_at + (g.effective_ttl * 0.8) <= $1
    )
    OR EXISTS (
      SELECT 1 FROM fqdn_resource_answer_generations g
      WHERE g.org_id=r.org_id AND g.resource_id=r.id AND g.state='withdrawn'
        AND g.ended_at + $2::interval <= $1
        AND g.generation=(SELECT max(x.generation) FROM fqdn_resource_answer_generations x WHERE x.org_id=r.org_id AND x.resource_id=r.id)
    )
  )
ORDER BY r.updated_at,r.id
LIMIT $3`, now, s.retryAfter.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Work
	for rows.Next() {
		var w Work
		var site, gateway uuid.UUID
		if err := rows.Scan(&w.OrgID, &w.ResourceID, &w.Hostname, &site, &gateway, &w.ExpectedGeneration); err != nil {
			return nil, err
		}
		w.Context = Context{ResolverID: site.String(), GatewayID: gateway.String()}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Publish(ctx context.Context, w Work, g Generation) error {
	if !w.Context.valid() || len(g.Addresses) == 0 || len(g.Addresses) > MaxAnswers {
		return ErrUnboundContext
	}
	err := s.inTx(ctx, w, func(tx pgx.Tx, next int64, site, gateway uuid.UUID) error {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `INSERT INTO fqdn_resource_answer_generations (org_id,resource_id,generation,resolver_node_id,resolver_site_id,state,effective_ttl,resolved_at) VALUES ($1,$2,$3,$4,$5,'pending',$6,$7) RETURNING id`, w.OrgID, w.ResourceID, next, gateway, site, g.TTL, g.ResolvedAt).Scan(&id)
		if err != nil {
			return err
		}
		for _, address := range g.Addresses {
			if !address.IsValid() {
				return fmt.Errorf("invalid persisted address")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,$3::inet)`, id, w.OrgID, hostAddress(address)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE fqdn_resource_answer_generations SET state='retired',ended_at=$3 WHERE org_id=$1 AND resource_id=$2 AND state='active'`, w.OrgID, w.ResourceID, g.ResolvedAt); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE fqdn_resource_answer_generations SET state='active',activated_at=$3,last_good_at=$3 WHERE id=$1 AND org_id=$2`, id, w.OrgID, g.ResolvedAt)
		return err
	})
	if err == nil && s.after != nil {
		s.after.Published(ctx, w, g)
	}
	return err
}

func (s *PostgresStore) Withdraw(ctx context.Context, w Work, cause WithdrawalCause, at time.Time) error {
	if !w.Context.valid() {
		return ErrUnboundContext
	}
	if !approvedWithdrawalCause(cause) {
		return fmt.Errorf("invalid D4 withdrawal cause %q", cause)
	}
	err := s.inTx(ctx, w, func(tx pgx.Tx, next int64, site, gateway uuid.UUID) error {
		// Record every D4 outcome, including a first failed attempt. This gives
		// operators typed history but no empty active generation to compile.
		var lastGood *time.Time
		if err := tx.QueryRow(ctx, `SELECT last_good_at FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2 ORDER BY generation DESC LIMIT 1`, w.OrgID, w.ResourceID).Scan(&lastGood); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE fqdn_resource_answer_generations SET state='withdrawn',ended_at=$3,failure_code=$4 WHERE org_id=$1 AND resource_id=$2 AND state='active'`, w.OrgID, w.ResourceID, at, string(cause)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO fqdn_resource_answer_generations (org_id,resource_id,generation,resolver_node_id,resolver_site_id,state,effective_ttl,resolved_at,last_good_at,ended_at,failure_code) VALUES ($1,$2,$3,$4,$5,'withdrawn',$6,$7,$8,$7,$9)`, w.OrgID, w.ResourceID, next, gateway, site, MinTTL, at, lastGood, string(cause))
		return err
	})
	if err == nil && s.after != nil {
		s.after.Withdrawn(ctx, w, cause, at)
	}
	return err
}

func approvedWithdrawalCause(c WithdrawalCause) bool {
	switch c {
	case WithdrawalNXDOMAIN, WithdrawalSERVFAIL, WithdrawalTimeout, WithdrawalDisagreement, WithdrawalOverflow, WithdrawalLastGoodExpiry:
		return true
	default:
		return false
	}
}

func (s *PostgresStore) inTx(ctx context.Context, w Work, fn func(pgx.Tx, int64, uuid.UUID, uuid.UUID) error) (err error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	var site, gateway uuid.UUID
	err = tx.QueryRow(ctx, `SELECT resolver_site_id,resolver_node_id FROM fqdn_resources WHERE id=$1 AND org_id=$2 FOR UPDATE`, w.ResourceID, w.OrgID).Scan(&site, &gateway)
	if err != nil {
		return err
	}
	if site.String() != w.Context.ResolverID || gateway.String() != w.Context.GatewayID {
		return ErrSuperseded
	}
	var current int64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(max(generation),0) FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2`, w.OrgID, w.ResourceID).Scan(&current); err != nil {
		return err
	}
	if current != w.ExpectedGeneration {
		return ErrSuperseded
	}
	if err = fn(tx, current+1, site, gateway); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func hostAddress(a netip.Addr) string {
	if a.Is4() {
		return a.Unmap().String() + "/32"
	}
	return a.String() + "/128"
}
