package nodes

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// stubHashProvider controls the pushed hash the CP sees for a node (and can force a compile
// fault). Distinct from policy_surface_test's fakeProvider so the desync inputs are direct.
type stubHashProvider struct {
	pol *policyspec.Compiled // the ROUTE-LESS pushed artifact; core pushedHash finalizes+hashes it
	err error
}

func (s stubHashProvider) CompiledForNode(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*policyspec.Compiled, error) {
	return s.pol, s.err
}
func (s stubHashProvider) CompiledArtifactsForNodes(_ context.Context, _ uuid.UUID, ids []uuid.UUID, _ uuid.UUID) (map[uuid.UUID]*policyspec.Compiled, error) {
	if s.err != nil {
		return nil, s.err
	}
	out := make(map[uuid.UUID]*policyspec.Compiled, len(ids))
	for _, id := range ids {
		out[id] = s.pol
	}
	return out, nil
}

// enfArt builds a distinct ENFORCING route-less artifact (its NodeID tag varies the CanonicalHash); a
// non-site node's pushedHash == CanonicalHash(enfArt(tag)). canon is that hash.
func enfArt(tag string) *policyspec.Compiled {
	return &policyspec.Compiled{Version: policyspec.ProtocolVersion, NodeID: tag, Mode: "enforcing"}
}
func canon(pol *policyspec.Compiled) string { return policyspec.CanonicalHash(*pol) }

func desyncPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func seedNode(t *testing.T, pool *pgxpool.Pool) sqlc.Node {
	t.Helper()
	ctx := context.Background()
	org, id := uuid.New(), uuid.New()
	exec := func(q string, a ...any) {
		if _, err := pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)`, org, "dh", "dh-"+org.String()[:8])
	exec(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,'gw',$3)`, id, org, "s-"+id.String())
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org) })
	// trackDesync only reads node.ID + node.OrgID.
	return sqlc.Node{ID: id, OrgID: org}
}

func desyncSince(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) pgtype.Timestamptz {
	t.Helper()
	var ts pgtype.Timestamptz
	if err := pool.QueryRow(context.Background(), `SELECT policy_desync_since FROM nodes WHERE id=$1`, id).Scan(&ts); err != nil {
		t.Fatalf("read desync_since: %v", err)
	}
	return ts
}

// trackDesync is the SINGLE WRITER of policy_desync_since. Reds pin: stamp on term-3, clear on
// reconvergence/non-enforcing, idempotent onset per episode, and the open-build silence.
func TestTrackDesync(t *testing.T) {
	pool := desyncPool(t)
	ctx := context.Background()
	svc := func(pol *policyspec.Compiled) *Service {
		return &Service{pool: pool, q: sqlc.New(pool), policy: stubHashProvider{pol: pol}}
	}

	t.Run("stamp on enforcing mismatch, then idempotent onset", func(t *testing.T) {
		n := seedNode(t, pool)
		svc(enfArt("new")).trackDesync(ctx, n, "old") // pushed(canon) != applied
		first := desyncSince(t, pool, n.ID)
		if !first.Valid {
			t.Fatal("mismatch must STAMP policy_desync_since")
		}
		svc(enfArt("new")).trackDesync(ctx, n, "old") // still mismatched → onset PRESERVED (WHERE IS NULL)
		if again := desyncSince(t, pool, n.ID); !again.Valid || !again.Time.Equal(first.Time) {
			t.Fatalf("repeated mismatch must preserve the first onset: %v vs %v", again.Time, first.Time)
		}
	})

	t.Run("clear on reconvergence (applied == pushed)", func(t *testing.T) {
		n := seedNode(t, pool)
		svc(enfArt("h")).trackDesync(ctx, n, "old")              // stamp
		svc(enfArt("h")).trackDesync(ctx, n, canon(enfArt("h"))) // applied caught up → CLEAR
		if desyncSince(t, pool, n.ID).Valid {
			t.Fatal("reconvergence must CLEAR the stamp")
		}
	})

	// A-3(ii), REAL PATH: a rule deleted and recreated with a new uuid but identical
	// grant compiles to the SAME CanonicalHash (rule_id is hash-excluded), so the actual
	// single-writer trackDesync sees pushed==applied and does NOT stamp policy_desync_since.
	// Proves the S7.4b desync flap is dead against the real writer + DB column, not merely
	// at the hash layer.
	t.Run("rule_id-only recreate does NOT stamp (S7.4b flap dead on the trackDesync path)", func(t *testing.T) {
		n := seedNode(t, pool)
		mk := func(ruleID string) policyspec.Compiled {
			return policyspec.Compiled{
				Version: policyspec.ProtocolVersion, NodeID: n.ID.String(), Mode: "enforcing",
				Allow: []policyspec.AllowEntry{{SrcIP: "10.99.0.10", DstCIDR: "10.0.5.0/24", Protocol: policyspec.ProtoTCP, PortLow: 5432, PortHigh: 5432, RuleID: ruleID}},
			}
		}
		applied := policyspec.CanonicalHash(mk("rule-uuid-1")) // node applied the ORIGINAL rule's artifact
		p2 := mk("rule-uuid-2")                                // admin deleted+recreated → new uuid, same grant
		if applied != policyspec.CanonicalHash(p2) {
			t.Fatalf("precondition: rule_id-only change must not move the hash")
		}
		svc(&p2).trackDesync(ctx, n, applied) // pushed(canon) == applied → the real writer must NOT stamp
		if desyncSince(t, pool, n.ID).Valid {
			t.Fatal("a rule_id-only recreate must NOT stamp policy_desync_since")
		}
	})

	t.Run("clear on non-enforcing (pushed == '')", func(t *testing.T) {
		n := seedNode(t, pool)
		svc(enfArt("h")).trackDesync(ctx, n, "old") // stamp under enforcing
		svc(nil).trackDesync(ctx, n, "old")         // org went off/mesh → route-less nil → pushed "" → CLEAR
		if desyncSince(t, pool, n.ID).Valid {
			t.Fatal("non-enforcing must CLEAR the stamp")
		}
	})

	t.Run("revert-to-clear then re-push re-stamps a NEW onset (per-episode)", func(t *testing.T) {
		n := seedNode(t, pool)
		svc(enfArt("new")).trackDesync(ctx, n, "old") // episode 1: stamp
		t1 := desyncSince(t, pool, n.ID)
		svc(enfArt("old")).trackDesync(ctx, n, canon(enfArt("old"))) // revert target back to applied → CLEAR
		svc(enfArt("newer")).trackDesync(ctx, n, "old")              // episode 2: fresh mismatch → NEW onset
		t2 := desyncSince(t, pool, n.ID)
		if !t2.Valid || t2.Time.Before(t1.Time) {
			t.Fatalf("a new episode must stamp a NEW onset (not the cleared one): t1=%v t2=%v", t1.Time, t2.Time)
		}
	})

	t.Run("open build (nil policy) is SILENT — no write", func(t *testing.T) {
		n := seedNode(t, pool)
		open := &Service{pool: pool, q: sqlc.New(pool), policy: nil}
		open.trackDesync(ctx, n, "anything")
		if desyncSince(t, pool, n.ID).Valid {
			t.Fatal("open build must NOT write policy_desync_since")
		}
	})

	t.Run("compile fault (provider error) never stamps/clears", func(t *testing.T) {
		n := seedNode(t, pool)
		svc(enfArt("new")).trackDesync(ctx, n, "old") // stamp first
		faulted := &Service{pool: pool, q: sqlc.New(pool), policy: stubHashProvider{err: context.DeadlineExceeded}}
		faulted.trackDesync(ctx, n, "old") // can't-determine → leave the stamp UNTOUCHED
		if !desyncSince(t, pool, n.ID).Valid {
			t.Fatal("a compile fault must NOT clear an existing stamp")
		}
	})
}

// PolicyHealthForNodes — the collapsed bool+kind. Reds: [1] the freshness gate reads
// policy_reported_at (NOT last_seen_at), so a node that polls but stopped REPORTING with a real
// mismatch → desync_unknown; [8] the open build → {false, healthy}, never desync_unknown.
func TestPolicyHealthForNodes(t *testing.T) {
	pool := desyncPool(t)
	ctx := context.Background()
	org, id := uuid.New(), uuid.New()
	exec := func(q string, a ...any) {
		if _, err := pool.Exec(ctx, q, a...); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	exec(`INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)`, org, "ph", "ph-"+org.String()[:8])
	exec(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,'gw',$3)`, id, org, "s-"+id.String())
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM organizations WHERE id=$1`, org) })
	// applied="applied", REPORT is 5 min stale, but last_seen is FRESH (a poll bumped it), and
	// an onset is stamped — i.e. the gateway stopped REPORTING while desynced.
	exec(`UPDATE nodes SET capabilities = jsonb_set('{}','{policy_hash}','"applied"'),
	      policy_reported_at = now() - interval '5 minutes',
	      last_seen_at = now(),
	      policy_desync_since = now() - interval '90 seconds' WHERE id=$1`, id)

	q := sqlc.New(pool)
	n, err := q.GetNodeByOrgName(ctx, sqlc.GetNodeByOrgNameParams{OrgID: org, Name: "gw"})
	if err != nil {
		t.Fatalf("GetNodeByOrgName: %v", err)
	}

	// [1] enterprise, pushed != applied, REPORT stale → desync_unknown (NOT converging/silent/healthy).
	ent := &Service{pool: pool, q: q, policy: stubHashProvider{pol: enfArt("pushed")}}
	h := ent.PolicyHealthForNodes(ctx, org, []sqlc.Node{n})[id]
	if !h.Degraded {
		t.Fatal("enforcing mismatch must set the authoritative bool")
	}
	if h.Kind != KindDesyncUnknown {
		t.Fatalf("[1] stale REPORT (last_seen fresh) must read desync_unknown, got %q", h.Kind)
	}

	// [8] open build (nil policy): {false, healthy}, never desync_unknown.
	open := &Service{pool: pool, q: q, policy: nil}
	ho := open.PolicyHealthForNodes(ctx, org, []sqlc.Node{n})[id]
	if ho.Degraded || ho.Kind != KindHealthy {
		t.Fatalf("[8] open build must be {false, healthy}, got {%v, %q}", ho.Degraded, ho.Kind)
	}
}
