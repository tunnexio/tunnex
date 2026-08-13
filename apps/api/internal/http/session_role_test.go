package http

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/session"
)

// TestSessionAuthResolvesRolePerRequest is the TRIPWIRE for our downgrade
// semantics (S4.4 decision d). It proves that SessionAuth resolves the caller's
// role from the membership row on EVERY request — not from a value baked into
// the session at login. That is the entire reason a role downgrade (or removal,
// or deactivation) takes effect on the victim's very NEXT request instead of at
// next login.
//
// If someone later "optimizes" by caching the role/status in the session to save
// the per-request GetUserByID + ListMembershipsByUser reads, this test must go
// red — because that optimization silently reopens an escalation window (a
// downgrade would stop biting until the victim logs out). Do not delete or
// weaken this test to make such a change pass; the two DB reads are the price of
// next-request semantics, and they are the point.
func TestSessionAuthResolvesRolePerRequest(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	q := sqlc.New(tx)

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	store := session.NewWithClient(redis.NewClient(&redis.Options{Addr: mr.Addr()}), time.Hour, 24*time.Hour)

	org, user := uuid.New(), uuid.New()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,'O',$2)", []any{org, "sr-" + org.String()}},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,'U')", []any{user, user.String() + "@t.local"}},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'admin')", []any{org, user}},
	} {
		if _, e := tx.Exec(ctx, s.sql, s.args...); e != nil {
			t.Fatalf("setup %q: %v", s.sql, e)
		}
	}

	sess, err := store.Create(ctx, user, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	authFn := SessionAuth(store, q)
	// The request carries the session cookie; nothing about the role is in it.
	req := func() *http.Request {
		r, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: session.CookieName, Value: sess.ID})
		return r
	}

	// 1) Initial resolution: admin.
	p := authFn(req())
	if p == nil {
		t.Fatal("expected an authenticated principal")
	}
	if role, ok := p.RoleIn(org); !ok || role != "admin" {
		t.Fatalf("initial role = (%q,%v), want admin", role, ok)
	}

	// 2) Downgrade admin -> member in the DB. The SAME session's NEXT request must
	// see 'member' — proving per-request resolution (the tripwire).
	if _, e := tx.Exec(ctx, "UPDATE memberships SET role='member' WHERE org_id=$1 AND user_id=$2", org, user); e != nil {
		t.Fatalf("downgrade: %v", e)
	}
	p = authFn(req())
	if p == nil {
		t.Fatal("principal must still resolve after downgrade")
	}
	if role, ok := p.RoleIn(org); !ok || role != "member" {
		t.Fatalf("post-downgrade role = (%q,%v), want member — role is stale (cached in session?)", role, ok)
	}

	// 3) Removal mid-session (adjacent fail-closed edge): delete the membership.
	// RoleIn must resolve to not-a-member — a fail-closed zero, never a panic or a
	// zero-value role that authorize() might treat as a grant.
	if _, e := tx.Exec(ctx, "DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", org, user); e != nil {
		t.Fatalf("remove: %v", e)
	}
	p = authFn(req())
	if p == nil {
		t.Fatal("principal still resolves (the user exists); only their org membership is gone")
	}
	if role, ok := p.RoleIn(org); ok || role != "" {
		t.Fatalf("post-removal RoleIn = (%q,%v), want (\"\",false) fail-closed", role, ok)
	}
}
