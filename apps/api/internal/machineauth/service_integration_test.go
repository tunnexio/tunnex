package machineauth

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func testPool(t *testing.T) *pgxpool.Pool {
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

func testSealer(t *testing.T) *crypto.Sealer {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	s, err := crypto.NewSealer(key)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

// TestMintUseRevoke — S10.2 Slice 1: the machine-credential lifecycle end to end. Mint returns a `tnxm_`
// token ONCE with a keyed fingerprint; the token HASH resolves the active row (the "use" the auth path
// performs), scoped to the org with the fixed 'operator' role; the mint is audited to the HUMAN owner
// (fingerprint only, never the token); Revoke severs (RevokedAt set → the auth path returns nil → denied)
// and drops it from List; a second revoke is a no-op (no leak).
func TestMintUseRevoke(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool, testSealer(t))
	ctx := context.Background()

	org, owner := uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'M',$2,'10.99.0.0/24')`, org, "m-"+org.String()[:8])
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, owner, "m-"+owner.String()[:8]+"@ex.com")

	// MINT — one-time token, keyed fingerprint.
	cred, err := svc.Mint(ctx, org, owner, "gitops")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasPrefix(cred.Token, TokenPrefix) {
		t.Fatalf("token must be %s-prefixed, got %q", TokenPrefix, cred.Token)
	}
	if cred.Fingerprint == "" {
		t.Fatal("fingerprint must be set")
	}

	q := sqlc.New(pool)
	h := sha256.Sum256([]byte(cred.Token))

	// USE — the token hash resolves the active row (what MachineAuth does), org-scoped, role=operator.
	row, err := q.GetMachineCredentialByHash(ctx, h[:])
	if err != nil {
		t.Fatalf("the mint token must resolve by hash: %v", err)
	}
	if row.RevokedAt.Valid {
		t.Fatal("a freshly-minted credential must not be revoked")
	}
	if row.Role != "operator" {
		t.Fatalf("the machine credential must hold the fixed 'operator' role, got %q", row.Role)
	}
	if row.OrgID != org {
		t.Fatal("the credential must be scoped to its org")
	}

	// The mint is audited to the human owner (org-scoped, fingerprint only — never the token).
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='machine.credential_issued'
		   AND actor_user_id=$2 AND metadata->>'fingerprint'=$3`, org, owner, cred.Fingerprint).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("mint must audit machine.credential_issued (owner, fingerprint), got %d", n)
	}
	if list, _ := svc.List(ctx, org); len(list) != 1 {
		t.Fatalf("List must show the 1 active credential, got %d", len(list))
	}

	// REVOKE — severs (the auth path re-reads and returns nil on RevokedAt), and drops from List.
	ok, err := svc.Revoke(ctx, org, owner, cred.ID)
	if err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	row2, err := q.GetMachineCredentialByHash(ctx, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if !row2.RevokedAt.Valid {
		t.Fatal("a revoked credential must have RevokedAt set (severs on its next request)")
	}
	if list, _ := svc.List(ctx, org); len(list) != 0 {
		t.Fatalf("a revoked credential must be excluded from List, got %d", len(list))
	}

	// Idempotent — a second revoke is a no-op (no leak of whether the id existed).
	if ok2, _ := svc.Revoke(ctx, org, owner, cred.ID); ok2 {
		t.Fatal("re-revoking must be a no-op (0 rows)")
	}
}

// TestOwnerAssignmentEligibility — S15.1, D21 and D22 ruled together, because they are the same row seen
// from two sides: WHO may be named the accountable owner, and WHETHER the name survives.
//
// ⛔ BOTH REDS IN EACH DIRECTION. A guard that refuses everything passes the exclusion half and is not a
// guard; a resolver that returns a constant passes the departed half and is not a resolver.
func TestOwnerAssignmentEligibility(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool, testSealer(t))
	ctx := context.Background()

	org, actor := uuid.New(), uuid.New()
	verified, unverified, departed := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'E',$2,'10.97.0.0/24')`, org, "e-"+org.String()[:8])
	mkUser := func(id uuid.UUID, tag string, isVerified bool) string {
		email := tag + "-" + id.String()[:8] + "@ex.com"
		if isVerified {
			ex(`INSERT INTO users (id, email, email_verified_at) VALUES ($1,$2,now())`, id, email)
		} else {
			ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, id, email)
		}
		ex(`INSERT INTO memberships (id, org_id, user_id, role) VALUES ($1,$2,$3,'admin')`, uuid.New(), org, id)
		return email
	}
	ex(`INSERT INTO users (id, email, email_verified_at) VALUES ($1,$2,now())`, actor, "a-"+actor.String()[:8]+"@ex.com")
	verifiedEmail := mkUser(verified, "v", true)
	mkUser(unverified, "u", false)
	departedEmail := mkUser(departed, "d", true)

	mint := func(name string) uuid.UUID {
		c, err := svc.Mint(ctx, org, actor, name)
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		return c.ID
	}

	// ── D21, RED 1: an UNVERIFIED account is refused ────────────────────────────────────────────────
	// Ownership is an accountability claim; requireVerifiedUser already bars an unverified account from
	// acting, and nameable-but-unable-to-act is a contradiction this screen would render as fact.
	cUnver := mint("to-unverified")
	assigned, err := svc.AssignOwner(ctx, org, actor, cUnver, unverified)
	if err != nil {
		t.Fatalf("assign(unverified): %v", err)
	}
	if assigned {
		t.Fatal("D21: an UNVERIFIED account must not be assignable as an accountable owner")
	}
	// The refusal is in the statement, so the column must be untouched — not merely the return value.
	var got *uuid.UUID
	if e := pool.QueryRow(ctx, `SELECT user_id FROM machine_credentials WHERE id=$1`, cUnver).Scan(&got); e != nil {
		t.Fatal(e)
	}
	if got != nil {
		t.Fatalf("D21: the UPDATE must not have written an unverified owner, got %v", *got)
	}
	// And the handler's pre-check must be able to SAY it was the verification, not the membership.
	isVerified, isMember, err := svc.OwnerEligible(ctx, org, unverified)
	if err != nil {
		t.Fatal(err)
	}
	if !isMember || isVerified {
		t.Fatalf("OwnerEligible(unverified) = verified:%v member:%v; want member and NOT verified", isVerified, isMember)
	}

	// ── D21, RED 2: a VERIFIED account is still ACCEPTED ────────────────────────────────────────────
	// ⛔ WITHOUT THIS, A GUARD THAT REFUSES EVERYONE PASSES RED 1.
	cVer := mint("to-verified")
	assigned, err = svc.AssignOwner(ctx, org, actor, cVer, verified)
	if err != nil || !assigned {
		t.Fatalf("D21: a VERIFIED member must remain assignable; assigned=%v err=%v", assigned, err)
	}

	// ── D22, THE RED THAT MAKES IT NOT A REFACTOR ───────────────────────────────────────────────────
	// An owner who has LEFT THE ORG still renders their identity. Nothing pins a membership, so the
	// roster cannot name them — and that is exactly the row an accountability screen exists for.
	cDep := mint("to-departed")
	if ok, e := svc.AssignOwner(ctx, org, actor, cDep, departed); e != nil || !ok {
		t.Fatalf("seed the departed case: assigned=%v err=%v", ok, e)
	}
	ex(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, org, departed)

	rows, err := svc.List(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]*string{}
	for _, r := range rows {
		seen[r.Name] = r.OwnerEmail
	}
	if e := seen["to-departed"]; e == nil || *e != departedEmail {
		t.Fatalf("D22: an owner who LEFT THE ORG must still be named, want %q, got %v", departedEmail, e)
	}
	// ⚠ And not a constant: a live owner resolves to their own address, an unassigned row to NULL.
	if e := seen["to-verified"]; e == nil || *e != verifiedEmail {
		t.Fatalf("D22: a live owner must resolve to their own email, want %q, got %v", verifiedEmail, e)
	}
	if e := seen["to-unverified"]; e != nil {
		t.Fatalf("D22: an UNASSIGNED credential must carry no owner_email, got %q", *e)
	}
}
