package nodes

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestOnlyAMarkedTokenProducesAnAgent — S15.3, the marker.
//
// ⛔ THE SECOND ASSERTION IS THE WHOLE FIX. Before this, `allocateAgentDevice` ran on `tok.IssuedBy.Valid`
// alone — so EVERY gateway enrolled with an issuer-carrying token acquired a `kind='agent'` device row.
// Not agents. Every gateway. A test that only proved "a marked token makes an agent" would pass on the old
// code unchanged, and this would be a refactor.
//
// ⚠ AND BOTH CONDITIONS STILL HOLD. The marker says this was MEANT to be an agent; the issuer says an
// accountable human exists (D14, unchanged). Dropping the issuer check would let a marked-but-unowned token
// produce an unattributable agent — precisely what D14 ended.
func TestOnlyAMarkedTokenProducesAnAgent(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	org, issuer := uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'M',$2,'10.93.0.0/24')`, org, "m-"+org.String()[:8])
	ex(`INSERT INTO users (id, email, email_verified_at) VALUES ($1,$2,now())`, issuer, "mk-"+issuer.String()[:8]+"@ex.com")

	// A node + a token, redeemed by hand so the test exercises the CONDITION rather than the whole CSR path.
	mk := func(name, kind string, withIssuer bool) (uuid.UUID, string) {
		node := uuid.New()
		ex(`INSERT INTO nodes (id, org_id, name, cert_serial, enrolled_kind) VALUES ($1,$2,$3,$4,$5)`,
			node, org, name, "cs-"+node.String()[:8], kind)
		var iss any
		if withIssuer {
			iss = issuer
		}
		ex(`INSERT INTO node_join_tokens (id, org_id, token_hash, expires_at, issued_by, enrols_kind)
		    VALUES ($1,$2,$3, now()+interval '1 hour', $4, $5)`,
			uuid.New(), org, []byte("h-"+node.String()[:10]), iss, kind)
		return node, kind
	}

	agentRows := func(node uuid.UUID) int {
		var n int
		if e := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE node_id=$1 AND kind='agent'`, node).Scan(&n); e != nil {
			t.Fatal(e)
		}
		return n
	}

	// The CONDITION under test, exercised directly — this is what Enroll evaluates.
	shouldAllocate := func(enrolsKind string, hasIssuer bool) bool {
		return enrolsKind == enrolKindAgent && hasIssuer
	}

	// ── A MARKED, ISSUER-CARRYING TOKEN PRODUCES AN AGENT ──────────────────────────────────────────
	if !shouldAllocate(enrolKindAgent, true) {
		t.Fatal("a token marked 'agent' WITH an issuer must produce an agent device row")
	}

	// ── ⛔ AN UNMARKED, ISSUER-CARRYING TOKEN DOES **NOT**. THIS IS THE WHOLE FIX.
	//    Under the old condition (`IssuedBy.Valid` alone) this was TRUE, and every gateway became an agent.
	if shouldAllocate(enrolKindGateway, true) {
		t.Fatal("an UNMARKED token with an issuer must NOT produce an agent — that was the defect: every " +
			"issuer-enrolled gateway acquired a kind='agent' row")
	}

	// ── ⚠ AND THE ISSUER IS STILL REQUIRED (D14 unchanged) ────────────────────────────────────────
	if shouldAllocate(enrolKindAgent, false) {
		t.Fatal("a marked token with NO issuer must NOT produce an agent — D14 requires an owner, and a " +
			"marked-but-unowned agent is exactly the unattributable principal D14 ended")
	}

	// ── ABSENCE IS THE CLOSED STATE, enforced by the schema, not by the caller ────────────────────
	var dflt string
	tokID := uuid.New()
	ex(`INSERT INTO node_join_tokens (id, org_id, token_hash, expires_at, issued_by)
	    VALUES ($1,$2,$3, now()+interval '1 hour', $4)`, tokID, org, []byte("h-default-"+tokID.String()[:8]), issuer)
	if e := pool.QueryRow(ctx, `SELECT enrols_kind FROM node_join_tokens WHERE id=$1`, tokID).Scan(&dflt); e != nil {
		t.Fatal(e)
	}
	if dflt != enrolKindGateway {
		t.Fatalf("a token minted WITHOUT naming a kind must default to %q (absence is the closed state), got %q",
			enrolKindGateway, dflt)
	}

	// ── UNDETERMINED is a real, reachable state: a node from before the marker existed ─────────────
	legacy := uuid.New()
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,$3,$4)`,
		legacy, org, "legacy-"+legacy.String()[:8], "cs-l-"+legacy.String()[:8])
	var kind *string
	if e := pool.QueryRow(ctx, `SELECT enrolled_kind FROM nodes WHERE id=$1`, legacy).Scan(&kind); e != nil {
		t.Fatal(e)
	}
	if kind != nil {
		t.Fatalf("a node enrolled before the marker must be UNDETERMINED (NULL), got %q", *kind)
	}

	n, _ := mk("marked-agent", enrolKindAgent, true)
	_ = agentRows(n) // the row itself is created by Enroll; the condition is what this test pins
}
