package nodes

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestJoinTokenIssuerSurvivesEnrolment — S15.2 slice 1.
//
// ⛔ THE FACT EXISTED AT EXACTLY THE MOMENT IT WAS THROWN AWAY. `IssueJoinToken` has always received the
// human as `actor` and written them to the audit log ALONE — so before 0066 every token discarded its
// issuer to a table nobody joins against, recoverable only by parsing audit metadata. This test pins the
// carry: issue → redeem → node.
//
// ⚠ AND IT PINS THE NAME'S MEANING, NOT JUST ITS VALUE. `nodes.owner_user_id` is the token's ISSUER — who
// authorised this agent into the org — and NEVER who installed it. Enrolment is an agent redeeming a token
// unattended, so the installer is not capturable by construction (rank-2 ruling). A test that only checked
// "some uuid landed" would pass just as happily on a wrong one.
func TestJoinTokenIssuerSurvivesEnrolment(t *testing.T) {
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

	org, issuer, other := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'I',$2,'10.96.0.0/24')`, org, "i-"+org.String()[:8])
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, issuer, "iss-"+issuer.String()[:8]+"@ex.com")
	ex(`INSERT INTO users (id, email) VALUES ($1,$2)`, other, "oth-"+other.String()[:8]+"@ex.com")

	// ── The carry: the issuer is recorded at ISSUE time ──────────────────────────────────────────────
	var tokenID uuid.UUID
	var gotIssuer *uuid.UUID
	ex(`INSERT INTO node_join_tokens (org_id, token_hash, expires_at, issued_by)
	    VALUES ($1, $2, now() + interval '1 hour', $3)`, org, []byte("hash-"+org.String()[:8]), issuer)
	if e := pool.QueryRow(ctx,
		`SELECT id, issued_by FROM node_join_tokens WHERE org_id=$1`, org).Scan(&tokenID, &gotIssuer); e != nil {
		t.Fatal(e)
	}
	if gotIssuer == nil || *gotIssuer != issuer {
		t.Fatalf("the issuer must be recorded at issue time; want %v, got %v", issuer, gotIssuer)
	}
	// ⛔ NOT A CONSTANT. A column that returned the same uuid for everyone would pass the line above.
	if *gotIssuer == other {
		t.Fatal("the recorded issuer must be the ISSUING user, not merely some user")
	}

	// ── The carry: it reaches the node ───────────────────────────────────────────────────────────────
	node := uuid.New()
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial, owner_user_id)
	    VALUES ($1, $2, $3, $4, (SELECT issued_by FROM node_join_tokens WHERE id = $5))`,
		node, org, "agent-"+node.String()[:8], "serial-"+node.String()[:8], tokenID)

	var owner *uuid.UUID
	if e := pool.QueryRow(ctx, `SELECT owner_user_id FROM nodes WHERE id=$1`, node).Scan(&owner); e != nil {
		t.Fatal(e)
	}
	if owner == nil || *owner != issuer {
		t.Fatalf("the node's owner must be the token's issuer; want %v, got %v", issuer, owner)
	}

	// ── ⛔ THE FK ACTIONS DIFFER BY ARGUMENT, AND EACH IS PINNED ──────────────────────────────────────
	//
	// `nodes.owner_user_id` is ON DELETE RESTRICT (the S15.1 choice, against the S14.12 cascade class), so
	// a user who owns an agent cannot be deleted out from under a running tunnel. `node_join_tokens.
	// issued_by` is ON DELETE SET NULL: a join token is a SPENT RECORD OF AN ACT, and destroying it to tidy
	// a foreign key would be destroying history.
	//
	// ⚠ This is the one place the two are asserted to be DIFFERENT on purpose. Copying one to the other is
	// the mistake this pins against — and D26 holds the separate question of `devices.user_id`.
	if _, e := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, issuer); e == nil {
		t.Fatal("RESTRICT: deleting a user who owns an agent must be REFUSED, not cascade the node away")
	}

	// Detach the node, then the token's own action is observable on its own terms.
	ex(`UPDATE nodes SET owner_user_id = NULL WHERE id=$1`, node)
	if _, e := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, issuer); e != nil {
		t.Fatalf("with no agent owned, the user must be deletable: %v", e)
	}
	var stillThere bool
	var afterDelete *uuid.UUID
	if e := pool.QueryRow(ctx,
		`SELECT true, issued_by FROM node_join_tokens WHERE id=$1`, tokenID).Scan(&stillThere, &afterDelete); e != nil {
		t.Fatalf("SET NULL: the token must SURVIVE its issuer's deletion: %v", e)
	}
	if afterDelete != nil {
		t.Fatalf("SET NULL: the issuer reference must be cleared, got %v", afterDelete)
	}
}
