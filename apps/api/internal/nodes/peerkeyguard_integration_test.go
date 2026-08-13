package nodes

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestMalformedPeerKeyExcludesThePeerNotTheInterface — S15.2 walk Leg 4.
//
// ⛔ `wg syncconf` IS ALL-OR-NOTHING, AND THAT IS THE HAZARD THIS PINS. One malformed key does not produce
// one broken peer — it makes WireGuard reject the ENTIRE interface configuration, so a gateway ends up with
// **zero** peers and every human device on it stops working.
//
// The guard for this already existed (an is-not-empty check on public_key, S9.1/WF-OVPN-10) and was one
// predicate too narrow: emptiness is a special case of malformedness, and an agent device's `pending-agent-<uuid>`
// placeholder is non-empty. It sailed through the guard written to stop exactly this.
//
// > A GUARD WRITTEN FOR A HAZARD IS NOT A GUARD AGAINST THE HAZARD. An is-not-empty test asks IS THERE A KEY;
// > the parser asks *is this a key*, and only the second question is the one `wg` will ask.
func TestMalformedPeerKeyExcludesThePeerNotTheInterface(t *testing.T) {
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
	q := sqlc.New(pool)

	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id, name, slug, pool_cidr) VALUES ($1,'P',$2,'10.94.0.0/24')`, org, "p-"+org.String()[:8])
	ex(`INSERT INTO users (id, email, status) VALUES ($1,$2,'active')`, owner, "pk-"+owner.String()[:8]+"@ex.com")
	ex(`INSERT INTO memberships (id, org_id, user_id, role) VALUES ($1,$2,$3,'admin')`, uuid.New(), org, owner)
	ex(`INSERT INTO nodes (id, org_id, name, cert_serial) VALUES ($1,$2,$3,$4)`, node, org, "gw-"+node.String()[:8], "cs-"+node.String()[:8])

	// A REAL WireGuard key: base64 of 32 bytes — 43 chars plus '='.
	const goodKey = "T1Xn3SrqHb4NjLqIyDaqMxm03Mqr6fdBY8ypjwcjTWQ="
	mk := func(name, key, ip string) {
		t.Helper()
		ex(`INSERT INTO devices (org_id,user_id,node_id,name,public_key,assigned_ip,status,kind,transport)
		    VALUES ($1,$2,$3,$4,$5,$6,'active','human','wireguard')`, org, owner, node, name, key, ip)
	}
	peers := func() []sqlc.ListActiveWireGuardPeersForNodeRow {
		rows, e := q.ListActiveWireGuardPeersForNode(ctx, node)
		if e != nil {
			t.Fatal(e)
		}
		return rows
	}

	// ── A REAL-KEYED DEVICE IS INCLUDED. Without this, "excludes the bad one" would also pass on a
	//    filter that excluded everything — which is the outage, not the fix.
	mk("laptop", goodKey, "10.94.0.10")
	if got := len(peers()); got != 1 {
		t.Fatalf("a well-formed peer must be INCLUDED; want 1, got %d", got)
	}

	// ── A PLACEHOLDER-KEYED DEVICE IS EXCLUDED. This is the exact value S15.2 slice 3 wrote.
	mk("agent-row", "pending-agent-"+node.String(), "10.94.0.11")
	if got := len(peers()); got != 1 {
		t.Fatalf("a placeholder-keyed device must be EXCLUDED; peer count must stay 1, got %d", got)
	}

	// ── ⛔ THE LEG THIS DEFECT IS REALLY ABOUT: ONE BAD PEER, AND EVERY GOOD ONE STILL CONFIGURES.
	//    A filter that dropped the whole node's peer set on encountering a bad row would pass both
	//    assertions above and reproduce the original outage exactly.
	mk("phone", "cMv8u9xQZ1bK3nR7tYwEfGhJkLmNpQrStUvWxYz0A1c=", "10.94.0.12")
	got := peers()
	if len(got) != 2 {
		t.Fatalf("ONE malformed peer must not cost the others: want 2 good peers alongside 1 bad, got %d", len(got))
	}
	for _, r := range got {
		if r.PublicKey == "" || len(r.PublicKey) != 44 {
			t.Fatalf("every returned peer must carry a well-formed key, got %q", r.PublicKey)
		}
	}

	// ── ⚠ AND THE EXCLUSION IS VISIBLE. A peer that vanishes without a word is indistinguishable from one
	//    that was never configured — the reassuring-empty class, on a data plane.
	bad, e := q.ListMalformedKeyPeersForNode(ctx, node)
	if e != nil {
		t.Fatal(e)
	}
	if len(bad) != 1 || bad[0].Name != "agent-row" {
		t.Fatalf("the excluded peer must be REPORTABLE by name; got %d rows %v", len(bad), bad)
	}

	// ⛔ THE TWO PREDICATES MUST BE EXACT COMPLEMENTS. If they drift, a row could be in neither set —
	// excluded from the data plane AND invisible in the report, which is the worst of both.
	var total int
	if e := pool.QueryRow(ctx,
		`SELECT count(*) FROM devices WHERE node_id=$1 AND status='active' AND deleted_at IS NULL
		   AND public_key <> ''`, node).Scan(&total); e != nil {
		t.Fatal(e)
	}
	if len(got)+len(bad) != total {
		t.Fatalf("included(%d) + reported-excluded(%d) must equal all keyed devices(%d) — the predicates "+
			"have drifted and some row is in neither set", len(got), len(bad), total)
	}
}
