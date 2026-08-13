package tenancy

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestDeactivationRevokesOVPNCertsAndReactivationRestoresThem drives the REAL verbs against a REAL database.
//
// ⛔ THE COMPANION SOURCE TEST PROVES A CALL EXISTS; THIS PROVES THE CALL DOES SOMETHING. A query that
// selected the wrong user's certs, or matched no rows because of a join typo, would satisfy the source test
// completely — it would still be a deactivation that revokes nothing.
func TestDeactivationRevokesOVPNCertsAndReactivationRestoresThem(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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

	org, actor, target, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	dev, devOther, node := uuid.New(), uuid.New(), uuid.New()
	for _, s := range [][]any{
		{"INSERT INTO organizations (id,name,slug) VALUES ($1,$2,$3)", org, "O", "crl-" + org.String()},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", actor, actor.String() + "@t", "A"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", target, target.String() + "@t", "T"},
		{"INSERT INTO users (id,email,name) VALUES ($1,$2,$3)", other, other.String() + "@t", "O"},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, target},
		{"INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, other},
		{"INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'k','e:51820')", node, org, "crl-" + node.String()[:8]},
		{"INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,status) VALUES ($1,$2,$3,$4,'d','pk-crl-1','active')", dev, org, target, node},
		{"INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,status) VALUES ($1,$2,$3,$4,'d','pk-crl-2','active')", devOther, org, other, node},
		// the target's live cert, and a BYSTANDER on another member's device
		{"INSERT INTO ovpn_client_certs (org_id,device_id,serial,common_name,not_after) VALUES ($1,$2,'AA01','cn1',now()+interval '1 year')", org, dev},
		{"INSERT INTO ovpn_client_certs (org_id,device_id,serial,common_name,not_after) VALUES ($1,$2,'AA02','cn2',now()+interval '1 year')", org, devOther},
		// ⚠ AND A CERT REVOKED FOR A DIFFERENT REASON, on the target's own device. Reactivation must NOT
		// revive this one: a cascade cert is revived by a GATEWAY restore, and a deliberate revoke by nobody.
		{"INSERT INTO ovpn_client_certs (org_id,device_id,serial,common_name,not_after,revoked_at,revoked_cause) VALUES ($1,$2,'AA03','cn3',now()+interval '1 year',now(),'cascade')", org, dev},
	} {
		if _, err := tx.Exec(ctx, s[0].(string), s[1:]...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	revoked := func(serial string) bool {
		var r *time.Time
		if err := tx.QueryRow(ctx, "SELECT revoked_at FROM ovpn_client_certs WHERE serial=$1", serial).Scan(&r); err != nil {
			t.Fatalf("read %s: %v", serial, err)
		}
		return r != nil
	}

	svc := &MembershipService{q: q} // tx-scoped; nil crl/revoker/pusher are skipped
	if err := svc.DeactivateMember(ctx, actor, org, target); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	// ⛔ THE POINT OF THE CHANGE: the cert is revoked in the control plane, not merely refused by a config
	// flag on a remote gateway.
	if !revoked("AA01") {
		t.Fatal("deactivated user's OVPN cert is still live — the refusal rests entirely on ccd-exclusive " +
			"in the agent's server.conf, which is one mechanism on a remote box, not defence in depth")
	}
	// ⚠ AND IT IS SCOPED. A revoke that caught the whole org would pass the assertion above and take every
	// other member offline — the blast-radius failure, which reads as success from the target's side.
	if revoked("AA02") {
		t.Fatal("deactivating one user revoked ANOTHER member's cert — the revoke is not user-scoped")
	}

	if err := svc.ReactivateMember(ctx, actor, org, target); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if revoked("AA01") {
		t.Fatal("reactivated user's cert is still on the CRL — a one-way door: active in the control plane, " +
			"refused in the data plane, and the operator was told it succeeded")
	}
	if !revoked("AA03") {
		t.Fatal("reactivation revived a cert revoked by CASCADE — reactivation must reverse its own act and " +
			"no one else's, or a returning user silently un-revokes a gateway's cascade")
	}
}
