package nodes

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// TestRevokeRefusesWhileDevicesAreHomedThere — S12.12 D1, the half that makes the transfer unskippable.
//
// ⛔ THE DEFECT THIS CLOSES IS THE ONE THE FOUNDER MET. He revoked a gateway and his device read `revoked`,
// which he had not done. RevokeDevicesForNode runs inside the revoke's own transaction and sweeps every
// active and pending device homed there, and a revoked gateway is never active again — so the operator's
// only remedy was an endpoint they did not know existed, on a fleet that was already offline.
//
// ⚠ A WARNING THAT COUNTED THE DEVICES WAS THE FIRST ANSWER AND IT WAS NOT ENOUGH. A confirm dialog stating
// the cost still lets an operator proceed straight into the outage; a refusal makes the move a precondition
// rather than a suggestion, and that is the difference between telling someone the cost and not charging it.
//
// ⭐ AND THE REFUSAL NAMES THE COUNT, because a blocked operator's next question is "how many?" and a refusal
// that withholds the figure they need is a refusal they will route around.
func TestRevokeRefusesWhileDevicesAreHomedThere(t *testing.T) {
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

	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'R',$2,'10.94.0.0/24')`, org, "r-"+org.String()[:8])
	ex(`INSERT INTO users (id,email) VALUES ($1,$2)`, owner, "rv-"+owner.String()[:8]+"@ex.com")
	ex(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, owner)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,$3,$4)`,
		node, org, "gw-"+node.String()[:8], "s-"+node.String()[:8])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org) })

	addDevice := func(name, ip, status string) uuid.UUID {
		id := uuid.New()
		ex(`INSERT INTO devices (id,org_id,user_id,node_id,name,platform,public_key,assigned_ip,status,transport)
		    VALUES ($1,$2,$3,$4,$5,'linux',$6,$7,$8,'wireguard')`,
			id, org, owner, node, name, "wyUOtRkANy0utrYJb0R6aVOh5WJX375rarRrmwGBwW4="+id.String(), ip, status)
		return id
	}
	svc := NewService(pool, nil, nil)

	active := addDevice("laptop", "10.94.0.10", "active")
	// PENDING COUNTS TOO, because the cascade sweeps pending too (D4). A count narrower than the sweep it
	// guards would let a revoke through that still disconnects someone — the guard and the act must define
	// "live" identically, which is why both read the same predicate.
	pending := addDevice("phone", "10.94.0.11", "pending")

	err = svc.Revoke(ctx, owner, org, node)
	if err == nil {
		t.Fatal("revoking a gateway with live devices homed on it must be REFUSED — the cascade is permanent " +
			"and there is no un-revoke")
	}
	var ae *apierr.Error
	if !asAPIErr(err, &ae) {
		t.Fatalf("the refusal must be a typed API error the surface can act on, got %T: %v", err, err)
	}
	if ae.Code != "devices_still_homed" {
		t.Fatalf("the refusal needs its OWN code — the UI has exactly one correct response to it (offer the "+
			"move) and none to a generic conflict. got %q", ae.Code)
	}
	if !strings.Contains(ae.Message, "2 devices are") {
		t.Fatalf("the refusal must NAME THE COUNT: %q", ae.Message)
	}
	// ⛔ AND NOTHING WAS REVOKED. A refusal that had already cascaded would be the worst of both — the outage
	// happened and the operator was told it did not.
	var nodeRevoked, deviceRevoked int
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE id=$1 AND revoked_at IS NOT NULL", node).
		Scan(&nodeRevoked); e != nil {
		t.Fatal(e)
	}
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM devices WHERE id = ANY($1) AND status='revoked'",
		[]uuid.UUID{active, pending}).Scan(&deviceRevoked); e != nil {
		t.Fatal(e)
	}
	if nodeRevoked != 0 || deviceRevoked != 0 {
		t.Fatalf("the refusal must roll back the whole transaction: node_revoked=%d devices_revoked=%d",
			nodeRevoked, deviceRevoked)
	}

	// ⭐ AND THE REFUSAL LIFTS ONCE THE DEVICES ARE GONE, or it would be a permanent block rather than an
	// ordering constraint. This is the state the transfer produces.
	other := uuid.New()
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial) VALUES ($1,$2,$3,$4)`,
		other, org, "gw2-"+other.String()[:8], "s2-"+other.String()[:8])
	ex(`UPDATE devices SET node_id=$2 WHERE id = ANY($1)`, []uuid.UUID{active, pending}, other)
	if err := svc.Revoke(ctx, owner, org, node); err != nil {
		t.Fatalf("with nothing homed there the revoke must proceed: %v", err)
	}
}

// asAPIErr is errors.As with the concrete type spelled out, kept local so the assertion above reads as one
// question rather than three lines of plumbing.
func asAPIErr(err error, target **apierr.Error) bool {
	e, ok := err.(*apierr.Error)
	if ok {
		*target = e
	}
	return ok
}

// TestDeleteAndRenameACompletedRetirement — S12.12 D2 and D3, driven in the order the product enforces.
//
// ⛔ THE SEQUENCE IS THE SAFETY ARGUMENT FOR THE DELETE, so the test walks it rather than asserting the
// delete in isolation. Devices homed there → revoke refused. Devices moved → revoke proceeds. Node revoked
// → delete permitted, and its enrolment token goes with it. A delete tested against a hand-made revoked row
// would pass while proving nothing about whether that state is reachable safely.
func TestDeleteAndRenameACompletedRetirement(t *testing.T) {
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

	org, owner, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed %q: %v", sql, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'D',$2,'10.93.0.0/24')`, org, "d-"+org.String()[:8])
	ex(`INSERT INTO users (id,email) VALUES ($1,$2)`, owner, "dl-"+owner.String()[:8]+"@ex.com")
	ex(`INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'owner')`, org, owner)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,endpoint) VALUES ($1,$2,'gw-typpo',$3,'gw.example.com:51820')`,
		node, org, "s-"+node.String()[:8])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM organizations WHERE id=$1", org) })
	svc := NewService(pool, nil, nil)

	// D3 — THE TYPO IS CORRECTABLE, which it was not before: enrolment is a CLI act and the name it supplies
	// was written once and never again.
	renamed, err := svc.RenameNode(ctx, owner, org, node, "  gw-london  ")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Name != "gw-london" {
		t.Fatalf("rename must trim: %q", renamed.Name)
	}
	// ⛔ AND THE ENDPOINT SURVIVED THE RENAME. UpdateNodeIdentity edits both fields behind COALESCE and the
	// rename passes nil for the endpoint — so this asserts the nil means "leave it" rather than "blank it".
	// Silently clearing the one field D3 deliberately did NOT ship would be the worst possible outcome of
	// not shipping it: every peer holds that endpoint and every issued config bakes it.
	if renamed.Endpoint != "gw.example.com:51820" {
		t.Fatalf("a rename must not touch the endpoint: %q", renamed.Endpoint)
	}
	if _, err := svc.RenameNode(ctx, owner, org, node, "   "); err == nil {
		t.Fatal("an all-whitespace name must be refused, not stored — it is how an operator tells one " +
			"gateway from another on every screen")
	}

	// ⛔ A LIVE GATEWAY CANNOT BE DELETED. Its devices cascade, and that cascade is only harmless because the
	// revoke already refused while any were homed there.
	if err := svc.DeleteRevokedNode(ctx, owner, org, node); err == nil {
		t.Fatal("deleting a LIVE gateway must be refused — the cascade would be a silent outage with no " +
			"revoked rows left behind to explain it")
	}

	// The enrolment token that produced this gateway, which must not outlive it.
	ex(`INSERT INTO node_join_tokens (token_hash,org_id,node_name,expires_at,consumed_node_id)
	    VALUES ($1,$2,'gw-london',now() + interval '1 day',$3)`, "hash-"+node.String()[:8], org, node)

	if err := svc.Revoke(ctx, owner, org, node); err != nil {
		t.Fatalf("revoke with nothing homed there: %v", err)
	}
	if err := svc.DeleteRevokedNode(ctx, owner, org, node); err != nil {
		t.Fatalf("delete a revoked gateway: %v", err)
	}
	var nodes, tokens int
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM nodes WHERE id=$1", node).Scan(&nodes); e != nil {
		t.Fatal(e)
	}
	if e := pool.QueryRow(ctx, "SELECT count(*) FROM node_join_tokens WHERE org_id=$1", org).Scan(&tokens); e != nil {
		t.Fatal(e)
	}
	if nodes != 0 {
		t.Fatal("the gateway row must be gone")
	}
	// ⛔ D2 — THE TOKEN GOES WITH IT. `consumed_node_id` is ON DELETE SET NULL, so without the deliberate
	// cleanup the token would survive UNLINKED and still enrol a gateway. That is the finding: the FK would
	// have left a working credential behind for a gateway an operator believes they destroyed.
	if tokens != 0 {
		t.Fatal("the enrolment token must be cleaned with the delete, not orphaned by ON DELETE SET NULL")
	}
	// And the audit row survives the row it describes, carrying the NAME — the only form of the question
	// anyone asks afterwards.
	var withName int
	if e := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='node.deleted' AND metadata->>'name'='gw-london'`,
		org).Scan(&withName); e != nil {
		t.Fatal(e)
	}
	if withName != 1 {
		t.Fatalf("the delete's audit row must name the gateway; after the delete there is nothing left to "+
			"join against. got %d", withName)
	}
}
