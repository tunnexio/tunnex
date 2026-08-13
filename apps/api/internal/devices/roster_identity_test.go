package devices

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestOVPNRosterHonorsOwnerIdentityParity is the review-#1 red (the epic's identity-binding invariant): a
// device credential is only valid for its owning user's ACTIVE, CURRENT-MEMBER identity — so the OpenVPN
// roster severs a deactivated / health-blocked / non-member owner's device exactly as the WireGuard peer
// query does. Parity: for the same user state, both transports give the same served-or-not answer.
func TestOVPNRosterHonorsOwnerIdentityParity(t *testing.T) {
	ctx, tx := txOrSkip(t)
	q := sqlc.New(tx)
	org, user, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed: %v", e)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')", org, "ri-"+org.String()[:8])
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", user, user.String()+"@t")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, user)
	ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'k','e:51820')", node, org, "cs-"+node.String()[:8])
	ovD, wgD := uuid.New(), uuid.New()
	ex("INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip,transport) VALUES ($1,$2,$3,$4,'ov',''::text,'10.99.0.6','openvpn')", ovD, org, user, node)
	ex("INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'wg', 'qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M=', '10.99.0.7')", wgD, org, user, node)

	ovpnServed := func() bool {
		rows, e := q.ListActiveOVPNDevicesForNode(ctx, node)
		if e != nil {
			t.Fatalf("ovpn roster: %v", e)
		}
		for _, r := range rows {
			if r.ID == ovD {
				return true
			}
		}
		return false
	}
	wgServed := func() bool {
		rows, e := q.ListActiveWireGuardPeersForNode(ctx, node)
		if e != nil {
			t.Fatalf("wg peers: %v", e)
		}
		for _, r := range rows {
			if r.AssignedIp != nil && *r.AssignedIp == "10.99.0.7" {
				return true
			}
		}
		return false
	}

	// Active member: BOTH transports serve (parity).
	if !ovpnServed() || !wgServed() {
		t.Fatalf("active member must be served on both transports; ovpn=%v wg=%v", ovpnServed(), wgServed())
	}

	// Deactivated owner: BOTH severed (the identity-binding parity — the defect was OVPN staying live).
	ex("UPDATE users SET status='deactivated' WHERE id=$1", user)
	if ovpnServed() {
		t.Fatal("deactivated owner: the OVPN device must leave the roster (was the defect)")
	}
	if wgServed() {
		t.Fatal("deactivated owner: the WG device must leave the peers (parity)")
	}

	// Reactivate, then health-block the OVPN device: severed.
	ex("UPDATE users SET status='active' WHERE id=$1", user)
	ex("UPDATE devices SET health_blocked=true WHERE id=$1", ovD)
	if ovpnServed() {
		t.Fatal("health_blocked owner's device must leave the OVPN roster")
	}
	ex("UPDATE devices SET health_blocked=false WHERE id=$1", ovD)

	// Removed member (non-member owner): severed (the memberships join, mirroring the policy compiler).
	ex("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", org, user)
	if ovpnServed() {
		t.Fatal("non-member owner: the OVPN device must leave the roster (memberships join)")
	}
}
