package devices

import (
	"testing"

	"github.com/google/uuid"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// TestOffboardingSeversPeerAndCompilerParity is the hotfix red for the WG-peer membership gap: a device
// credential is only valid for its owning user's CURRENT-MEMBER identity, so REMOVING a member severs
// their WireGuard device from every node's peer set — not only the compiled enterprise policy. This is the
// identity-binding invariant's home: the policy compiler (ListActiveDevicesForOrg, the reference impl) and
// the open-edition WG peer query (ListActiveWireGuardPeersForNode) answer IDENTICALLY for the same membership state.
// (The OpenVPN roster is the third consumer of the same invariant, added in S9.1.)
func TestOffboardingSeversPeerAndCompilerParity(t *testing.T) {
	ctx, tx := txOrSkip(t)
	q := sqlc.New(tx)
	org, user, node := uuid.New(), uuid.New(), uuid.New()
	ex := func(sql string, args ...any) {
		if _, e := tx.Exec(ctx, sql, args...); e != nil {
			t.Fatalf("seed: %v", e)
		}
	}
	ex("INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'O',$2,'10.99.0.0/24')", org, "ob-"+org.String()[:8])
	ex("INSERT INTO users (id,email,name,status) VALUES ($1,$2,'U','active')", user, user.String()+"@t")
	ex("INSERT INTO memberships (org_id,user_id,role) VALUES ($1,$2,'member')", org, user)
	ex("INSERT INTO nodes (id,org_id,name,cert_serial,wg_public_key,endpoint) VALUES ($1,$2,'gw',$3,'k','e:51820')", node, org, "cs-"+node.String()[:8])
	dev := uuid.New()
	ex("INSERT INTO devices (id,org_id,user_id,node_id,name,public_key,assigned_ip) VALUES ($1, $2, $3, $4, 'wg', 'qz/uIHKyeTmf08TjUpwbMLlBr78PS+fKYl33OGdZU+M=', '10.99.0.7')", dev, org, user, node)

	peerServed := func() bool {
		rows, e := q.ListActiveWireGuardPeersForNode(ctx, node)
		if e != nil {
			t.Fatalf("peers: %v", e)
		}
		for _, r := range rows {
			if r.AssignedIp != nil && *r.AssignedIp == "10.99.0.7" {
				return true
			}
		}
		return false
	}
	compilerServed := func() bool {
		rows, e := q.ListActiveDevicesForOrg(ctx, org)
		if e != nil {
			t.Fatalf("compiler input: %v", e)
		}
		for _, r := range rows {
			if r.ID == dev {
				return true
			}
		}
		return false
	}

	// Active member: BOTH consumers serve (parity).
	if !peerServed() || !compilerServed() {
		t.Fatalf("active member must be served by both consumers; peer=%v compiler=%v", peerServed(), compilerServed())
	}

	// Remove the member (hard-delete the membership — the offboarding path): BOTH sever (the guarantee
	// RemoveMember's comment claims, now true for the open-edition WG peer set, not only the compiled policy).
	ex("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", org, user)
	if peerServed() {
		t.Fatal("removed member: the WG device must leave the peer set (offboarding fail-to-sever was the defect)")
	}
	if compilerServed() {
		t.Fatal("removed member: the device must leave the compiler input (parity — both consumers sever)")
	}
}
