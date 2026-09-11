package aigateway

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"testing"
)

func TestVPNModelChecksCurrentDeviceAndUserGrant(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	f := newPolicyFixture(t, ctx, pool)
	f.policies.engine = newProviderFixtureEngine()
	f.policies.EnableProviderManagement(true)
	secret := "fixture-secret"
	p, err := f.policies.CreateProvider(ctx, f.org, f.owner, ProviderInput{Provider: "openrouter", Name: "VPN provider", Models: []string{"openrouter/vpn"}, Secret: &secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	var node uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT node_id FROM devices WHERE org_id=$1 AND id=$2`, f.org, f.device).Scan(&node); err != nil {
		t.Fatal(err)
	}
	if err := f.policies.ConfigureVPNIngress("internal.test", node.String(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	user, device, group := uuid.New(), uuid.New(), uuid.New()
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	f.exec(`INSERT INTO users(id,email,email_verified_at) VALUES($1,$2,now())`, user, user.String()+"@test.local")
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, f.org, user)
	f.exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,status,kind) VALUES($1,$2,$3,$4,'VPN user',$5,'10.99.0.2','active','human')`, device, f.org, user, node, key)
	f.exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'VPN group')`, group, f.org)
	f.exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, f.org, group, user)
	g, err := f.policies.PutUserModelGrant(ctx, f.org, f.owner, group, p.ID, "openrouter/vpn", true, 0)
	if err != nil || g.Status != "applied" {
		t.Fatalf("grant=%v err=%v", g, err)
	}
	call := func() error {
		v, err := f.policies.ResolveVPNModel(ctx, f.org, node, "10.99.0.2", key, g.Model)
		if err == nil && (v.SubjectKind != "user" || v.Agent != user.String() || v.VirtualKey == "") {
			t.Fatal("incorrect identity")
		}
		return err
	}
	if f.policies.VPNDeviceIngress(ctx, f.org, device, user) == nil {
		t.Fatal("missing device-specific DNS")
	}
	if f.policies.VPNDeviceIngress(ctx, f.org, device, f.owner) != nil {
		t.Fatal("DNS disclosed to non-owner")
	}
	if err := call(); err != nil {
		t.Fatalf("authorized VPN user: %v", err)
	}
	alias := func() error {
		_, err := f.policies.ResolveSingleOrgVPNModel(ctx, f.org, node, "10.99.0.2", key, g.Model)
		return err
	}
	if err := alias(); err != nil {
		t.Fatalf("single membership alias: %v", err)
	}
	other := newPolicyFixture(t, ctx, pool)
	f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, other.org, user)
	if err := alias(); err == nil {
		t.Fatal("alias guessed an organization for a multi-org user")
	}
	if err := call(); err != nil {
		t.Fatalf("explicit organization must remain usable: %v", err)
	}
	f.exec(`UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, other.org, user)
	if err := alias(); err != nil {
		t.Fatalf("revoked membership must not block alias: %v", err)
	}
	for _, tc := range []struct {
		name           string
		org, node      uuid.UUID
		ip, key, model string
	}{
		{"wrong-org", uuid.New(), node, "10.99.0.2", key, g.Model}, {"wrong-node", f.org, uuid.New(), "10.99.0.2", key, g.Model},
		{"wrong-ip", f.org, node, "10.99.0.3", key, g.Model}, {"wrong-key", f.org, node, "10.99.0.2", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", g.Model},
		{"wrong-model", f.org, node, "10.99.0.2", key, "openrouter/other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.policies.ResolveVPNModel(ctx, tc.org, tc.node, tc.ip, tc.key, tc.model); err == nil {
				t.Fatal("invalid peer allowed")
			}
		})
	}
	for _, tc := range []struct{ name, set, restore string }{
		{"revoked", "status='revoked'", "status='active'"}, {"posture", "health_blocked=true", "health_blocked=false"}, {"agent", "kind='agent'", "kind='human'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.exec("UPDATE devices SET "+tc.set+" WHERE org_id=$1 AND id=$2", f.org, device)
			if call() == nil {
				t.Fatal("invalid device allowed")
			}
			f.exec("UPDATE devices SET "+tc.restore+" WHERE org_id=$1 AND id=$2", f.org, device)
		})
	}
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, f.org, group, user)
	if call() == nil {
		t.Fatal("removed grant allowed")
	}
}
