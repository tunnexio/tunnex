package aigateway

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"testing"
)

func TestProposalAutomaticVPNIdentityAndDiscovery(t *testing.T) {
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

	f.policies.ConfigureAutomaticVPNIngress(true)
	ready := func() {
		f.exec(`UPDATE nodes SET status='active',revoked_at=NULL,capabilities='{"ai_vpn_http_ready":true,"ai_vpn_http_address":"10.99.0.1"}',policy_reported_at=now() WHERE org_id=$1 AND id=$2`, f.org, node)
	}
	ready()
	call := func() error {
		_, err := f.policies.ResolveAutomaticVPNModel(ctx, f.org, node, "10.99.0.2", key, g.Model, false)
		return err
	}
	wantURL := "http://10.99.0.1:8083/ai/v1"
	assertReady := func() {
		t.Helper()
		if err := call(); err != nil {
			t.Fatalf("valid VPN peer denied: %v", err)
		}
		u, err := f.policies.AutomaticVPNBaseURL(ctx, f.org, user)
		if err != nil || u != wantURL {
			t.Fatalf("endpoint=%q err=%v", u, err)
		}
	}
	assertUnavailable := func() {
		t.Helper()
		if call() == nil {
			t.Fatal("invalid state authorized")
		}
		u, err := f.policies.AutomaticVPNBaseURL(ctx, f.org, user)
		if err != nil || u != "" {
			t.Fatalf("invalid state advertised %q (%v)", u, err)
		}
	}
	assertReady()
	t.Run("short-url-follows-current-single-organization-guard", func(t *testing.T) {
		alias := func() error {
			_, err := f.policies.ResolveAutomaticVPNModel(ctx, f.org, node, "10.99.0.2", key, g.Model, true)
			return err
		}
		if err := alias(); err != nil {
			t.Fatalf("single-organization alias denied: %v", err)
		}
		otherOrg := uuid.New()
		f.exec(`INSERT INTO organizations(id,name,slug) VALUES($1,'Other',$2)`, otherOrg, otherOrg.String())
		f.exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, otherOrg, user)
		wantURL = "http://10.99.0.1:8083/api/v1/organizations/" + f.org.String() + "/ai-gateway/inference/v1"
		assertReady() // Explicit organization access remains valid.
		if alias() == nil {
			t.Fatal("short alias selected an organization for a multi-organization user")
		}
		f.exec(`UPDATE memberships SET access_revoked_at=now() WHERE org_id=$1 AND user_id=$2`, otherOrg, user)
		wantURL = "http://10.99.0.1:8083/ai/v1"
		assertReady()
		if err := alias(); err != nil {
			t.Fatalf("revoked membership kept alias unavailable: %v", err)
		}
		f.exec(`UPDATE memberships SET access_revoked_at=NULL WHERE org_id=$1 AND user_id=$2`, otherOrg, user)
		f.exec(`UPDATE organizations SET deleted_at=now() WHERE id=$1`, otherOrg)
		assertReady()
		if err := alias(); err != nil {
			t.Fatalf("deleted organization kept alias unavailable: %v", err)
		}
		f.exec(`DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, otherOrg, user)
	})
	if u, err := f.policies.AutomaticVPNBaseURL(ctx, f.org, f.owner); err != nil || u != "" {
		t.Fatal("another user's device disclosed")
	}
	f.policies.ConfigureAutomaticVPNIngress(false)
	assertUnavailable()
	f.policies.ConfigureAutomaticVPNIngress(true)
	for _, caps := range []string{`{}`, `{"ai_vpn_http_ready":false,"ai_vpn_http_address":"10.99.0.1"}`, `{"ai_vpn_http_ready":true,"ai_vpn_http_address":"10.99.0.2"}`, `{"ai_vpn_http_ready":true,"ai_vpn_http_address":"8.8.8.8"}`, `{"ai_vpn_http_ready":true,"ai_vpn_http_address":"http://10.99.0.1"}`, `{"ai_vpn_http_ready":"true","ai_vpn_http_address":"10.99.0.1"}`} {
		f.exec(`UPDATE nodes SET capabilities=$3 WHERE org_id=$1 AND id=$2`, f.org, node, caps)
		assertUnavailable()
	}
	ready()
	for _, stamp := range []string{"now()-interval '91 seconds'", "NULL", "now()+interval '1 minute'"} {
		f.exec("UPDATE nodes SET policy_reported_at="+stamp+",last_seen_at=now() WHERE org_id=$1 AND id=$2", f.org, node)
		assertUnavailable()
	}
	ready()
	for _, tc := range []struct {
		table, where, set, restore string
		id                         uuid.UUID
	}{
		{"nodes", "id", "status='revoked',revoked_at=now()", "status='active',revoked_at=NULL", node},
		{"devices", "id", "status='revoked'", "status='active'", device},
		{"devices", "id", "health_blocked=true", "health_blocked=false", device},
		{"devices", "id", "kind='agent'", "kind='human'", device},
		{"devices", "id", "deleted_at=now()", "deleted_at=NULL", device},
		{"users", "id", "status='deactivated'", "status='active'", user},
		{"users", "id", "email_verified_at=NULL", "email_verified_at=now()", user},
		{"memberships", "user_id", "access_revoked_at=now()", "access_revoked_at=NULL", user},
		{"organizations", "id", "ai_gateway_enabled=false", "ai_gateway_enabled=true", f.org},
	} {
		t.Run(tc.table+tc.set, func(t *testing.T) {
			f.exec("UPDATE "+tc.table+" SET "+tc.set+" WHERE "+tc.where+"=$1", tc.id)
			assertUnavailable()
			f.exec("UPDATE "+tc.table+" SET "+tc.restore+" WHERE "+tc.where+"=$1", tc.id)
		})
	}
	assertReady()
	for _, tc := range []struct {
		org, node      uuid.UUID
		ip, key, model string
	}{
		{uuid.New(), node, "10.99.0.2", key, g.Model}, {f.org, uuid.New(), "10.99.0.2", key, g.Model},
		{f.org, node, "10.99.0.3", key, g.Model}, {f.org, node, "10.99.0.2", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", g.Model},
		{f.org, node, "10.99.0.2", key, "openrouter/other"},
	} {
		if _, err := f.policies.ResolveAutomaticVPNModel(ctx, tc.org, tc.node, tc.ip, tc.key, tc.model, false); err == nil {
			t.Fatal("wrong org/node/peer/model accepted")
		}
	}
	// Enabling automatic HTTP never widens the manually configured TLS node allowlist.
	if err := f.policies.ConfigureVPNIngress("internal.test", uuid.NewString(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.policies.ResolveVPNModel(ctx, f.org, node, "10.99.0.2", key, g.Model); err == nil {
		t.Fatal("automatic mode bypassed manual TLS gateway pin")
	}
	assertReady()
	if err := f.policies.ConfigureVPNIngress("internal.test", node.String(), "10.99.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.policies.ResolveVPNModel(ctx, f.org, node, "10.99.0.2", key, g.Model); err != nil {
		t.Fatalf("legacy TLS regression: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.policies.ResolveAutomaticVPNModel(cancelled, f.org, node, "10.99.0.2", key, g.Model, false); err == nil {
		t.Fatal("failed database read allowed")
	}
	f.exec(`DELETE FROM group_members WHERE org_id=$1 AND group_id=$2 AND user_id=$3`, f.org, group, user)
	if call() == nil {
		t.Fatal("removed model grant still authorized")
	}
}
