package policy

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"testing"
)

func TestPostgresStaticCNAMEProjectionAndDesktopCapability(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 229)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, site, node, user, device, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode) VALUES($1,'DNS projection',$2,'10.99.0.0/24','enforcing')`, org, "dns-"+org.String())
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'office')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'gateway',$3,$4,'{"max_policy_version":14}',clock_timestamp())`, node, org, node.String(), site)
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, user, user.String()+"@example.test")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, org, user)
	exec(`INSERT INTO devices(id,org_id,user_id,node_id,name,public_key,assigned_ip,full_tunnel) VALUES($1,$2,$3,$4,'desktop','ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=','10.99.0.7',false)`, device, org, user, node)
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'DNS callers')`, group, org)
	exec(`INSERT INTO group_members(org_id,group_id,user_id) VALUES($1,$2,$3)`, org, group, user)
	for _, proto := range []string{"udp", "tcp"} {
		resource := uuid.New()
		exec(`INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high) VALUES($1,$2,$3,'10.99.0.1/32',$3,53,53)`, resource, org, proto)
		exec(`INSERT INTO policy_rules(id,org_id,src_group_id,dst_kind,dst_resource_id) VALUES($1,$2,$3,'resource',$4)`, uuid.New(), org, group, resource)
	}
	_, err := fqdnresources.New(pool).SetResolverProfiles(ctx, org, site, node, uuid.Nil, "test", "CNAME projection", []fqdnresources.ResolverProfile{{Name: "Aliases", ProviderHint: "on_premises", ZoneSuffixes: []string{"office.test"}, StaticRecords: []fqdnresources.ResolverStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "outside.example", TTL: 300}}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "tcp"}}}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := sqlc.New(pool).ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 1 {
		t.Fatal("projection missing", err)
	}
	profile, err := DecodeIPsecDNSProfile(rows[0])
	if err != nil || len(profile.Profile.Endpoints) != 1 || profile.Profile.Endpoints[0].Address != "1.1.1.1" || profile.Profile.Endpoints[0].Transport != "tcp" || profile.TransportAvailable {
		t.Fatal("static endpoint changed or IPsec dependency introduced", profile, err)
	}
	svc := NewService(pool)
	check := func(want int) {
		t.Helper()
		forwards, err := svc.devicePrivateDNSForwards(ctx, org, device)
		if err != nil || len(forwards) != want {
			t.Fatalf("forwards=%+v want%d err=%v", forwards, want, err)
		}
		if want > 0 && (forwards[0].Domain != "office.test" || forwards[0].ResolverIP != "10.99.0.1") {
			t.Fatal("upstream exposed as desktop authority", forwards)
		}
	}
	check(1)
	for _, tc := range []struct {
		version int
		age     string
	}{{13, "0 seconds"}, {14, "91 seconds"}, {14, "-1 minute"}} {
		exec(`UPDATE nodes SET capabilities=jsonb_build_object('max_policy_version',$2::int),policy_reported_at=clock_timestamp()-$3::interval WHERE id=$1`, node, tc.version, tc.age)
		check(0)
	}
	exec(`UPDATE nodes SET capabilities='{"max_policy_version":14}',policy_reported_at=clock_timestamp() WHERE id=$1`, node)
	check(1)
	exec(`DELETE FROM group_members WHERE org_id=$1 AND user_id=$2`, org, user)
	check(0)
	snap, err := BuildSnapshotWithQueries(ctx, sqlc.New(pool), org)
	if err != nil {
		t.Fatal(err)
	}
	for _, pol := range Compile(snap) {
		for _, allow := range pol.Allow {
			if allow.DstCIDR != "10.99.0.1/32" {
				t.Fatal("DNS completion manufactured application access", allow)
			}
		}
	}
}
