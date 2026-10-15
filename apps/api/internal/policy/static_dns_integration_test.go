package policy_test

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"testing"
)

func TestPostgresStaticLANProjectionRevocationAndTenantScope(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 228)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, site, gateway, subnet := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'static DNS',$2,'10.99.0.0/24')`, org, "dns-"+org.String())
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'office')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, "dns-"+gateway.String(), site)
	exec(`UPDATE nodes SET capabilities='{"max_policy_version":13}'::jsonb,policy_reported_at=clock_timestamp() WHERE id=$1`, gateway)
	exec(`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'192.168.1.0/24','approved')`, subnet, site)
	cfg, err := fqdnresources.New(pool).SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "static DNS projection", []fqdnresources.ResolverProfile{{Name: "Office", ProviderHint: "on_premises", ZoneSuffixes: []string{"office.test"}, StaticRecords: []fqdnresources.ResolverStaticRecord{{Name: "app.office.test", Type: "A", Value: "10.20.0.80", TTL: 300}}, LANListener: &fqdnresources.ResolverLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: []string{"1.1.1.1"}}}})
	if err != nil {
		t.Fatal(err)
	}
	q := sqlc.New(pool)
	rows, err := q.ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 1 {
		t.Fatal("static profile omitted without IPsec", err, len(rows))
	}
	profile, err := policy.DecodeIPsecDNSProfile(rows[0])
	if err != nil || len(profile.Profile.StaticRecords) != 1 || profile.Profile.LANListener == nil || len(profile.Profile.LANListener.DefaultUpstreams) != 1 || profile.TransportAvailable {
		t.Fatal("static/LAN projection", err, profile)
	}
	foreign, err := q.ListIPsecDNSResolverProfiles(ctx, uuid.New())
	if err != nil || len(foreign) != 0 {
		t.Fatal("tenant DNS leaked", err)
	}
	exec(`UPDATE site_subnets SET status='pending' WHERE id=$1`, subnet)
	rows, err = q.ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 1 {
		t.Fatal("subnet revocation destroyed independent static profile", err)
	}
	profile, err = policy.DecodeIPsecDNSProfile(rows[0])
	if err != nil || profile.Profile.LANListener != nil || len(profile.Profile.StaticRecords) != 1 {
		t.Fatal("revoked subnet kept LAN authorization", err)
	}
	exec(`UPDATE site_subnets SET status='approved' WHERE id=$1`, subnet)
	exec(`UPDATE nodes SET site_id=NULL WHERE id=$1`, gateway)
	rows, err = q.ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 0 {
		t.Fatal("site-unbound gateway kept DNS authority", err)
	}
	exec(`UPDATE nodes SET site_id=$2 WHERE id=$1`, gateway, site)
	if err := fqdnresources.New(pool).DeleteResolverConfig(ctx, org, site, gateway, uuid.Nil, "test", "retirement"); err != nil {
		t.Fatal(err)
	}
	rows, err = q.ListIPsecDNSResolverProfiles(ctx, org)
	if err != nil || len(rows) != 0 {
		t.Fatal("retired context kept DNS authority", cfg.ID, err)
	}
}
