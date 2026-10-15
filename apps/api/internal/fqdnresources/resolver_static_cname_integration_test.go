package fqdnresources

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"slices"
	"strings"
	"testing"
)

func TestPostgresStaticCNAMEEndpointLifecycleAndMigration(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 228)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, site, gateway := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'alias test',$2,'10.99.0.0/24')`, org, "cname-"+org.String())
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'office')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'gateway',$3,$4,'{"max_policy_version":14}',clock_timestamp())`, gateway, org, gateway.String(), site)
	svc := New(pool)
	p := cnameProfile()
	previous, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "baseline", []ResolverProfile{p})
	if err != nil {
		t.Fatal(err)
	}
	p.Endpoints = []ResolverEndpoint{{Address: "1.1.1.1", Port: 53, Transport: "udp"}}
	if _, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "pre migration", []ResolverProfile{p}); err == nil {
		t.Fatal("0228 no longer reproduces endpoint activation refusal")
	}
	up, _ := db.MigrationsFS.ReadFile("migrations/0229_static_dns_cname_endpoints.up.sql")
	down, _ := db.MigrationsFS.ReadFile("migrations/0229_static_dns_cname_endpoints.down.sql")
	exec(string(up))
	for _, tc := range []struct {
		version int
		age     string
	}{{13, "0 seconds"}, {14, "91 seconds"}, {14, "-1 minute"}} {
		exec(`UPDATE nodes SET capabilities=jsonb_build_object('max_policy_version',$2::int),policy_reported_at=clock_timestamp()-$3::interval WHERE id=$1`, gateway, tc.version, tc.age)
		if _, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "unsupported", []ResolverProfile{p}); err == nil {
			t.Fatal("unsupported gateway accepted")
		}
		retained, err := svc.ResolverConfig(ctx, org, site, gateway)
		if err != nil || retained.ID != previous.ID || retained.Version != previous.Version || len(retained.Profiles[0].Endpoints) != 0 {
			t.Fatal("old working profile retired", retained, err)
		}
	}
	exec(`UPDATE nodes SET capabilities='{"max_policy_version":14}',policy_reported_at=clock_timestamp() WHERE id=$1`, gateway)
	exec(`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'1.1.1.0/24','approved')`, uuid.New(), site)
	if _, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "local loop", []ResolverProfile{p}); err == nil {
		t.Fatal("locally routed public resolver accepted")
	}
	exec(`DELETE FROM site_subnets WHERE site_id=$1`, site)
	current, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "completion", []ResolverProfile{p})
	if err != nil {
		t.Fatal(err)
	}
	read, err := svc.ResolverConfig(ctx, org, site, gateway)
	if err != nil || read.ID != current.ID || !slices.Equal(read.Profiles[0].Endpoints, p.Endpoints) {
		t.Fatal("endpoint roundtrip", read, err)
	}
	shadowed := cnameProfile()
	shadowed.StaticRecords = append(shadowed.StaticRecords, ResolverStaticRecord{Name: "hidden.private.office.test", Type: "A", Value: "10.20.0.80", TTL: 300})
	narrow := ResolverProfile{Name: "Private", ProviderHint: "on_premises", ZoneSuffixes: []string{"private.office.test"}, StaticRecords: []ResolverStaticRecord{{Name: "owned.private.office.test", Type: "A", Value: "10.20.0.81", TTL: 300}}}
	if _, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "shadowed record", []ResolverProfile{shadowed, narrow}); err == nil || !strings.Contains(err.Error(), "shadowed_static_dns_record") {
		t.Fatal("shadowed activation did not return its safe ownership error", err)
	}
	read, err = svc.ResolverConfig(ctx, org, site, gateway)
	if err != nil || read.ID != current.ID || read.Version != current.Version || !slices.Equal(read.Profiles[0].Endpoints, p.Endpoints) {
		t.Fatal("shadowed activation replaced working configuration", err)
	}
	if _, err := pool.Exec(ctx, string(down)); err == nil || !strings.Contains(err.Error(), "refusing to roll back 0229") {
		t.Fatal("downgrade did not explicitly refuse active completion", err)
	}
	read, err = svc.ResolverConfig(ctx, org, site, gateway)
	if err != nil || read.ID != current.ID || !slices.Equal(read.Profiles[0].Endpoints, p.Endpoints) {
		t.Fatal("refused downgrade lost configuration", err)
	}
	if err := svc.DeleteResolverConfig(ctx, org, site, gateway, uuid.Nil, "test", "retire"); err != nil {
		t.Fatal(err)
	}
	exec(string(down))
	if _, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "old trigger", []ResolverProfile{p}); err == nil {
		t.Fatal("downgrade did not restore original endpoint restriction")
	}
	exec(string(up))
	if _, err := svc.SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "re-upgrade", []ResolverProfile{p}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resolver_context_profile_endpoints WHERE profile_id=$1`, current.Profiles[0].ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("history lost across roundtrip", count, err)
	}
}
