package fqdnresolver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestStaticProfileMaterializesOnlyCurrentTenantGeneration(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, site, gateway, config, profile, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'static test',$2,'10.249.0.0/24',true)`, org, "static-"+org.String())
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'static gateway',$3,$4)`, gateway, org, "static-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'web','web.test.internal',$3,$4)`, resource, org, site, gateway)
	records := []StaticRecord{{"web.test.internal", "A", "10.180.10.229", 60}}
	data, _ := json.Marshal(records)
	// The activation constraint is deferred: stage a complete revision atomically.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, []any{config, org, site, gateway}},
		{`INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint,static_records) VALUES($1,$2,$3,0,'Static','on_premises',$4)`, []any{profile, config, org, data}},
		{`INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,'test.internal')`, []any{profile, config, org}},
	} {
		if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	store := NewPostgresStore(pool)
	due, err := store.Due(ctx, time.Now(), 10)
	if err != nil || len(due) != 1 || len(due[0].ResolverConfig.StaticRecords) != 1 || len(due[0].ResolverConfig.Endpoints) != 0 {
		t.Fatalf("static work missing: %+v %v", due, err)
	}
	rpc := &scopedFixtureResolver{}
	s := NewScheduler(store, rpc, SchedulerConfig{})
	s.Tick(ctx)
	active, err := store.ActiveGenerations(ctx, org)
	if err != nil || len(active) != 1 || active[0].Addresses[0].String() != "10.180.10.229" || len(active[0].ResolverConfig.StaticRecords) != 1 || rpc.got.Hostname != "" {
		t.Fatalf("static generation=%+v err=%v rpc=%+v", active, err, rpc)
	}
	if other, err := store.ActiveGenerations(ctx, uuid.New()); err != nil || len(other) != 0 {
		t.Fatal("cross tenant static generation")
	}
	exec(`UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE id=$1`, config)
	if active, err := store.ActiveGenerations(ctx, org); err != nil || len(active) != 0 {
		t.Fatal("retired static authority remained active", err)
	}
	if err := store.Publish(ctx, due[0], Generation{TTL: time.Minute, ResolvedAt: time.Now(), Addresses: active[0].Addresses}); err == nil {
		t.Fatal("stale worker published retired profile")
	}
}
