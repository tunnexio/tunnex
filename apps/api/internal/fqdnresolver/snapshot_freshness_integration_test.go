package fqdnresolver

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Real publication and immutable history in a dedicated child database only.
// No scheduler tick is needed to exclude an active row past its original TTL.
func TestActiveGenerationsOriginalDatabaseClockFreshness(t *testing.T) {
	ctx, pool := testpostgres.New(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal("owned freshness fixture statement refused", err)
		}
	}
	org, site, gateway, config, profile := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'freshness',$2,'10.249.0.0/24',true)`, org, "freshness-"+org.String())
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'freshness-gateway',$3,$4)`, gateway, org, "freshness-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint) VALUES($1,$2,$3,0,'Private DNS','azure')`, profile, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,'private.test')`, profile, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profile_endpoints(profile_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53',53,'udp')`, profile, org)
	store := NewPostgresStore(pool)
	newWork := func(name string) Work {
		t.Helper()
		resource := uuid.New()
		hostname := name + ".private.test"
		exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,$3,$4,$5,$6)`, resource, org, name, hostname, site, gateway)
		return Work{OrgID: org, ResourceID: resource, Hostname: hostname, Context: Context{ResolverID: site.String(), GatewayID: gateway.String()}, ResolverConfig: ResolverConfig{ID: config.String(), Version: 1, ProfileID: profile.String(), ProfileName: "Private DNS", ProfileProvider: "azure", MatchedSuffix: "private.test", Endpoints: []ResolverEndpoint{{Address: addr("10.53.0.53"), Port: 53, Transport: "udp"}}}}
	}
	clock := func() time.Time {
		t.Helper()
		var now time.Time
		if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal("read actual database clock", err)
		}
		return now
	}
	expected := map[uuid.UUID]int64{}
	check := func() {
		t.Helper()
		rows, err := store.ActiveGenerations(ctx, org)
		if err != nil || len(rows) != len(expected) {
			t.Fatalf("exact fresh projection count=%d want=%d error=%v", len(rows), len(expected), err)
		}
		for _, g := range rows {
			if expected[g.ResourceID] != g.Sequence || g.Context.ResolverID != site.String() || g.Context.GatewayID != gateway.String() || g.ResolverConfig.ProfileID != profile.String() {
				t.Fatal("fresh projection borrowed or superseded context")
			}
		}
		if rows, err := store.ActiveGenerations(ctx, uuid.New()); err != nil || len(rows) != 0 {
			t.Fatal("freshness projection crossed organization")
		}
	}
	for _, tc := range []struct {
		name  string
		delta time.Duration
		zero  bool
		fresh bool
	}{
		{"fresh", 0, false, true}, {"expired", -2 * time.Hour, false, false}, {"future", 5 * time.Minute, false, false}, {"zero", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWork(tc.name)
			at := clock().Add(tc.delta)
			if tc.zero {
				at = time.Time{}
			}
			if err := store.Publish(ctx, w, Generation{TTL: time.Minute, ResolvedAt: at, Addresses: []netip.Addr{addr("10.2.3.4")}}); err != nil {
				t.Fatal("actual publication refused", err)
			}
			if tc.fresh {
				expected[w.ResourceID] = 1
			}
			check()
			var active int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, w.ResourceID).Scan(&active); err != nil || active != 1 {
				t.Fatal("projection modified durable publication state")
			}
		})
	}
	// Explicit malformed historical fixtures stay immutable once promoted. They
	// are negative data, never claimed to be actual resolver observations.
	for _, text := range []string{"infinity", "-infinity"} {
		name := "positive-infinity"
		if text == "-infinity" {
			name = "negative-infinity"
		}
		w := newWork(name)
		generation := uuid.New()
		exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,resolver_profile_id,resolver_match_suffix,state,effective_ttl,resolved_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,'private.test','pending',interval '1 minute',$8::timestamptz)`, generation, org, w.ResourceID, gateway, site, config, profile, text)
		exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,'10.2.3.4')`, generation, org)
		exec(`UPDATE fqdn_resource_answer_generations SET state='active',activated_at=clock_timestamp() WHERE id=$1`, generation)
		check()
	}
	w := newWork("superseded")
	for sequence := int64(1); sequence <= 2; sequence++ {
		w.ExpectedGeneration = sequence - 1
		if err := store.Publish(ctx, w, Generation{TTL: time.Minute, ResolvedAt: clock(), Addresses: []netip.Addr{addr("10.2.3.5")}}); err != nil {
			t.Fatal("actual successor publication refused", err)
		}
		expected[w.ResourceID] = sequence
		check()
	}
	var retired int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='retired'`, w.ResourceID).Scan(&retired); err != nil || retired != 1 {
		t.Fatal("successor did not retain immutable predecessor")
	}
}
