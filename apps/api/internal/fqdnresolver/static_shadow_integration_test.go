package fqdnresolver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

func TestStaticHistoricalShadowedProfileNeverPublishesOrFallsBack(t *testing.T) {
	for _, allShadowed := range []bool{false, true} {
		name := "alias target shadowed"
		if allShadowed {
			name = "all records shadowed with public endpoints"
		}
		t.Run(name, func(t *testing.T) {
			ctx, pool := testpostgres.NewAtVersion(t, 229)
			org, site, gateway, config, broad, narrow, resource, generation := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'shadow test',$2,'10.249.0.0/24',true)`, org, "shadow-"+org.String())
			exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'office')`, site, org)
			exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, gateway.String(), site)
			exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'alias','alias.office.test',$3,$4)`, resource, org, site, gateway)
			records := []StaticRecord{{"hidden.private.office.test", "A", "10.20.0.80", 300}}
			if !allShadowed {
				records = append(records, StaticRecord{"alias.office.test", "CNAME", "hidden.private.office.test", 300})
			}
			raw, _ := json.Marshal(records)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			for _, s := range []struct {
				q string
				a []any
			}{
				{`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, []any{config, org, site, gateway}},
				{`INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint,static_records) VALUES($1,$2,$3,0,'Broad','on_premises',$4)`, []any{broad, config, org, raw}},
				{`INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,'office.test')`, []any{broad, config, org}},
				{`INSERT INTO fqdn_resolver_context_profile_endpoints(profile_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'1.1.1.1',53,'udp')`, []any{broad, org}},
				{`INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint,static_records) VALUES($1,$2,$3,1,'Narrow','on_premises','[{"name":"owned.private.office.test","type":"A","value":"10.20.0.81","ttl":300}]')`, []any{narrow, config, org}},
				{`INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,'private.office.test')`, []any{narrow, config, org}},
			} {
				if _, err := tx.Exec(ctx, s.q, s.a...); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			// Preserve an old worker's bad generation as history; current readers must not authorize it.
			if !allShadowed {
				exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,resolver_profile_id,resolver_match_suffix,state,effective_ttl,resolved_at) VALUES($1,$2,$3,1,$4,$5,$6,$7,'office.test','pending',interval '5 minutes',clock_timestamp()-interval '241 seconds')`, generation, org, resource, gateway, site, config, broad)
				exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,'10.20.0.80')`, generation, org)
				exec(`UPDATE fqdn_resource_answer_generations SET state='active',activated_at=resolved_at,last_good_at=resolved_at WHERE id=$1`, generation)
			}
			store := NewPostgresStore(pool)
			active, err := store.ActiveGenerations(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			if len(active) != 0 {
				t.Error("historical shadowed generation reached compiler", active)
			}
			due, err := store.Due(ctx, time.Now(), 10)
			if err != nil || len(due) != 1 {
				t.Fatal("work missing", err, len(due))
			}
			if due[0].ResolverConfig.valid() {
				t.Error("shadowed profile kept usable worker authority")
			}
			rpc := &scopedFixtureResolver{}
			NewScheduler(store, rpc, SchedulerConfig{}).Tick(ctx)
			if rpc.got.Hostname != "" {
				t.Fatal("invalid static profile switched to public/RPC resolver", rpc.got)
			}
			active, err = store.ActiveGenerations(ctx, org)
			if err != nil || len(active) != 0 {
				t.Fatal("shadowed alias published application grant", err, active)
			}
			var stored []byte
			if err := pool.QueryRow(ctx, `SELECT static_records FROM fqdn_resolver_context_profiles WHERE id=$1`, broad).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			var preserved []StaticRecord
			if err := json.Unmarshal(stored, &preserved); err != nil || len(preserved) != len(records) {
				t.Fatal("reader changed historical profile")
			}
		})
	}
}
