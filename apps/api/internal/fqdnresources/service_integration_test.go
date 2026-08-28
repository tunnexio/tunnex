package fqdnresources

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// This proof owns a fresh database through migration 0116. It deliberately
// never connects test behavior to a shared application stack.
func TestPostgresResourceContractFailClosedAndBounded(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable Postgres resource-contract proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_s21_resource_contract_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	if err := db.MigrateTo(testURL.String(), 116); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}

	org, site, gateway, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'resource contract',$2,'10.248.0.0/24')`, org, "resource-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, "resource-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'orders','orders.internal',$3,$4)`, resource, org, site, gateway)
	config := uuid.New()
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, config, org)
	publish := func(configID uuid.UUID, generation int64, address string) {
		t.Helper()
		id := uuid.New()
		now := time.Now().UTC().Truncate(time.Second)
		exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,resolver_config_id,state,effective_ttl,resolved_at) VALUES($1,$2,$3,$4,$5,$6,$7,'pending','5 minutes',$8)`, id, org, resource, generation, gateway, site, configID, now)
		exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,$3::inet)`, id, org, address)
		exec(`UPDATE fqdn_resource_answer_generations SET state='active',activated_at=resolved_at,last_good_at=resolved_at WHERE id=$1`, id)
	}
	publish(config, 1, "10.2.3.4")

	// The outer joins in resourceQuery must not lock their nullable sides. A
	// successful ordinary update proves PostgreSQL reached the mutation logic.
	svc := New(pool)
	updated, err := svc.Update(ctx, org, resource, Input{Name: "orders renamed", FQDN: "orders.internal", Protocol: "any", Context: &Context{SiteID: site, GatewayID: gateway}}, uuid.Nil, "resource-contract-test", "")
	if err != nil || updated.Name != "orders renamed" {
		t.Fatalf("ordinary update did not reach mutation logic: resource=%+v err=%v", updated, err)
	}

	for n := 0; n < 33; n++ {
		group, rule := uuid.New(), uuid.New()
		exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,$3)`, group, org, "group-"+group.String())
		expires := any(nil)
		if n == 32 {
			expires = time.Now().Add(-time.Minute)
		}
		exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_group_id,dst_kind,dst_fqdn_resource_id,expires_at) VALUES($1,$2,'group',$3,'fqdn_resource',$4,$5)`, rule, org, group, resource, expires)
	}
	impact, err := svc.Impact(ctx, org, resource)
	if err != nil || impact.ReferencingRuleCount != 33 || len(impact.ReferencingRuleIDs) != 32 || !impact.RuleIDsTruncated {
		t.Fatalf("bounded resource impact=%+v err=%v", impact, err)
	}
	setting, err := svc.SettingImpact(ctx, org)
	if err != nil || setting.EnforcementReadyRuleCount != 32 || len(setting.EnforcementReadyRuleIDs) != 32 || setting.RuleIDsTruncated {
		t.Fatalf("expired rule leaked into opt-in impact=%+v err=%v", setting, err)
	}

	replacement := uuid.New()
	exec(`UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE id=$1`, config)
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,2,'active')`, replacement, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.54'::inet,53,'tcp')`, replacement, org)
	assertUnavailable := func(stage string) {
		t.Helper()
		detail, err := svc.Detail(ctx, org, resource)
		if err != nil || detail.Resource.State == "healthy" || detail.Resource.Generation != nil || detail.Resource.AnswerCount != 0 || detail.Resource.EffectiveTTLSeconds != nil || detail.Resource.RefreshedAt != nil || detail.FreshUntilAt != nil || len(detail.ActiveAnswers) != 0 {
			t.Fatalf("%s detail retained eligible health: detail=%+v err=%v", stage, detail, err)
		}
	}
	assertUnavailable("replacement")
	if err := svc.DeleteResolverConfig(ctx, org, site, gateway, uuid.Nil, "resource-contract-test", ""); err != nil {
		t.Fatal(err)
	}
	assertUnavailable("removal")
}
