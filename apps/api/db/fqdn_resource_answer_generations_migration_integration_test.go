package db_test

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

// TestFQDNResourceAnswerGenerationMigrationPostgres exercises the DB-owned
// D3/D4/D5 constraints against a throwaway database.  It intentionally does
// not call a resolver, compiler, or HTTP route: this migration is additive
// storage only, and those later layers must not be faked by a schema test.
func TestFQDNResourceAnswerGenerationMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0110 PostgreSQL proof")
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
	name := "tnx_s21_fqdn_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	if err := db.MigrateTo(testURL.String(), 112); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	org, node, resource := uuid.New(), uuid.New(), uuid.New()
	otherOrg := uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'FQDN test',$2,'10.250.0.0/24')`, org, "fqdn-"+org.String()[:8])
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'FQDN other',$2,'10.251.0.0/24')`, otherOrg, "fqdn-other-"+otherOrg.String()[:8])
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial) VALUES($1,$2,'resolver',$3)`, node, org, "fqdn-"+node.String())
	site := uuid.New()
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'resolver site')`, site, org)
	exec(`UPDATE nodes SET site_id=$3 WHERE id=$1 AND org_id=$2`, node, org, site)
	// 0112 makes resolver Site and gateway an atomic selected context.  Seed
	// both in the initial insert rather than creating an invalid half-context.
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,protocol,port_low,port_high,resolver_site_id,resolver_node_id) VALUES($1,$2,'orders','orders.internal.example','tcp',443,443,$3,$4)`, resource, org, site, node)
	otherSite := uuid.New()
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'other resolver site')`, otherSite, org)
	if _, err := pool.Exec(ctx, `UPDATE fqdn_resources SET resolver_site_id=$3 WHERE id=$1 AND org_id=$2`, resource, org, otherSite); err == nil {
		t.Fatal("resolver gateway must be selected from the stated site in the same organization")
	}
	var staticResources int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM resources WHERE org_id=$1`, org).Scan(&staticResources); err != nil {
		t.Fatal(err)
	}
	if staticResources != 0 {
		t.Fatalf("independent FQDN resource must not need a static CIDR sentinel, resources=%d", staticResources)
	}

	gen := uuid.New()
	exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,state,effective_ttl,resolved_at) VALUES($1,$2,$3,1,$4,$5,'pending',interval '30 seconds',now())`, gen, org, resource, node, site)
	for i := 1; i <= 32; i++ {
		exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,('10.250.1.' || $3::int::text)::inet)`, gen, org, i)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,'10.250.1.33')`, gen, org); err == nil {
		t.Fatal("33rd answer must be refused")
	}
	if _, err := pool.Exec(ctx, `UPDATE fqdn_resource_answer_generations SET state='active', activated_at=now(), last_good_at=now() WHERE id=$1`, gen); err != nil {
		t.Fatalf("non-empty pending generation should promote: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,'10.250.2.1')`, gen, org); err == nil {
		t.Fatal("published answer history must not accept a new answer")
	}
	if _, err := pool.Exec(ctx, `UPDATE fqdn_resource_generation_answers SET address='10.250.2.1' WHERE generation_id=$1 AND address='10.250.1.1'`, gen); err == nil {
		t.Fatal("published answer history must be immutable")
	}
	second := uuid.New()
	exec(`INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,state,effective_ttl,resolved_at) VALUES($1,$2,$3,2,$4,$5,'pending',interval '1 hour',now())`, second, org, resource, node, site)
	exec(`INSERT INTO fqdn_resource_generation_answers(generation_id,org_id,address) VALUES($1,$2,'fd00::1')`, second, org)
	if _, err := pool.Exec(ctx, `UPDATE fqdn_resource_answer_generations SET state='active', activated_at=now(), last_good_at=now() WHERE id=$1`, second); err == nil {
		t.Fatal("a second active generation for one FQDN resource must fail")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO fqdn_resource_answer_generations(id,org_id,resource_id,generation,resolver_node_id,resolver_site_id,state,effective_ttl,resolved_at) VALUES($1,$2,$3,1,$4,$5,'pending',interval '30 seconds',now())`, uuid.New(), otherOrg, resource, node, site); err == nil {
		t.Fatal("cross-organization FQDN generation must fail")
	}
	if err := db.DownOne(testURL.String()); err == nil {
		t.Fatal("0110 down must refuse FQDN lifecycle data loss")
	}
}
