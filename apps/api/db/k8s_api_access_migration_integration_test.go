package db_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// 0239 (K8N-3 stage 1): the cluster API endpoint table, the k8s_api rule kind, and the proof that an
// exposure of default/kubernetes made BEFORE the migration is left exactly as it was.
func TestK8sAPIAccessMigrationPostgres(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for 0239 PostgreSQL proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	base, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	name := "tnx_k8n3_api_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	dsn := testURL.String()
	if err := db.MigrateTo(dsn, 238); err != nil {
		t.Fatalf("migrate prerequisite chain through 0238: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("exec %q: %v", query, err)
		}
	}
	refused := func(what, contains, query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err == nil || !strings.Contains(err.Error(), contains) {
			t.Fatalf("%s must be refused by %s, got %v", what, contains, err)
		}
	}
	org, site, cluster, user, group, legacy, legacyRule, web := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'0239',$2,'10.246.0.0/24')`, org, "k8n3-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'0239-site')`, site, org)
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, user, user.String()+"@k8n3.example")
	exec(`INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, user)
	exec(`INSERT INTO user_groups(id,org_id,name) VALUES($1,$2,'platform')`, group, org)
	exec(`INSERT INTO k8s_clusters(id,org_id,site_id,name,vip_range,dns_zone,dns_vip) VALUES($1,$2,$3,'prod','100.124.0.0/24','k8s.acme.com','100.124.0.2')`, cluster, org, site)
	// Before 0239 nothing stopped this: default/kubernetes exposed as an ordinary Service, with a rule.
	exec(`INSERT INTO k8s_services(id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,$3,'kubernetes','default','tcp',443,443,'100.124.0.3')`, legacy, org, cluster)
	exec(`INSERT INTO k8s_services(id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,$3,'web','shop','tcp',80,80,'100.124.0.4')`, web, org, cluster)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_user_id,dst_kind,dst_k8s_service_id) VALUES($1,$2,'user',$3,'k8s_service',$4)`, legacyRule, org, user, legacy)

	if err := db.MigrateTo(dsn, 239); err != nil {
		t.Fatalf("apply 0239: %v", err)
	}

	// The existing exposure and its rule are untouched, and nothing was converted into an API endpoint.
	var vip, kind string
	var live bool
	if err := pool.QueryRow(ctx, `SELECT host(s.vip), s.deleted_at IS NULL, r.dst_kind FROM k8s_services s JOIN policy_rules r ON r.dst_k8s_service_id=s.id WHERE s.id=$1 AND r.id=$2`, legacy, legacyRule).
		Scan(&vip, &live, &kind); err != nil || vip != "100.124.0.3" || !live || kind != "k8s_service" {
		t.Fatalf("the existing default/kubernetes exposure must survive 0239 unchanged: vip=%q live=%v kind=%q err=%v", vip, live, kind, err)
	}
	var endpoints int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM k8s_api_endpoints`).Scan(&endpoints); err != nil || endpoints != 0 {
		t.Fatalf("0239 must not create or convert anything: %d endpoints (err=%v)", endpoints, err)
	}
	// It can still be updated and soft-deleted like any exposure.
	exec(`UPDATE k8s_services SET updated_at=now() WHERE id=$1`, legacy)

	// The endpoint: off has no address, on has one, inside the range, not the DNS address, not a Service's.
	endpoint := uuid.New()
	exec(`INSERT INTO k8s_api_endpoints(id,org_id,cluster_id) VALUES($1,$2,$3)`, endpoint, org, cluster)
	refused("on without an address", "k8s_api_endpoints_enabled_has_vip", `UPDATE k8s_api_endpoints SET enabled=true WHERE id=$1`, endpoint)
	refused("an address while off", "k8s_api_endpoints_enabled_has_vip", `UPDATE k8s_api_endpoints SET vip='100.124.0.9' WHERE id=$1`, endpoint)
	refused("the DNS address", "k8s_api_endpoint_vip_is_dns_vip", `UPDATE k8s_api_endpoints SET enabled=true, vip='100.124.0.2' WHERE id=$1`, endpoint)
	refused("a Service's address", "k8s_api_endpoint_vip_in_use", `UPDATE k8s_api_endpoints SET enabled=true, vip='100.124.0.4' WHERE id=$1`, endpoint)
	refused("an address outside the range", "k8s_api_endpoint_vip_outside_cluster_range", `UPDATE k8s_api_endpoints SET enabled=true, vip='100.125.0.9' WHERE id=$1`, endpoint)
	refused("a second endpoint for one cluster", "k8s_api_endpoints_cluster_id_key", `INSERT INTO k8s_api_endpoints(org_id,cluster_id) VALUES($1,$2)`, org, cluster)
	exec(`UPDATE k8s_api_endpoints SET enabled=true, vip='100.124.0.9', enabled_at=now() WHERE id=$1`, endpoint)
	refused("a Service at the API's address", "k8s_service_vip_reserved_for_api_access",
		`INSERT INTO k8s_services(org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,'rogue','shop','tcp',9,9,'100.124.0.9')`, org, cluster)

	// The rule kind: a person or a group, exactly one destination, one rule per subject.
	exec(`INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'user',$2,'k8s_api',$3)`, org, user, endpoint)
	exec(`INSERT INTO policy_rules(org_id,src_kind,src_group_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'group',$2,'k8s_api',$3)`, org, group, endpoint)
	refused("a duplicate person rule", "policy_rules_user_k8s_api_uniq", `INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'user',$2,'k8s_api',$3)`, org, user, endpoint)
	refused("a duplicate group rule", "policy_rules_group_k8s_api_uniq", `INSERT INTO policy_rules(org_id,src_kind,src_group_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'group',$2,'k8s_api',$3)`, org, group, endpoint)
	refused("a site source", "policy_rules_k8s_api_people_only", `INSERT INTO policy_rules(org_id,src_kind,src_site_id,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'site',$2,'k8s_api',$3)`, org, site, endpoint)
	refused("an address-range source", "policy_rules_k8s_api_people_only", `INSERT INTO policy_rules(org_id,src_kind,src_cidr,dst_kind,dst_k8s_api_endpoint_id) VALUES($1,'cidr','10.20.0.7/32','k8s_api',$2)`, org, endpoint)
	refused("a k8s_api rule without an endpoint", "policy_rules_check", `INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind) VALUES($1,'user',$2,'k8s_api')`, org, user)
	refused("a k8s_api rule that also names a Service", "policy_rules_check", `INSERT INTO policy_rules(org_id,src_kind,src_group_id,dst_kind,dst_k8s_api_endpoint_id,dst_k8s_service_id) VALUES($1,'group',$2,'k8s_api',$3,$4)`, org, group, endpoint, web)
	refused("a Service rule that also names an API endpoint", "policy_rules_check", `INSERT INTO policy_rules(org_id,src_kind,src_group_id,dst_kind,dst_k8s_service_id,dst_k8s_api_endpoint_id) VALUES($1,'group',$2,'k8s_service',$3,$4)`, org, group, web, endpoint)
	// Agent access and agent templates have their own destination checks, and neither knows the kind.
	for _, table := range []string{"agent_access_requests", "agent_policy_template_version_items"} {
		var definition string
		if err := pool.QueryRow(ctx, `SELECT string_agg(pg_get_constraintdef(c.oid), ' ') FROM pg_constraint c WHERE c.conrelid=$1::regclass AND c.contype='c'`, table).Scan(&definition); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(definition, "k8s_service") || strings.Contains(definition, "k8s_api") {
			t.Fatalf("%s must not accept the Kubernetes API as a destination: %s", table, definition)
		}
	}

	// Down is refused while the feature holds data, and nothing is lost by the refusal.
	if err := db.MigrateTo(dsn, 238); err == nil || !strings.Contains(err.Error(), "0239 rollback refused") {
		t.Fatalf("0239 down must be refused while API access is on or has rules, got %v", err)
	}
	// A refused down leaves the version dirty at 238 in golang-migrate's bookkeeping; the schema itself is
	// still 0239 because the migration is one transaction. Put the bookkeeping back and continue.
	exec(`UPDATE schema_migrations SET version=239, dirty=false`)
	var rules int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE dst_kind='k8s_api'`).Scan(&rules); err != nil || rules != 2 {
		t.Fatalf("a refused down must keep the rules: %d (err=%v)", rules, err)
	}

	// Turning the feature off cleanly lets it go down, the old checks come back, and it comes up again.
	exec(`DELETE FROM policy_rules WHERE dst_kind='k8s_api'`)
	exec(`UPDATE k8s_api_endpoints SET enabled=false, vip=NULL`)
	if err := db.MigrateTo(dsn, 238); err != nil {
		t.Fatalf("clean 0239 down: %v", err)
	}
	var column, table int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM information_schema.columns WHERE table_name='policy_rules' AND column_name='dst_k8s_api_endpoint_id'),
		(SELECT count(*) FROM information_schema.tables WHERE table_name='k8s_api_endpoints')`).Scan(&column, &table); err != nil || column != 0 || table != 0 {
		t.Fatalf("0239 down must remove the column and the table: column=%d table=%d err=%v", column, table, err)
	}
	refused("the kind after down", "violates check constraint", `INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind) VALUES($1,'user',$2,'k8s_api')`, org, user)
	if err := pool.QueryRow(ctx, `SELECT host(vip) FROM k8s_services WHERE id=$1 AND deleted_at IS NULL`, legacy).Scan(&vip); err != nil || vip != "100.124.0.3" {
		t.Fatalf("the existing exposure must survive down as well: %q %v", vip, err)
	}
	// With the triggers gone a Service can take any free address again.
	exec(`INSERT INTO k8s_services(org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES($1,$2,'later','shop','tcp',9,9,'100.124.0.9')`, org, cluster)
	if err := db.MigrateTo(dsn, 239); err != nil {
		t.Fatalf("0239 re-up: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM policy_rules WHERE id=$1 AND dst_kind='k8s_service'`, legacyRule).Scan(&rules); err != nil || rules != 1 {
		t.Fatalf("the existing rule must survive the round trip: %d (err=%v)", rules, err)
	}
}
