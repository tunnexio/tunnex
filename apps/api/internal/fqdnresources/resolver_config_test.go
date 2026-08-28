package fqdnresources

import (
	"context"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

func TestValidateResolverEndpointsRequiresDirectBoundedTransport(t *testing.T) {
	valid := []ResolverEndpoint{{Address: "10.20.0.53", Transport: "udp"}, {Address: "fd00::53", Port: 53, Transport: "tcp"}}
	if err := validateEndpoints(valid); err != nil {
		t.Fatalf("valid direct endpoints rejected: %v", err)
	}
	if valid[0].Port != 53 {
		t.Fatalf("zero port must normalize to DNS port 53, got %d", valid[0].Port)
	}
	for _, endpoints := range [][]ResolverEndpoint{
		{{Address: "resolver.example.test", Port: 53, Transport: "udp"}},
		{{Address: "127.0.0.1", Port: 53, Transport: "udp"}},
		{{Address: "10.20.0.53", Port: 53, Transport: "doh"}},
		{{Address: "10.20.0.53", Port: 53, Transport: "udp"}, {Address: "10.20.0.53", Port: 53, Transport: "udp"}},
	} {
		if err := validateEndpoints(endpoints); err == nil {
			t.Fatalf("invalid resolver endpoint set accepted: %#v", endpoints)
		}
	}
}

// TestPostgresSetResolverConfigReplacement is a fresh-schema proof for the
// two-phase immutable revision write. The initially retired replacement row
// must satisfy the migration constraint before its endpoints are bound and it
// is activated, while no invalid row is ever committed.
func TestPostgresSetResolverConfigReplacement(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable resolver config proof")
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
	name := "tnx_s21_resolver_config_" + uuid.NewString()[:8]
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

	org, site, gateway, oldID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr) VALUES($1,'resolver config',$2,'10.254.0.0/24')`, org, "resolver-config-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, "resolver-config-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, oldID, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, oldID, org)

	endpoints := []ResolverEndpoint{{Address: "10.53.0.54", Port: 53, Transport: "tcp"}, {Address: "10.53.0.55", Port: 5353, Transport: "udp"}}
	got, err := New(pool).SetResolverConfig(ctx, org, site, gateway, uuid.Nil, "test", "replacement proof", endpoints)
	if err != nil {
		t.Fatalf("replace resolver config: %v", err)
	}
	if got.Version != 2 || got.State != "active" || len(got.Endpoints) != len(endpoints) {
		t.Fatalf("replacement=%+v", got)
	}

	var oldState, newState string
	var oldRetiredAt, newRetiredAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT state,retired_at FROM fqdn_resolver_context_configs WHERE id=$1`, oldID).Scan(&oldState, &oldRetiredAt); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT state,retired_at FROM fqdn_resolver_context_configs WHERE id=$1`, got.ID).Scan(&newState, &newRetiredAt); err != nil {
		t.Fatal(err)
	}
	if oldState != "retired" || oldRetiredAt == nil || newState != "active" || newRetiredAt != nil {
		t.Fatalf("old=(%q,%v) new=(%q,%v)", oldState, oldRetiredAt, newState, newRetiredAt)
	}
	var bound int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resolver_context_endpoints WHERE config_id=$1 AND org_id=$2`, got.ID, org).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != len(endpoints) {
		t.Fatalf("replacement endpoint count=%d want %d", bound, len(endpoints))
	}
	boundConfig, err := New(pool).ResolverConfig(ctx, org, site, gateway)
	if err != nil {
		t.Fatalf("read replacement resolver config: %v", err)
	}
	if boundConfig.ID != got.ID || !slices.Equal(boundConfig.Endpoints, endpoints) {
		t.Fatalf("bound replacement=%+v want id=%s endpoints=%+v", boundConfig, got.ID, endpoints)
	}
	var invalidCommitted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resolver_context_configs WHERE (state='active' AND retired_at IS NOT NULL) OR (state='retired' AND retired_at IS NULL)`).Scan(&invalidCommitted); err != nil {
		t.Fatal(err)
	}
	if invalidCommitted != 0 {
		t.Fatalf("invalid resolver revisions committed: %d", invalidCommitted)
	}
}
