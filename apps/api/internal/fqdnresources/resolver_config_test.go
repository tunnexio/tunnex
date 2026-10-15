package fqdnresources

import (
	"context"
	"fmt"
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

func TestValidateResolverProfilesNormalizesAndRejectsAmbiguousAuthority(t *testing.T) {
	endpoint := []ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}
	profiles := []ResolverProfile{
		{Name: "AWS parent", ProviderHint: "aws", ZoneSuffixes: []string{"Internal.Example.COM."}, Endpoints: append([]ResolverEndpoint(nil), endpoint...)},
		{Name: "Azure child", ProviderHint: "azure", ZoneSuffixes: []string{"azure.internal.example.com"}, Endpoints: append([]ResolverEndpoint(nil), endpoint...)},
	}
	if err := validateProfiles(profiles); err != nil {
		t.Fatalf("valid profile set rejected: %v", err)
	}
	if profiles[0].ZoneSuffixes[0] != "internal.example.com" {
		t.Fatalf("suffix was not normalized: %q", profiles[0].ZoneSuffixes[0])
	}
	duplicate := []ResolverProfile{
		{Name: "AWS", ProviderHint: "aws", ZoneSuffixes: []string{"internal.example.com"}, Endpoints: append([]ResolverEndpoint(nil), endpoint...)},
		{Name: "Azure", ProviderHint: "azure", ZoneSuffixes: []string{"INTERNAL.EXAMPLE.COM"}, Endpoints: append([]ResolverEndpoint(nil), endpoint...)},
	}
	if err := validateProfiles(duplicate); err == nil {
		t.Fatal("equal-precedence duplicate suffix was accepted")
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
	if err := db.MigrateTo(testURL.String(), 228); err != nil {
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
	provider := "aws"
	got, err := New(pool).SetResolverConfig(ctx, org, site, gateway, uuid.Nil, "test", "replacement proof", &provider, endpoints)
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
	if boundConfig.ProviderHint == nil || *boundConfig.ProviderHint != provider {
		t.Fatalf("bound replacement provider=%v want %q", boundConfig.ProviderHint, provider)
	}
	var invalidCommitted int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resolver_context_configs WHERE (state='active' AND retired_at IS NOT NULL) OR (state='retired' AND retired_at IS NULL)`).Scan(&invalidCommitted); err != nil {
		t.Fatal(err)
	}
	if invalidCommitted != 0 {
		t.Fatalf("invalid resolver revisions committed: %d", invalidCommitted)
	}
	exec(`INSERT INTO site_subnets(site_id,cidr,status) VALUES($1,'192.168.1.0/24','approved')`, site)
	static := []ResolverProfile{{Name: "Managed records", ProviderHint: "on_premises", ZoneSuffixes: []string{"private.example"}, StaticRecords: []ResolverStaticRecord{{Name: "app.private.example", Type: "A", Value: "10.20.1.10", TTL: 300}, {Name: "alias.private.example", Type: "CNAME", Value: "app.private.example", TTL: 300}}, LANListener: &ResolverLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}}}}
	for _, capability := range []struct {
		version int
		age     string
	}{{11, "0 seconds"}, {12, "2 minutes"}} {
		exec(`UPDATE nodes SET capabilities=jsonb_build_object('max_policy_version',$2::int),policy_reported_at=clock_timestamp()-$3::interval WHERE id=$1`, gateway, capability.version, capability.age)
		if _, err := New(pool).SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "unsupported static profile", static); err == nil {
			t.Fatal("unsupported or stale gateway accepted static DNS")
		}
		retained, err := New(pool).ResolverConfig(ctx, org, site, gateway)
		if err != nil || retained.ID != got.ID {
			t.Fatalf("capability refusal retired previous profile: %+v %v", retained, err)
		}
	}
	exec(`UPDATE nodes SET capabilities=jsonb_build_object('max_policy_version',12),policy_reported_at=clock_timestamp() WHERE id=$1`, gateway)
	managed, err := New(pool).SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "static profile proof", static)
	if err != nil {
		t.Fatalf("activate static records: %v", err)
	}
	read, err := New(pool).ResolverConfig(ctx, org, site, gateway)
	if err != nil || read.ID != managed.ID || read.Version != 3 || len(read.Profiles) != 1 || len(read.Profiles[0].StaticRecords) != 2 || read.Profiles[0].LANListener == nil || read.Profiles[0].LANListener.Address != "192.168.1.39" {
		t.Fatalf("static readback=%+v err=%v", read, err)
	}
	static[0].LANListener.DefaultUpstreams = []string{"8.8.8.8", "1.1.1.1"}
	for _, capability := range []struct {
		version int
		age     string
	}{{12, "0 seconds"}, {13, "2 minutes"}} {
		exec(`UPDATE nodes SET capabilities=jsonb_build_object('max_policy_version',$2::int),policy_reported_at=clock_timestamp()-$3::interval WHERE id=$1`, gateway, capability.version, capability.age)
		if _, err := New(pool).SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "unsupported public DNS", static); err == nil {
			t.Fatal("old or stale gateway accepted public DNS")
		}
		retained, err := New(pool).ResolverConfig(ctx, org, site, gateway)
		if err != nil || retained.ID != managed.ID {
			t.Fatalf("public DNS refusal changed current authority: %+v %v", retained, err)
		}
	}
	exec(`UPDATE nodes SET capabilities=jsonb_build_object('max_policy_version',13),policy_reported_at=clock_timestamp() WHERE id=$1`, gateway)
	managed, err = New(pool).SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "explicit public DNS", static)
	if err != nil {
		t.Fatal(err)
	}
	read, err = New(pool).ResolverConfig(ctx, org, site, gateway)
	if err != nil || read.Version != 4 || !slices.Equal(read.Profiles[0].LANListener.DefaultUpstreams, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("public DNS readback=%+v err=%v", read, err)
	}
	staticResource := uuid.New()
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'managed app','app.private.example',$3,$4)`, staticResource, org, site, gateway)
	if detail, err := New(pool).Detail(ctx, org, staticResource); err != nil || detail.Resource.State != "resolving" {
		t.Fatalf("static-only context readiness=%+v err=%v", detail, err)
	}
	if _, err := New(pool).ResolverConfig(ctx, uuid.New(), site, gateway); err == nil {
		t.Fatal("cross-tenant read accepted")
	}
	if err := New(pool).DeleteResolverConfig(ctx, uuid.New(), site, gateway, uuid.Nil, "test", "foreign delete"); err == nil {
		t.Fatal("cross-tenant delete accepted")
	}
	static[0].LANListener.AllowedSources = []string{"10.0.0.0/8"}
	if _, err := New(pool).SetResolverProfiles(ctx, org, site, gateway, uuid.Nil, "test", "unapproved sources", static); err == nil {
		t.Fatal("unapproved LAN sources accepted")
	}
	retained, err := New(pool).ResolverConfig(ctx, org, site, gateway)
	if err != nil || retained.ID != managed.ID {
		t.Fatalf("failed replacement retired valid profile: %+v %v", retained, err)
	}
	if err := New(pool).DeleteResolverConfig(ctx, org, site, gateway, uuid.Nil, "test", "static retirement proof"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(pool).ResolverConfig(ctx, org, site, gateway); err == nil {
		t.Fatal("retired static records remained active")
	}
	if detail, err := New(pool).Detail(ctx, org, staticResource); err != nil || detail.Resource.State != "unconfigured" {
		t.Fatalf("retired static context readiness=%+v err=%v", detail, err)
	}
	var preserved int
	if err := pool.QueryRow(ctx, `SELECT jsonb_array_length(static_records) FROM fqdn_resolver_context_profiles WHERE config_id=$1 AND org_id=$2`, managed.ID, org).Scan(&preserved); err != nil || preserved != 2 {
		t.Fatalf("immutable provenance=%d err=%v", preserved, err)
	}
}

func TestValidateStaticDNSProfiles(t *testing.T) {
	base := func(records []ResolverStaticRecord) []ResolverProfile {
		return []ResolverProfile{{Name: "Managed", ProviderHint: "on_premises", ZoneSuffixes: []string{"private.example"}, StaticRecords: records}}
	}
	valid := base([]ResolverStaticRecord{{Name: "APP.Private.Example.", Type: "a", Value: "10.20.1.10"}, {Name: "app.private.example", Type: "AAAA", Value: "fd00::10", TTL: 60}, {Name: "alias.private.example", Type: "CNAME", Value: "app.private.example", TTL: 60}, {Name: "external.private.example", Type: "CNAME", Value: "lb.example.com", TTL: 60}})
	if err := validateProfiles(valid); err != nil {
		t.Fatal(err)
	}
	if valid[0].StaticRecords[1].Name != "app.private.example" || valid[0].StaticRecords[1].TTL != 300 {
		t.Fatalf("records not canonicalized: %+v", valid[0].StaticRecords)
	}
	for name, records := range map[string][]ResolverStaticRecord{
		"public":       {{Name: "app.private.example", Type: "A", Value: "8.8.8.8"}},
		"wrong family": {{Name: "app.private.example", Type: "AAAA", Value: "10.20.1.10"}},
		"outside zone": {{Name: "private.example.evil", Type: "A", Value: "10.20.1.10"}},
		"IP alias":     {{Name: "app.private.example", Type: "CNAME", Value: "10.20.1.10"}},
		"self alias":   {{Name: "app.private.example", Type: "CNAME", Value: "app.private.example"}},
		"cycle":        {{Name: "app.private.example", Type: "CNAME", Value: "other.private.example"}, {Name: "other.private.example", Type: "CNAME", Value: "app.private.example"}},
		"coexistence":  {{Name: "app.private.example", Type: "CNAME", Value: "other.private.example"}, {Name: "app.private.example", Type: "A", Value: "10.20.1.10"}},
		"duplicate":    {{Name: "app.private.example", Type: "A", Value: "10.20.1.10"}, {Name: "app.private.example", Type: "A", Value: "10.20.1.10"}},
		"TTL mismatch": {{Name: "app.private.example", Type: "A", Value: "10.20.1.10", TTL: 30}, {Name: "app.private.example", Type: "A", Value: "10.20.1.11", TTL: 60}},
		"TTL short":    {{Name: "app.private.example", Type: "A", Value: "10.20.1.10", TTL: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProfiles(base(records)); err == nil {
				t.Fatal("invalid records accepted")
			}
		})
	}
	mixed := base([]ResolverStaticRecord{{Name: "app.private.example", Type: "A", Value: "10.20.1.10"}})
	mixed[0].Endpoints = []ResolverEndpoint{{Address: "10.20.0.53", Transport: "udp"}}
	if err := validateProfiles(mixed); err == nil {
		t.Fatal("static/upstream ambiguity accepted")
	}
}

func TestValidateDNSLANListener(t *testing.T) {
	valid := &ResolverLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}}
	if err := validateLANListener(valid); err != nil {
		t.Fatal(err)
	}
	for name, listener := range map[string]ResolverLANListener{
		"IPv6 listener":             {Address: "fd00::53", Interface: "eth0", AllowedSources: []string{"fd00::/64"}},
		"wildcard":                  {Address: "0.0.0.0", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}},
		"interface command":         {Address: "192.168.1.39", Interface: "eth0;id", AllowedSources: []string{"192.168.1.0/24"}},
		"empty sources":             {Address: "192.168.1.39", Interface: "eth0"},
		"all sources":               {Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"0.0.0.0/0"}},
		"private start public span": {Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.0.0.0/8"}},
		"host bits":                 {Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.39/24"}},
		"family mismatch":           {Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"fd00::/64"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateLANListener(&listener); err == nil {
				t.Fatal("invalid listener accepted")
			}
		})
	}
}

func TestStaticDNSRejectsCrossProfileCyclesAndRuntimeBounds(t *testing.T) {
	profiles := []ResolverProfile{
		{Name: "One", ProviderHint: "on_premises", ZoneSuffixes: []string{"one.private"}, StaticRecords: []ResolverStaticRecord{{Name: "a.one.private", Type: "CNAME", Value: "b.two.private"}}},
		{Name: "Two", ProviderHint: "on_premises", ZoneSuffixes: []string{"two.private"}, StaticRecords: []ResolverStaticRecord{{Name: "b.two.private", Type: "CNAME", Value: "a.one.private"}}},
	}
	if err := validateProfiles(profiles); err == nil {
		t.Fatal("cross-profile CNAME cycle accepted")
	}
	var records []ResolverStaticRecord
	for i := 1; i <= 33; i++ {
		records = append(records, ResolverStaticRecord{Name: "app.private.example", Type: "A", Value: fmt.Sprintf("10.20.0.%d", i)})
	}
	if err := validateStaticRecords(records, []string{"private.example"}); err == nil {
		t.Fatal("unusable address set accepted")
	}
}

func TestLANDefaultUpstreamsValidation(t *testing.T) {
	base := func(values ...string) *ResolverLANListener {
		return &ResolverLANListener{Address: "192.168.1.39", Interface: "eth0", AllowedSources: []string{"192.168.1.0/24"}, DefaultUpstreams: values}
	}
	for _, value := range []string{"", "localhost", "1.1.1.1:53", "::ffff:1.1.1.1", "2001:4860:4860::8888", "0.1.2.3", "10.1.2.3", "100.64.0.1", "127.1.2.3", "169.254.1.1", "172.16.1.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.39", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255"} {
		t.Run(value, func(t *testing.T) {
			if err := validateLANListener(base(value)); err == nil {
				t.Fatalf("accepted nonpublic upstream %q", value)
			}
		})
	}
	for _, values := range [][]string{{"1.1.1.1", " 1.1.1.1 "}, {"1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"}} {
		if err := validateLANListener(base(values...)); err == nil {
			t.Fatal("accepted duplicate or excessive upstreams")
		}
	}
	valid := base("8.8.8.8", " 1.1.1.1 ")
	if err := validateLANListener(valid); err != nil || !slices.Equal(valid.DefaultUpstreams, []string{"1.1.1.1", "8.8.8.8"}) {
		t.Fatalf("canonical upstreams %+v %v", valid, err)
	}
	first, second := base("1.1.1.1"), base("8.8.8.8")
	profiles := []ResolverProfile{{LANListener: first}, {LANListener: second}}
	if err := validateLANDefaultContexts(profiles); err == nil {
		t.Fatal("conflicting public defaults accepted")
	}
	second.DefaultUpstreams = nil
	second.AllowedSources = []string{"192.168.1.0/25"}
	if err := validateLANDefaultContexts(profiles); err != nil {
		t.Fatalf("private-only sibling changed: %v", err)
	}
	second.DefaultUpstreams = []string{"1.1.1.1"}
	if err := validateLANDefaultContexts(profiles); err != nil {
		t.Fatal(err)
	}
	profiles[1].Endpoints = []ResolverEndpoint{{Address: "1.1.1.1"}}
	if err := validateLANDefaultContexts(profiles); err == nil {
		t.Fatal("private endpoint also used for public recursion")
	}
}
