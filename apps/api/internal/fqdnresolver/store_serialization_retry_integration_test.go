package fqdnresolver

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"
)

// This uses only a newly-created disposable database. No serving DB is accepted
// implicitly: the established test-admin environment variable is required.
type publishModelHook struct {
	calls int
	got   Generation
}

func (h *publishModelHook) Published(_ context.Context, _ Work, g Generation)           { h.calls++; h.got = g }
func (h *publishModelHook) Withdrawn(context.Context, Work, WithdrawalCause, time.Time) {}
func TestPostgresPublishSerializableRetryDesiredBehavior(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable DNS mailbox proof")
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
	name := "tnx_s21_dns_mailbox_" + uuid.NewString()[:8]
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })
	testURL := *base
	testURL.Path = "/" + name
	if err := db.MigrateTo(testURL.String(), 219); err != nil {
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
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'mailbox',$2,'10.252.0.0/24',true)`, org, "mailbox-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities) VALUES($1,$2,'gateway',$3,$4,'{"dns_resolve_rpc_version":2}')`, gateway, org, "mailbox-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'orders','orders.internal',$3,$4)`, resource, org, site, gateway)
	config := uuid.New()
	profile := uuid.New()
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint) VALUES($1,$2,$3,0,'Private internal','aws')`, profile, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,'internal')`, profile, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profile_endpoints(profile_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, profile, org)

	hook := &publishModelHook{}
	store := NewPostgresStore(pool).WithAfterCommit(hook)
	work, err := store.Due(ctx, time.Now(), 10)
	if err != nil || len(work) != 1 {
		t.Fatalf("work fixture len=%d err=%v", len(work), err)
	}
	w := work[0]
	original := Generation{TTL: 30 * time.Second, ResolvedAt: time.Now().UTC(), Addresses: []netip.Addr{netip.MustParseAddr("10.2.3.4")}}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.Background())
	var pid int
	if err = writer.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Exec(ctx, `UPDATE fqdn_resources SET updated_at=now() WHERE id=$1`, resource); err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- store.Publish(c, w, original) }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var n int
		err = pool.QueryRow(c, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%SELECT resolver_site_id,resolver_node_id FROM fqdn_resources%'`, pid).Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
		if n > 1 {
			t.Fatal("ambiguous lock wait")
		}
		select {
		case <-c.Done():
			t.Fatal("no actual lock evidence within original5s")
		case <-ticker.C:
		}
	}
	if err = writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatalf("RED old serializable Publish must recover known abort, got %v", err)
	}
	if hook.calls != 1 || !hook.got.ResolvedAt.Equal(original.ResolvedAt) || hook.got.TTL != original.TTL {
		t.Fatal("after-commit hook must occur once with unchanged observation")
	}
	var n int
	var resolved time.Time
	var ttlSeconds float64
	var gen int64
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1`, resource).Scan(&n); err != nil || n != 1 {
		t.Fatalf("generation count=%d err=%v", n, err)
	}
	if err = pool.QueryRow(ctx, `SELECT generation,resolved_at,extract(epoch from effective_ttl)::float8 FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, resource).Scan(&gen, &resolved, &ttlSeconds); err != nil {
		t.Fatal(err)
	}
	if gen != w.ExpectedGeneration+1 || !resolved.Equal(original.ResolvedAt.Truncate(time.Microsecond)) || ttlSeconds != original.TTL.Seconds() {
		t.Fatal("retry changed generation CAS, original observation time or TTL")
	}
	if err = store.Publish(ctx, w, original); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("old ExpectedGeneration replay=%v", err)
	}
	if hook.calls != 1 {
		t.Fatal("staleCAS invoked callback")
	}
}
