package fqdnresolver

import (
	"context"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

type committedHook struct {
	t        *testing.T
	pool     *pgxpool.Pool
	resource uuid.UUID
	publish  int
	withdraw int
}

func (h *committedHook) Published(ctx context.Context, _ Work, _ Generation) {
	h.t.Helper()
	var active int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, h.resource).Scan(&active); err != nil || active != 1 {
		h.t.Fatalf("publish callback ran before commit: active=%d err=%v", active, err)
	}
	h.publish++
}
func (h *committedHook) Withdrawn(ctx context.Context, _ Work, _ WithdrawalCause, _ time.Time) {
	h.t.Helper()
	var active int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, h.resource).Scan(&active); err != nil || active != 0 {
		h.t.Fatalf("withdraw callback ran before commit: active=%d err=%v", active, err)
	}
	h.withdraw++
}

// This proof always creates and destroys its own database. It never points at
// the database named by TUNNEX_TEST_DATABASE_URL, which must therefore be an
// administrative URL to a disposable PostgreSQL instance.
func TestPostgresStorePublishesAndWithdrawsAtomically(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run disposable Postgres store proof")
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
	name := "tnx_s21_scheduler_" + uuid.NewString()[:8]
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
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
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	org, site, gateway, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'scheduler test',$2,'10.249.0.0/24',true)`, org, "scheduler-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, "scheduler-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'orders','orders.internal',$3,$4)`, resource, org, site, gateway)
	config := uuid.New()
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, config, org)

	hook := &committedHook{t: t, pool: pool, resource: resource}
	store := NewPostgresStore(pool).WithAfterCommit(hook)
	w := Work{OrgID: org, ResourceID: resource, Hostname: "orders.internal", Context: Context{ResolverID: site.String(), GatewayID: gateway.String()}, ResolverConfig: ResolverConfig{ID: config.String(), Version: 1, Endpoints: []ResolverEndpoint{{Address: addr("10.53.0.53"), Port: 53, Transport: "udp"}}}}
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	if err := store.Publish(ctx, w, Generation{TTL: time.Minute, ResolvedAt: now, Addresses: []netip.Addr{addr("10.2.3.4"), addr("fd00::4")}}); err != nil {
		t.Fatal(err)
	}
	var active, answers int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, resource).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_generation_answers a JOIN fqdn_resource_answer_generations g ON g.id=a.generation_id WHERE g.resource_id=$1 AND g.state='active'`, resource).Scan(&answers); err != nil {
		t.Fatal(err)
	}
	if active != 1 || answers != 2 {
		t.Fatalf("active=%d answers=%d", active, answers)
	}
	var persistedConfig uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT resolver_config_id FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, resource).Scan(&persistedConfig); err != nil || persistedConfig != config {
		t.Fatalf("active generation config=%s err=%v want=%s", persistedConfig, err, config)
	}
	// Lane 3 receives only this durable active snapshot: it is scoped to the
	// owning organization, carries the selected Site/Gateway authority, and
	// never consults last-good or pending lifecycle state.
	projection, err := store.ActiveGenerations(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection) != 1 {
		t.Fatalf("active projection count=%d want 1", len(projection))
	}
	got := projection[0]
	if got.ResourceID != resource || got.Sequence != 1 || got.Context.ResolverID != site.String() || got.Context.GatewayID != gateway.String() || len(got.Addresses) != 2 || got.Addresses[0] != addr("10.2.3.4") || got.Addresses[1] != addr("fd00::4") {
		t.Fatalf("unexpected active projection: %#v", got)
	}
	if other, err := store.ActiveGenerations(ctx, uuid.New()); err != nil || len(other) != 0 {
		t.Fatalf("cross-org active projection leaked: rows=%#v err=%v", other, err)
	}

	w.ExpectedGeneration = 1
	if err := store.Withdraw(ctx, w, WithdrawalTimeout, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_resource_answer_generations WHERE resource_id=$1 AND state='active'`, resource).Scan(&active); err != nil {
		t.Fatal(err)
	}
	var code string
	if err := pool.QueryRow(ctx, `SELECT failure_code FROM fqdn_resource_answer_generations WHERE resource_id=$1 ORDER BY generation DESC LIMIT 1`, resource).Scan(&code); err != nil {
		t.Fatal(err)
	}
	if active != 0 || code != string(WithdrawalTimeout) {
		t.Fatalf("withdrawal active=%d code=%q", active, code)
	}
	if projection, err := store.ActiveGenerations(ctx, org); err != nil || len(projection) != 0 {
		t.Fatalf("withdrawn generation must not project to compiler: rows=%#v err=%v", projection, err)
	}
	if hook.publish != 1 || hook.withdraw != 1 {
		t.Fatalf("after-commit calls publish=%d withdraw=%d", hook.publish, hook.withdraw)
	}
	// A withdrawn row is retryable, but it is not "no active row" every 15s.
	// The durable retry bound prevents a failed resolver from minting an
	// unbounded sequence of withdrawn generations.
	if due, err := store.Due(ctx, now.Add(time.Minute), 10); err != nil || len(due) != 0 {
		t.Fatalf("withdrawn resource retried before bound: due=%v err=%v", due, err)
	}
	if due, err := store.Due(ctx, now.Add(time.Minute+MinTTL), 10); err != nil || len(due) != 1 || due[0].ExpectedGeneration != 2 {
		t.Fatalf("withdrawn resource was not retried at bound: due=%v err=%v", due, err)
	}
	if err := store.Withdraw(ctx, Work{OrgID: org, ResourceID: resource, Context: Context{ResolverID: site.String(), GatewayID: gateway.String()}, ExpectedGeneration: 2}, WithdrawalInvalidAnswer, now.Add(2*time.Minute)); err == nil {
		t.Fatal("store accepted a non-D4 withdrawal cause")
	}
	if err := store.Publish(ctx, w, Generation{TTL: time.Minute, ResolvedAt: now, Addresses: []netip.Addr{addr("10.2.3.5")}}); err != ErrSuperseded {
		t.Fatalf("stale work must not overwrite typed withdrawal: %v", err)
	}
	// A context edit withdraws the old authority from compiler input immediately.
	// The resolver will publish a new generation only after it re-reads the new
	// selected pair; no old Site/Gateway snapshot may survive that handoff.
	site2, gateway2 := uuid.New(), uuid.New()
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'reselected')`, site2, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway-reselected',$3,$4)`, gateway2, org, "scheduler-"+gateway2.String(), site2)
	exec(`UPDATE fqdn_resources SET resolver_site_id=$3,resolver_node_id=$4 WHERE id=$1 AND org_id=$2`, resource, org, site2, gateway2)
	if projection, err := store.ActiveGenerations(ctx, org); err != nil || len(projection) != 0 {
		t.Fatalf("context-mismatched active generation must not project: rows=%#v err=%v", projection, err)
	}
}
