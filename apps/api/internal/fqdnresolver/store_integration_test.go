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
	if err := db.MigrateTo(testURL.String(), 112); err != nil {
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

	hook := &committedHook{t: t, pool: pool, resource: resource}
	store := NewPostgresStore(pool).WithAfterCommit(hook)
	w := Work{OrgID: org, ResourceID: resource, Hostname: "orders.internal", Context: Context{ResolverID: site.String(), GatewayID: gateway.String()}}
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
}
