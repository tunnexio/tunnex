package fqdnresolver

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
)

// Reproduces the live cross-resource cycle using real mailbox/store operations:
// mailbox owns node/site then waits for config; withdrawal owns config then its
// generation INSERT needs a node/site FK lock. A private BEFORE INSERT barrier
// controls the exact interleaving without adding production hooks or deadlines.
func TestPostgresMailboxWithdrawalLockOrder(t *testing.T) {
	adminURL := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if adminURL == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL for disposable PostgreSQL lock-order proof")
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
	name := "tnx_dns_lock_" + uuid.NewString()[:8]
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") }()
	testURL := *base
	testURL.Path = "/" + name
	if err = db.MigrateTo(testURL.String(), 230); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	org, site, gateway, config, profile := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'lock-order',$2,'10.252.0.0/24',true)`, org, "lock-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities) VALUES($1,$2,'gateway',$3,$4,'{"dns_resolve_rpc_version":2}')`, gateway, org, "lock-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53',53,'udp')`, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profiles(id,config_id,org_id,ordinal,name,provider_hint) VALUES($1,$2,$3,0,'Internal','aws')`, profile, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profile_suffixes(profile_id,config_id,org_id,suffix) VALUES($1,$2,$3,'internal')`, profile, config, org)
	exec(`INSERT INTO fqdn_resolver_context_profile_endpoints(profile_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53',53,'udp')`, profile, org)
	endpoints := []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.0.53"), Port: 53, Transport: "udp"}}
	for _, mode := range []string{"enqueue", "complete"} {
		t.Run(mode, func(t *testing.T) {
			a, b := uuid.New(), uuid.New()
			exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,$3,$4,$5,$6)`, a, org, mode+"-a", mode+".internal", site, gateway)
			exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,$3,$4,$5,$6)`, b, org, mode+"-b", "sibling-"+mode+".internal", site, gateway)
			w := Work{OrgID: org, ResourceID: b, Hostname: "sibling-" + mode + ".internal", Context: Context{ResolverID: site.String(), GatewayID: gateway.String()}, ResolverConfig: ResolverConfig{ID: config.String(), Version: 1, ProfileID: profile.String(), MatchedSuffix: "internal", Endpoints: endpoints}}
			store := NewPostgresStore(pool)
			goodAt := time.Now().UTC().Truncate(time.Microsecond)
			if err := store.Publish(ctx, w, Generation{TTL: time.Minute, ResolvedAt: goodAt, Addresses: []netip.Addr{netip.MustParseAddr("10.2.3.4")}}); err != nil {
				t.Fatal(err)
			}
			w.ExpectedGeneration = 1
			mailbox := NewPostgresGatewayDNSMailbox(pool)
			requestCtx, requestCancel := context.WithTimeout(ctx, 5*time.Second)
			defer requestCancel()
			deadline, _ := requestCtx.Deadline()
			r := GatewayDNSRequest{Version: GatewayDNSRPCVersion, RequestID: uuid.New(), OrgID: org, ResourceID: a, SiteID: site, GatewayID: gateway, ResolverConfigID: config, ResolverConfigVersion: 1, ResolverProfileID: profile, ResolverMatchSuffix: "internal", ResolverEndpoints: endpoints, Hostname: mode + ".internal", RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}, Deadline: deadline}
			response := responseFor(r, goodAt, Record{Name: r.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.5"), TTL: time.Minute})
			if mode == "complete" {
				if err := mailbox.Enqueue(requestCtx, r); err != nil {
					t.Fatal(err)
				}
			}
			barrier, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer barrier.Rollback(context.Background())
			var barrierPID int
			if err = barrier.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&barrierPID); err != nil {
				t.Fatal(err)
			}
			// A separate two-key advisory namespace cannot collide with the production
			// one-key hashtextextended(org) lock.
			if _, err = barrier.Exec(ctx, `SELECT pg_advisory_xact_lock(730221,1)`); err != nil {
				t.Fatal(err)
			}
			exec(fmt.Sprintf(`CREATE FUNCTION pause_withdrawal_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.resource_id='%s'::uuid AND NEW.state='withdrawn' THEN PERFORM pg_advisory_xact_lock(730221,1); END IF; RETURN NEW; END $$`, b))
			exec(`CREATE TRIGGER pause_withdrawal BEFORE INSERT ON fqdn_resource_answer_generations FOR EACH ROW EXECUTE FUNCTION pause_withdrawal_insert()`)
			defer func() {
				// Release the private barrier before DDL cleanup even when a lock
				// witness fails; otherwise DROP waits behind our paused writer.
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = barrier.Rollback(cleanup)
				for _, query := range []string{`DROP TRIGGER pause_withdrawal ON fqdn_resource_answer_generations`, `DROP FUNCTION pause_withdrawal_insert()`} {
					if _, err := pool.Exec(cleanup, query); err != nil {
						t.Errorf("private barrier cleanup: %v", err)
					}
				}
			}()
			waitBlocked := func(blocker int, pattern string) int {
				t.Helper()
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					var pid int
					err := pool.QueryRow(requestCtx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2`, blocker, pattern).Scan(&pid)
					if err == nil {
						return pid
					}
					if err != pgx.ErrNoRows {
						t.Fatal(err)
					}
					select {
					case <-requestCtx.Done():
						t.Fatal("no exact lock-wait witness before original deadline")
					case <-ticker.C:
					}
				}
			}
			withdrawalDone := make(chan error, 1)
			at := goodAt.Add(time.Millisecond)
			go func() { withdrawalDone <- store.Withdraw(ctx, w, WithdrawalTimeout, at) }()
			writerPID := waitBlocked(barrierPID, "%INSERT INTO fqdn_resource_answer_generations%")
			mailboxDone := make(chan error, 1)
			go func() {
				if mode == "enqueue" {
					mailboxDone <- mailbox.Enqueue(requestCtx, r)
				} else {
					mailboxDone <- mailbox.Complete(requestCtx, org, gateway, response)
				}
			}()
			mailboxPID := waitBlocked(writerPID, "%")
			t.Logf("real %s backend %d waits for sibling withdrawal %d at its held insert boundary", mode, mailboxPID, writerPID)
			if err = barrier.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			withdrawErr, mailboxErr := <-withdrawalDone, <-mailboxDone
			if withdrawErr != nil || mailboxErr != nil {
				t.Fatalf("cross-resource cycle: withdrawal=%v mailbox=%v", withdrawErr, mailboxErr)
			}
			if requestCtx.Err() != nil {
				t.Fatal("original request deadline exhausted")
			}
			var count int
			var storedDeadline time.Time
			var state string
			if err = pool.QueryRow(ctx, `SELECT count(*),min(deadline),min(state) FROM fqdn_gateway_dns_requests WHERE request_id=$1`, r.RequestID).Scan(&count, &storedDeadline, &state); err != nil {
				t.Fatal(err)
			}
			if count != 1 || !storedDeadline.Equal(deadline.Truncate(time.Microsecond)) {
				t.Fatal("request identity/deadline changed")
			}
			if mode == "enqueue" {
				if state != "pending" {
					t.Fatal(state)
				}
				if err = mailbox.Complete(requestCtx, org, gateway, response); err != nil {
					t.Fatal(err)
				}
			} else if state != "completed" {
				t.Fatal(state)
			}
			var active, withdrawn int
			var lastGood time.Time
			if err = pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE state='active'),count(*) FILTER(WHERE state='withdrawn'),max(last_good_at) FROM fqdn_resource_answer_generations WHERE resource_id=$1`, b).Scan(&active, &withdrawn, &lastGood); err != nil {
				t.Fatal(err)
			}
			if active != 0 || withdrawn != 2 || !lastGood.Equal(goodAt) {
				t.Fatalf("withdrawal/history changed active=%d withdrawn=%d lastGood=%v", active, withdrawn, lastGood)
			}
			if _, err = mailbox.Await(requestCtx, r.RequestID); err != nil {
				t.Fatal(err)
			}
		})
	}
}
