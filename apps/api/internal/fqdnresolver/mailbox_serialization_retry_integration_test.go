package fqdnresolver

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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
type enqueueModelNotifier struct {
	calls        int
	org, gateway uuid.UUID
}

func (n *enqueueModelNotifier) NotifyGatewayDNSRequest(_ context.Context, org, gateway uuid.UUID) {
	n.calls++
	n.org = org
	n.gateway = gateway
}
func TestPostgresEnqueueHeartbeatRetryDesiredBehavior(t *testing.T) {
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

	mailbox := NewPostgresGatewayDNSMailbox(pool)
	template := GatewayDNSRequest{Version: GatewayDNSRPCVersion, OrgID: org, ResourceID: resource, SiteID: site, GatewayID: gateway, ResolverConfigID: config, ResolverConfigVersion: 1, ResolverProfileID: profile, ResolverMatchSuffix: "internal", ResolverEndpoints: []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.0.53"), Port: 53, Transport: "udp"}}, Hostname: "orders.internal", RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}}
	count := func(id uuid.UUID) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM fqdn_gateway_dns_requests WHERE request_id=$1`, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	request := func() (context.Context, context.CancelFunc, GatewayDNSRequest) {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		r := template
		r.RequestID = uuid.New()
		r.Deadline, _ = c.Deadline()
		return c, cancel, r
	}
	t.Run("normal-control", func(t *testing.T) {
		c, cancel, r := request()
		defer cancel()
		if err := mailbox.Enqueue(c, r); err != nil {
			t.Fatal(err)
		}
		if count(r.RequestID) != 1 {
			t.Fatal("normal request not persisted exactly once")
		}
	})
	for _, mode := range []string{"heartbeat-40001", "capability-revocation", "original-context-cancel", "original-context-deadline"} {
		t.Run(mode, func(t *testing.T) {
			writer, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			var writerPID int
			if err = writer.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
				t.Fatal(err)
			}
			query := `UPDATE nodes SET last_seen_at=now() WHERE id=$1`
			if mode == "capability-revocation" {
				query = `UPDATE nodes SET capabilities='{"dns_resolve_rpc_version":0}'::jsonb,last_seen_at=now() WHERE id=$1`
			}
			if _, err = writer.Exec(ctx, query, gateway); err != nil {
				t.Fatal(err)
			}
			notifier := &enqueueModelNotifier{}
			mailbox.WithNotifier(notifier)
			c, cancel, r := request()
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- mailbox.Enqueue(c, r) }()
			// Evidence is an actual joined SELECT blocked by our own heartbeat backend.
			// No sleep is used as a substitute for observing the lock wait.
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			observed := false
			for !observed {
				var n int
				err = pool.QueryRow(c, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%SELECT r.org_id,r.resolver_site_id%' AND query LIKE '%JOIN nodes n%'`, writerPID).Scan(&n)
				if err != nil {
					t.Fatalf("lock-wait evidence unavailable: %v", err)
				}
				observed = n == 1
				if n > 1 {
					t.Fatal("ambiguous fixture lock wait")
				}
				if !observed {
					select {
					case <-c.Done():
						t.Fatal("original five-second context expired before lock evidence")
					case <-ticker.C:
					}
				}
			}
			t.Log("observed fixture Enqueue joined-node row lock wait")
			if mode == "original-context-cancel" {
				cancel()
			} else if mode == "original-context-deadline" {
				<-c.Done()
			} else if err = writer.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var got error
			select {
			case got = <-done:
			case <-ctx.Done():
				t.Fatal("Enqueue did not finish")
			}
			if mode == "original-context-cancel" {
				if !errors.Is(got, context.Canceled) {
					t.Fatalf("cancel result=%v want context.Canceled", got)
				}
			} else if mode == "original-context-deadline" {
				if !errors.Is(got, context.DeadlineExceeded) {
					t.Fatalf("deadline result=%v want context.DeadlineExceeded", got)
				}
			} else if mode == "capability-revocation" {
				if !errors.Is(got, ErrGatewayDNSRPCVersion) {
					t.Fatalf("aborted attempt must revalidate revoked capability: %v", got)
				}
			} else {
				if got != nil {
					var pe *pgconn.PgError
					if errors.As(got, &pe) && pe.Code == "40001" {
						t.Fatal("RED: known-aborted heartbeat transaction escaped without whole-unit retry")
					}
					t.Fatalf("retry result=%v", got)
				}
			}
			want := 0
			if mode == "heartbeat-40001" {
				want = 1
			}
			if count(r.RequestID) != want {
				t.Fatalf("mailbox insertion count != %d", want)
			}
			if notifier.calls != want {
				t.Fatalf("notifier calls=%d want%d", notifier.calls, want)
			}
			if want == 1 {
				if notifier.org != r.OrgID || notifier.gateway != r.GatewayID {
					t.Fatal("notifier identity changed")
				}
				pending, err := mailbox.PendingForGateway(ctx, org, gateway, 10)
				if err != nil {
					t.Fatal(err)
				}
				matched := false
				for _, got := range pending {
					if got.RequestID == r.RequestID {
						persisted := r
						persisted.Deadline = r.Deadline.Truncate(time.Microsecond)
						matched = sameMailboxRequest(got, persisted)
					}
				}
				if !matched {
					t.Fatal("retry changed full original request/deadline")
				}
				if err := mailbox.Enqueue(c, r); err != nil {
					t.Fatal(err)
				}
				if count(r.RequestID) != 1 || notifier.calls != 1 {
					t.Fatal("confirmed duplicate notified or inserted twice")
				}
			}
			if mode == "capability-revocation" {
				c2, cancel2, r2 := request()
				defer cancel2()
				if err := mailbox.Enqueue(c2, r2); !errors.Is(err, ErrGatewayDNSRPCVersion) {
					t.Fatalf("fresh revoked context result=%v", err)
				}
				if count(r2.RequestID) != 0 {
					t.Fatal("revoked context inserted work")
				}
				exec(`UPDATE nodes SET capabilities='{"dns_resolve_rpc_version":2}'::jsonb WHERE id=$1`, gateway)
			}
		})
	}
}
