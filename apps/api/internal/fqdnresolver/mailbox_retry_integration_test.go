package fqdnresolver

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestPostgresMailboxSerializationRetry(t *testing.T) {
	ctx, pool := testpostgres.NewAtVersion(t, 219)
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

	exec(`CREATE SEQUENCE mailbox_retry_test_sequence`)
	exec(`CREATE FUNCTION mailbox_retry_test_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='completed' AND nextval('mailbox_retry_test_sequence')=1 THEN RAISE EXCEPTION 'test serialization refusal' USING ERRCODE='40001'; END IF; RETURN NEW; END $$`)
	exec(`CREATE TRIGGER mailbox_retry_test_trigger BEFORE UPDATE ON fqdn_gateway_dns_requests FOR EACH ROW EXECUTE FUNCTION mailbox_retry_test_failure()`)
	for _, kind := range []string{"success", "expiry", "context-change", "concurrent", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			exec(`SELECT setval('mailbox_retry_test_sequence',1,false)`)
			exec(`UPDATE fqdn_resolver_context_configs SET state='active',retired_at=NULL WHERE id=$1`, config)
			now := time.Now().UTC().Truncate(time.Second)
			mailbox := NewPostgresGatewayDNSMailbox(pool)
			request := GatewayDNSRequest{Version: GatewayDNSRPCVersion, RequestID: uuid.New(), OrgID: org, ResourceID: resource, SiteID: site, GatewayID: gateway, ResolverConfigID: config, ResolverConfigVersion: 1, ResolverProfileID: profile, ResolverMatchSuffix: "internal", ResolverEndpoints: []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.0.53"), Port: 53, Transport: "udp"}}, Hostname: "orders.internal", RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}, Deadline: now.Add(5 * time.Second)}
			if err := mailbox.Enqueue(ctx, request); err != nil {
				t.Fatal(err)
			}
			response := responseFor(request, now, Record{Name: request.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.4"), TTL: time.Minute})
			if kind == "expiry" {
				calls := 0
				mailbox.now = func() time.Time {
					calls++
					if calls >= 3 {
						return request.Deadline.Add(time.Millisecond)
					}
					return now
				}
			}
			var err error
			switch kind {
			case "canceled":
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				err = mailbox.Complete(canceled, org, gateway, response)
				if !errors.Is(err, context.Canceled) {
					t.Fatal("canceled completion dispatched")
				}

			case "context-change":
				attempts := 0
				err = retryMailboxCompletion(ctx, func() error {
					attempts++
					e := mailbox.completeAttempt(ctx, org, gateway, response)
					if attempts == 1 {
						if !mailboxSerializationFailure(e) {
							t.Fatal("injected serialization missing")
						}
						exec(`UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE id=$1`, config)
					}
					return e
				})
				if !errors.Is(err, ErrSuperseded) {
					t.Fatalf("changed context=%v", err)
				}
			case "concurrent":
				start := make(chan struct{})
				out := make(chan error, 2)
				var wg sync.WaitGroup
				for i := 0; i < 2; i++ {
					wg.Add(1)
					go func() { defer wg.Done(); <-start; out <- mailbox.Complete(ctx, org, gateway, response) }()
				}
				close(start)
				wg.Wait()
				close(out)
				success, replay := 0, 0
				for e := range out {
					if e == nil {
						success++
					} else if errors.Is(e, ErrGatewayDNSRPCReplay) {
						replay++
					} else {
						t.Fatalf("concurrent completion=%v", e)
					}
				}
				if success != 1 || replay != 1 {
					t.Fatal("terminal replay contract changed")
				}
			default:
				err = mailbox.Complete(ctx, org, gateway, response)
				if kind == "expiry" {
					if !errors.Is(err, ErrGatewayDNSRPCStale) {
						t.Fatalf("expiry=%v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			var state string
			if e := pool.QueryRow(ctx, `SELECT state FROM fqdn_gateway_dns_requests WHERE request_id=$1`, request.RequestID).Scan(&state); e != nil {
				t.Fatal(e)
			}
			want := "completed"
			if kind == "canceled" {
				want = "pending"
			}
			if kind == "expiry" || kind == "context-change" {
				want = "expired"
			}
			if state != want {
				t.Fatalf("state=%s want%s", state, want)
			}
			var persisted time.Time
			if err := pool.QueryRow(ctx, `SELECT deadline FROM fqdn_gateway_dns_requests WHERE request_id=$1`, request.RequestID).Scan(&persisted); err != nil || !persisted.Equal(request.Deadline) {
				t.Fatal("original persisted deadline changed")
			}
			if kind == "success" {
				var attempts int64
				if err := pool.QueryRow(ctx, `SELECT last_value FROM mailbox_retry_test_sequence`).Scan(&attempts); err != nil || attempts != 2 {
					t.Fatal("whole transaction retry missing")
				}
			}

		})
	}
}
