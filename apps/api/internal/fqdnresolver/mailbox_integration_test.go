package fqdnresolver

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db"
)

// TestPostgresGatewayDNSMailbox is an isolated Postgres proof of the durable
// agent-pull boundary: durable request, gateway-scoped desired-state pull,
// authenticated completion, one-time response consumption, and no cross-org
// response oracle. It is skipped unless the repository's disposable admin URL
// is explicitly supplied.
func TestPostgresGatewayDNSMailbox(t *testing.T) {
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

	org, site, gateway, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'mailbox',$2,'10.252.0.0/24',true)`, org, "mailbox-"+org.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'selected')`, site, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'gateway',$3,$4)`, gateway, org, "mailbox-"+gateway.String(), site)
	exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,resolver_site_id,resolver_node_id) VALUES($1,$2,'orders','orders.internal',$3,$4)`, resource, org, site, gateway)
	config := uuid.New()
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, config, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.53'::inet,53,'udp')`, config, org)

	now := time.Now().UTC().Truncate(time.Second)
	currentNow := now
	mailbox := NewPostgresGatewayDNSMailbox(pool)
	mailbox.now = func() time.Time { return currentNow }
	request := GatewayDNSRequest{Version: GatewayDNSRPCVersion, RequestID: uuid.New(), OrgID: org, ResourceID: resource, SiteID: site, GatewayID: gateway, ResolverConfigID: config, ResolverConfigVersion: 1, ResolverEndpoints: []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.0.53"), Port: 53, Transport: "udp"}}, Hostname: "orders.internal", RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}, Deadline: now.Add(time.Minute)}
	if err := mailbox.Enqueue(ctx, request); err != nil {
		t.Fatal(err)
	}
	// Each persisted request must use the one current, same-org selected
	// (resource, Site, gateway) context. Individual FKs are not sufficient to
	// prevent a cross-tenant combination, so Enqueue locks and checks the pair.
	otherOrg, otherSite, otherGateway := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,fqdn_resources_enabled) VALUES($1,'other',$2,'10.253.0.0/24',true)`, otherOrg, "other-"+otherOrg.String()[:8])
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'other-selected')`, otherSite, otherOrg)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'other-gateway',$3,$4)`, otherGateway, otherOrg, "mailbox-"+otherGateway.String(), otherSite)
	bad := request
	bad.RequestID = uuid.New()
	bad.SiteID, bad.GatewayID = otherSite, otherGateway
	if err := mailbox.Enqueue(ctx, bad); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("cross-org context enqueue=%v want ErrSuperseded", err)
	}
	if pending, err := mailbox.PendingForGateway(ctx, org, gateway, 10); err != nil || len(pending) != 1 || !sameMailboxRequest(pending[0], request) {
		t.Fatalf("gateway pending=%#v err=%v want %#v", pending, err, request)
	}
	if other, err := mailbox.PendingForGateway(ctx, uuid.New(), gateway, 10); err != nil || len(other) != 0 {
		t.Fatalf("cross-org pending leaked=%#v err=%v", other, err)
	}
	response := responseFor(request, now, Record{Name: request.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.4"), TTL: time.Minute})
	if err := mailbox.Complete(ctx, org, gateway, response); err != nil {
		t.Fatal(err)
	}
	if got, err := mailbox.Await(ctx, request.RequestID); err != nil || got.RequestID != request.RequestID || len(got.Records) != 1 {
		t.Fatalf("await=%#v err=%v", got, err)
	}
	if err := mailbox.Complete(ctx, org, gateway, response); !errors.Is(err, ErrGatewayDNSRPCReplay) {
		t.Fatalf("second completion=%v want replay", err)
	}
	if err := mailbox.Complete(ctx, uuid.New(), gateway, response); !errors.Is(err, ErrGatewayDNSRPCIdentity) {
		t.Fatalf("cross-org completion=%v want identity", err)
	}

	// A configuration revision invalidates already-pending pull work before a
	// reconnecting gateway can query its retired endpoint snapshot.
	pendingOldConfig := request
	pendingOldConfig.RequestID = uuid.New()
	if err := mailbox.Enqueue(ctx, pendingOldConfig); err != nil {
		t.Fatal(err)
	}
	config2 := uuid.New()
	exec(`UPDATE fqdn_resolver_context_configs SET state='retired',retired_at=now() WHERE id=$1`, config)
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,2,'active')`, config2, org, site, gateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.0.54'::inet,53,'tcp')`, config2, org)
	if pending, err := mailbox.PendingForGateway(ctx, org, gateway, 10); err != nil || len(pending) != 0 {
		t.Fatalf("retired config request remained deliverable: pending=%#v err=%v", pending, err)
	}
	var oldState string
	if err := pool.QueryRow(ctx, `SELECT state FROM fqdn_gateway_dns_requests WHERE request_id=$1`, pendingOldConfig.RequestID).Scan(&oldState); err != nil || oldState != "expired" {
		t.Fatalf("retired config request state=%q err=%v want expired", oldState, err)
	}
	request.ResolverConfigID, request.ResolverConfigVersion = config2, 2
	request.ResolverEndpoints = []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.0.54"), Port: 53, Transport: "tcp"}}

	// A response for a context that was reselected between request and
	// completion is expired, not published under the newly selected gateway.
	second := request
	second.RequestID = uuid.New()
	if err := mailbox.Enqueue(ctx, second); err != nil {
		t.Fatal(err)
	}
	reselectedSite, reselectedGateway := uuid.New(), uuid.New()
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'reselected')`, reselectedSite, org)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id) VALUES($1,$2,'reselected-gateway',$3,$4)`, reselectedGateway, org, "mailbox-"+reselectedGateway.String(), reselectedSite)
	reselectedConfig := uuid.New()
	exec(`INSERT INTO fqdn_resolver_context_configs(id,org_id,site_id,gateway_id,version,state) VALUES($1,$2,$3,$4,1,'active')`, reselectedConfig, org, reselectedSite, reselectedGateway)
	exec(`INSERT INTO fqdn_resolver_context_endpoints(config_id,org_id,ordinal,address,port,transport) VALUES($1,$2,0,'10.53.1.53'::inet,53,'tcp')`, reselectedConfig, org)
	exec(`UPDATE fqdn_resources SET resolver_site_id=$3,resolver_node_id=$4 WHERE id=$1 AND org_id=$2`, resource, org, reselectedSite, reselectedGateway)
	late := responseFor(second, now, Record{Name: second.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.5"), TTL: time.Minute})
	if err := mailbox.Complete(ctx, org, gateway, late); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("reselected context completion=%v want ErrSuperseded", err)
	}
	if pending, err := mailbox.PendingForGateway(ctx, org, gateway, 10); err != nil || len(pending) != 0 {
		t.Fatalf("superseded request remained deliverable to prior gateway: pending=%#v err=%v", pending, err)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM fqdn_gateway_dns_requests WHERE request_id=$1`, second.RequestID).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("superseded request state=%q err=%v, want durable expired", state, err)
	}

	// A late response under an otherwise-current context must also commit terminal
	// expiry. Without this, a retry could keep a stale request pending forever.
	stale := second
	stale.RequestID = uuid.New()
	stale.SiteID, stale.GatewayID = reselectedSite, reselectedGateway
	stale.ResolverConfigID, stale.ResolverConfigVersion = reselectedConfig, 1
	stale.ResolverEndpoints = []ResolverEndpoint{{Address: netip.MustParseAddr("10.53.1.53"), Port: 53, Transport: "tcp"}}
	stale.Deadline = now.Add(time.Second)
	if err := mailbox.Enqueue(ctx, stale); err != nil {
		t.Fatal(err)
	}
	currentNow = now.Add(2 * time.Second)
	staleResponse := responseFor(stale, now, Record{Name: stale.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.6"), TTL: time.Minute})
	if err := mailbox.Complete(ctx, org, reselectedGateway, staleResponse); !errors.Is(err, ErrGatewayDNSRPCStale) {
		t.Fatalf("late response completion=%v want ErrGatewayDNSRPCStale", err)
	}
	if pending, err := mailbox.PendingForGateway(ctx, org, reselectedGateway, 10); err != nil || len(pending) != 0 {
		t.Fatalf("stale request remained pending: pending=%#v err=%v", pending, err)
	}
	if err := pool.QueryRow(ctx, `SELECT state FROM fqdn_gateway_dns_requests WHERE request_id=$1`, stale.RequestID).Scan(&state); err != nil || state != "expired" {
		t.Fatalf("stale request state=%q err=%v, want durable expired", state, err)
	}
}

// PostgreSQL scans timestamptz using the local Location while request creation
// uses UTC. Equal compares the persisted instant without discarding any other
// identity field of the durable request.
func sameMailboxRequest(got, want GatewayDNSRequest) bool {
	return got.Version == want.Version && got.RequestID == want.RequestID && got.OrgID == want.OrgID &&
		got.ResourceID == want.ResourceID && got.SiteID == want.SiteID && got.GatewayID == want.GatewayID &&
		got.ResolverConfigID == want.ResolverConfigID && got.ResolverConfigVersion == want.ResolverConfigVersion && slices.Equal(got.ResolverEndpoints, want.ResolverEndpoints) &&
		got.Hostname == want.Hostname && slices.Equal(got.RecordTypes, want.RecordTypes) && got.Deadline.Equal(want.Deadline)
}
