package fqdnresolver

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"reflect"
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
	if err := db.MigrateTo(testURL.String(), 114); err != nil {
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

	now := time.Now().UTC().Truncate(time.Second)
	mailbox := NewPostgresGatewayDNSMailbox(pool)
	mailbox.now = func() time.Time { return now }
	request := GatewayDNSRequest{Version: GatewayDNSRPCVersion, RequestID: uuid.New(), OrgID: org, ResourceID: resource, SiteID: site, GatewayID: gateway, Hostname: "orders.internal", RecordTypes: []RecordType{TypeA, TypeAAAA, TypeCNAME}, Deadline: now.Add(time.Minute)}
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
	if pending, err := mailbox.PendingForGateway(ctx, org, gateway, 10); err != nil || len(pending) != 1 || !reflect.DeepEqual(pending[0], request) {
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
	exec(`UPDATE fqdn_resources SET resolver_site_id=$3,resolver_node_id=$4 WHERE id=$1 AND org_id=$2`, resource, org, reselectedSite, reselectedGateway)
	late := responseFor(second, now, Record{Name: second.Hostname, Type: TypeA, Address: netip.MustParseAddr("10.2.3.5"), TTL: time.Minute})
	if err := mailbox.Complete(ctx, org, gateway, late); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("reselected context completion=%v want ErrSuperseded", err)
	}
}
