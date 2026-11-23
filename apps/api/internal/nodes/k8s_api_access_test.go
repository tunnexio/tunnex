package nodes

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// K8N-3: what a gateway may write about the cluster's API into its node's capabilities is a closed set.
func TestNormalizeK8sAPIEndpointState(t *testing.T) {
	for _, known := range []string{"", "ready", "endpoints_on_gateway_node", "no_ready_endpoints", "endpoints_unavailable", "invalid_vip", "invalid_port", "all_ports_unsupported", "port_range_unsupported"} {
		if got := NormalizeK8sAPIEndpointState(known); got != known {
			t.Fatalf("%q must be kept, got %q", known, got)
		}
	}
	for _, other := range []string{"READY", "ok", "<script>", "endpoints_on_gateway_node; drop table", "a very long free text an agent should never be able to store"} {
		if got := NormalizeK8sAPIEndpointState(other); got != K8sAPIEndpointUnknown {
			t.Fatalf("%q must become %q, got %q", other, K8sAPIEndpointUnknown, got)
		}
	}
	// It is read back through the capabilities document like every other agent-reported field.
	raw, _ := json.Marshal(map[string]any{"k8s_api_endpoint": K8sAPIEndpointOnGatewayNode})
	if got := Capabilities(raw).K8sAPIEndpoint; got != K8sAPIEndpointOnGatewayNode {
		t.Fatalf("capabilities read back %q", got)
	}
	if got := Capabilities([]byte(`{"k8s_endpoints_unavailable":false}`)).K8sAPIEndpoint; got != "" {
		t.Fatalf("an older gateway reports nothing, got %q", got)
	}
}

// K8N-3 (DB): a cluster whose API access is on has ONE more mapping on its gateway, default/kubernetes on
// TCP 443 under the name the mechanism already produces, and its gateway answers DNS for the cluster's
// zone even when no Service is exposed. Off, or never on, changes nothing.
func TestLoadSiteTopologyCarriesTheClusterAPIMapping(t *testing.T) {
	dsn := os.Getenv("TUNNEX_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TUNNEX_TEST_DATABASE_URL to run this integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	org, site, cluster, connector, edge, endpoint := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ex := func(q string, a ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, q, a...); e != nil {
			t.Fatalf("seed %q: %v", q, e)
		}
	}
	ex(`INSERT INTO organizations (id,name,slug,pool_cidr) VALUES ($1,'K',$2,'10.99.0.0/24')`, org, "ka-"+org.String()[:8])
	ex(`INSERT INTO sites (id,org_id,name) VALUES ($1,$2,'A')`, site, org)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,status) VALUES ($1,$2,'connector',$3,$4,'c2VydmVycHVia2V5MDAwMDAwMDAwMDAwMDAwMDAwMD0=','172.31.1.10:51820','active')`, connector, org, "ka-"+connector.String(), site)
	ex(`INSERT INTO nodes (id,org_id,name,cert_serial,site_id,wg_public_key,endpoint,status) VALUES ($1,$2,'edge',$3,$4,'ZWRnZXB1YmtleTAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=','172.31.1.11:51820','active')`, edge, org, "ka-"+edge.String(), site)
	ex(`INSERT INTO k8s_clusters (id,org_id,site_id,connector_node_id,name,vip_range,service_cidr,dns_zone,dns_vip) VALUES ($1,$2,$3,$4,'prod','100.64.0.0/24','10.96.0.0/12','k8s.acme.com','100.64.0.2')`, cluster, org, site, connector)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org) })

	svc := &Service{pool: pool, q: sqlc.New(pool)}
	load := func() siteTopology {
		t.Helper()
		topo, e := svc.loadSiteTopology(ctx, org)
		if e != nil {
			t.Fatal(e)
		}
		return topo
	}
	servedZones := func() int {
		t.Helper()
		zones, e := sqlc.New(pool).ListK8sServedZonesForOrg(ctx, org)
		if e != nil {
			t.Fatal(e)
		}
		return len(zones)
	}

	// Off (never enabled): nothing for this cluster, as before the feature.
	if topo := load(); len(topo.vipMappings[connector]) != 0 || len(topo.k8sDNS[connector]) != 0 {
		t.Fatalf("API access off must program nothing: vip=%+v dns=%+v", topo.vipMappings, topo.k8sDNS)
	}

	// On: exactly one mapping, on the cluster's gateway only.
	ex(`INSERT INTO k8s_api_endpoints (id,org_id,cluster_id,enabled,vip,enabled_at) VALUES ($1,$2,$3,true,'100.64.0.3',now())`, endpoint, org, cluster)
	topo := load()
	mappings := topo.vipMappings[connector]
	if len(mappings) != 1 {
		t.Fatalf("want one mapping for the cluster API, got %+v", mappings)
	}
	m := mappings[0]
	if m.VIP != "100.64.0.3" || m.Namespace != "default" || m.Service != "kubernetes" || m.Protocol != "tcp" || m.PortLow != 443 || m.PortHigh != 443 ||
		m.DNSName != "kubernetes.default.svc.prod.k8s.acme.com" || m.ServiceID != endpoint.String() || m.ServiceCIDR != "10.96.0.0/12" {
		t.Fatalf("cluster API mapping = %+v", m)
	}
	if len(topo.vipMappings[edge]) != 0 {
		t.Fatalf("only the cluster's own gateway maps the API, the edge got %+v", topo.vipMappings[edge])
	}
	zones := topo.k8sDNS[connector]
	if len(zones) != 1 || zones[0].ListenVIP != "100.64.0.2" || zones[0].Zone != "prod.k8s.acme.com" {
		t.Fatalf("the gateway must answer DNS for the cluster's zone for an API-only cluster, got %+v", zones)
	}
	if got := topo.k8sConnectors[connector].vips; len(got) != 2 || got[0] != "100.64.0.2/32" || got[1] != "100.64.0.3/32" {
		t.Fatalf("the API address and the DNS address must be routed to the cluster's gateway, got %v", got)
	}
	// The Service-only zone query is untouched; the API's zones are a separate read.
	if servedZones() != 0 {
		t.Fatal("ListK8sServedZonesForOrg must stay Service-only")
	}
	apiZones, e := sqlc.New(pool).ListK8sAPIServedZonesForOrg(ctx, org)
	if e != nil || len(apiZones) != 1 || apiZones[0].Name != "prod" || apiZones[0].DnsZone != "k8s.acme.com" || apiZones[0].DnsVip != "100.64.0.2" {
		t.Fatalf("API served zones = %+v err=%v", apiZones, e)
	}

	// Beside an exposed Service: both are mapped, one DNS zone entry.
	ex(`INSERT INTO k8s_services (id,org_id,cluster_id,name,namespace,protocol,port_low,port_high,vip) VALUES ($1,$2,$3,'web','shop','tcp',80,80,'100.64.0.5')`, uuid.New(), org, cluster)
	topo = load()
	if len(topo.vipMappings[connector]) != 2 || len(topo.k8sDNS[connector]) != 1 {
		t.Fatalf("Service and API side by side: vip=%+v dns=%+v", topo.vipMappings[connector], topo.k8sDNS[connector])
	}

	// Off again: the API mapping goes, the Service's stays.
	ex(`UPDATE k8s_api_endpoints SET enabled=false, vip=NULL WHERE id=$1`, endpoint)
	topo = load()
	if got := topo.vipMappings[connector]; len(got) != 1 || got[0].Service != "web" {
		t.Fatalf("turning API access off must withdraw only the API mapping, got %+v", got)
	}
}
