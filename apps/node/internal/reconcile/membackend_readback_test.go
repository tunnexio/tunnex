package reconcile

import (
	"context"
	"reflect"
	"testing"
)

func TestMemBackendReadbackReportsEffectiveStateAndClones(t *testing.T) {
	ctx := context.Background()
	backend := NewMemBackend()
	if err := backend.Configure(ctx, InterfaceConfig{Address: "10.99.0.1/24, fd00::1/64"}); err != nil {
		t.Fatal(err)
	}
	if err := backend.ApplyPeers(ctx, []Peer{{
		PublicKey: "peer-a", AllowedIPs: []string{"100.64.0.0/24"}, Endpoint: "192.0.2.1:51820", SiteLink: true,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := backend.ApplyRoutes(ctx, []string{
		"172.16.0.0/16", "10.99.0.9/24", "10.99.0.0/24", "fd00::9/64", "not-a-prefix",
	}, ""); err != nil {
		t.Fatal(err)
	}

	got, err := backend.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 1 || got.Peers[0].PublicKey != "peer-a" || got.Peers[0].SiteLink ||
		!reflect.DeepEqual(got.Peers[0].AllowedIPs, []string{"100.64.0.0/24"}) {
		t.Fatalf("peer readback must mirror the substrate-visible full peer set: %+v", got.Peers)
	}
	wantRoutes := []string{"10.99.0.0/24", "172.16.0.0/16", "fd00::/64"}
	if !reflect.DeepEqual(got.Routes, wantRoutes) {
		t.Fatalf("routes = %v, want canonical deduplicated effective routes %v", got.Routes, wantRoutes)
	}
	wantDetails := []OwnedRoute{
		{Family: "ipv4", Destination: "10.99.0.0/24", Device: "memory", Protocol: "static", Metric: siteRouteMetric},
		{Family: "ipv4", Destination: "172.16.0.0/16", Device: "memory", Protocol: "static", Metric: siteRouteMetric},
		{Family: "ipv6", Destination: "fd00::/64", Device: "memory", Protocol: "static", Metric: siteRouteMetric},
	}
	if !reflect.DeepEqual(got.RouteDetails, wantDetails) {
		t.Fatalf("route details = %+v, want %+v", got.RouteDetails, wantDetails)
	}
	wantRules := []ReturnRule{
		{Priority: returnRulePriority, Destination: "10.99.0.0/24", Lookup: "main"},
		{Priority: returnRulePriority, Destination: "fd00::/64", Lookup: "main"},
	}
	if !reflect.DeepEqual(got.ReturnRules, wantRules) {
		t.Fatalf("return rules = %+v, want only configured-prefix intersections %+v", got.ReturnRules, wantRules)
	}

	got.Peers[0].AllowedIPs[0] = "203.0.113.0/24"
	got.Routes[0] = "203.0.113.0/24"
	got.RouteDetails[0].Device = "foreign0"
	again, err := backend.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.Peers[0].AllowedIPs[0] != "100.64.0.0/24" || !reflect.DeepEqual(again.Routes, wantRoutes) || !reflect.DeepEqual(again.RouteDetails, wantDetails) {
		t.Fatalf("readback must not alias backend state: %+v", again)
	}
}
