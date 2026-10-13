package bgp

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// Captured native GCP ens4 /32 + approved routed LAN input. The generic probe
// must refuse it; only the controller's separately proven exact export path
// may use the explicit proof-aware boundary.
func TestGCPRoutedExportRequiresExplicitProof(t *testing.T) {
	raw, err := os.ReadFile("testdata/gcp_routed_export.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture")
	}
	read := func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "-j -d link show":
			return fixture["links"], nil
		case "-j -4 addr show":
			return fixture["addresses"], nil
		case "-j -4 route show table main":
			return fixture["main_routes"], nil
		case "-j -4 route get 10.70.0.0":
			return fixture["selected"], nil
		}
		return nil, ErrPackage
	}
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.70.0.0/24")}
	strict := func(ctx context.Context, p []netip.Prefix) error { return probeLocalReachability(p, read) }
	if proveProcessLocalExport(context.Background(), prefixes, nil, strict) == nil {
		t.Fatal("generic probe admitted unproven GCP routed topology")
	}
	calls := 0
	proof := func(ctx context.Context, p []netip.Prefix) error {
		calls++
		if len(p) != 1 || p[0] != prefixes[0] {
			return ErrPackage
		}
		return nil
	}
	if proveProcessLocalExport(context.Background(), prefixes, proof, strict) != nil || calls != 1 {
		t.Fatal("explicit exact proof refused")
	}
	originalPrefix := prefixes[0]
	if proveProcessLocalExport(context.Background(), prefixes, func(_ context.Context, p []netip.Prefix) error {
		p[0] = netip.MustParsePrefix("10.99.0.0/24")
		return nil
	}, strict) != nil || prefixes[0] != originalPrefix {
		t.Fatal("proof mutated immutable caller config")
	}

	if proveProcessLocalExport(context.Background(), []netip.Prefix{netip.MustParsePrefix("10.71.0.0/24")}, proof, strict) == nil {
		t.Fatal("changed export admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if proveProcessLocalExport(ctx, prefixes, proof, strict) == nil {
		t.Fatal("cancelled proof admitted")
	}
	if proveProcessLocalExport(context.Background(), prefixes, func(context.Context, []netip.Prefix) error { return ErrPackage }, strict) == nil {
		t.Fatal("failed explicit proof admitted")
	}
}
