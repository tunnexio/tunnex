package aiegress

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func fixturePolicy(t *testing.T) *Policy {
	t.Helper()
	p := &Policy{Endpoints: []Endpoint{{Name: "fixture", URL: "https://models.internal/base", AllowedCIDRs: []string{"10.20.0.0/16", "fd00::/8"}}}, ProtectedHosts: []string{"control.internal"}, DeniedCIDRs: []string{"10.20.1.0/24"}}
	if p.validate() != nil {
		t.Fatal("fixture invalid")
	}
	return p
}
func TestPolicyAddressBoundary(t *testing.T) {
	p := fixturePolicy(t)
	for _, tc := range []struct {
		name string
		ips  []string
		ok   bool
	}{{"private-approved", []string{"10.20.2.3"}, true}, {"mixed", []string{"10.20.2.3", "127.0.0.1"}, false}, {"outside", []string{"8.8.8.8"}, false}, {"denied", []string{"10.20.1.2"}, false}, {"protected-resolution", []string{"10.20.3.3"}, false}, {"loopback", []string{"127.0.0.1"}, false}, {"mapped-loopback", []string{"::ffff:127.0.0.1"}, false}, {"metadata", []string{"169.254.169.254"}, false}, {"aws-v6", []string{"fd00:ec2::254"}, false}, {"gcp-v6", []string{"fd20:ce::254"}, false}, {"azure", []string{"168.63.129.16"}, false}, {"ali", []string{"100.100.100.200"}, false}, {"transition", []string{"64:ff9b::7f00:1"}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			lookup := func(_ context.Context, h string) ([]netip.Addr, error) {
				if h == "control.internal" {
					return []netip.Addr{netip.MustParseAddr("10.20.3.3")}, nil
				}
				calls++
				out := []netip.Addr{}
				for _, raw := range tc.ips {
					out = append(out, netip.MustParseAddr(raw))
				}
				return out, nil
			}
			_, err := p.addresses(context.Background(), "models.internal:443", lookup)
			if (err == nil) != tc.ok || calls != 1 {
				t.Fatalf("boundary result %v calls%d", err, calls)
			}
		})
	}
	answers := 0
	lookup := func(_ context.Context, h string) ([]netip.Addr, error) {
		if h == "control.internal" {
			return []netip.Addr{netip.MustParseAddr("10.20.3.3")}, nil
		}
		answers++
		if answers == 1 {
			return []netip.Addr{netip.MustParseAddr("10.20.2.3")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, e := p.addresses(context.Background(), "models.internal:443", lookup); e != nil {
		t.Fatal(e)
	}
	if _, e := p.addresses(context.Background(), "models.internal:443", lookup); e == nil {
		t.Fatal("DNS rebind accepted")
	}
}
func TestPolicyFileAndURL(t *testing.T) {
	p := fixturePolicy(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	b, _ := json.Marshal(p)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("write")
	}
	loaded, e := LoadPolicy(path)
	if e != nil || !loaded.AllowsEndpoint("https://models.internal/base/") || loaded.AllowsEndpoint("https://models.internal/other") {
		t.Fatal("file exact endpoint boundary")
	}
	for _, raw := range []string{"http://user:pass@host", "https://host/?q=x", "https://host/#x", "https://host/v1", "https://host/base/v1/", "https://host/a/../b", "https://host/%2fsecret", "https://host//base", "file:///tmp/x", "https://host\\evil"} {
		if _, e := NormalizeEndpoint(raw); e == nil {
			t.Errorf("invalid endpoint accepted %s", raw)
		}
	}
	p = fixturePolicy(t)
	p.Endpoints = append(p.Endpoints, Endpoint{Name: "other", URL: "https://models.internal/other", AllowedCIDRs: []string{"0.0.0.0/0"}})
	if p.validate() == nil {
		t.Fatal("same authority CIDR widening accepted")
	}
	p = fixturePolicy(t)
	p.ProtectedHosts = nil
	if p.validate() == nil {
		t.Fatal("missing protected hosts accepted")
	}
	p = fixturePolicy(t)
	p.Endpoints[0].AllowedCIDRs = []string{"10.20.1.1/24"}
	if p.validate() == nil {
		t.Fatal("noncanonical CIDR accepted")
	}
}
