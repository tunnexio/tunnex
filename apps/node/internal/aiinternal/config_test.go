package aiinternal

import (
	"net/netip"
	"testing"

	"github.com/tunnexio/tunnex/apps/node/internal/control"
)

const testEndpointID = "0b6f7c1e-3a52-4c1d-9e8f-2a7b5c4d3e21"

func validDoc() control.AIInternalDesired {
	return control.AIInternalDesired{Version: 1, Endpoint: &control.AIInternalEndpoint{
		ID: testEndpointID, Revision: 3, ListenAddresses: []string{"10.123.0.1", "192.168.10.5"}, Port: 9443,
		DNSName: "ai.internal.example", SourceCIDRs: []string{"10.20.0.0/16", "192.168.10.0/24"}, TLSMode: TLSModeTunnexCA,
	}}
}

func TestParseDesiredAcceptsTheContract(t *testing.T) {
	ep, err := ParseDesired(validDoc())
	if err != nil {
		t.Fatal(err)
	}
	if ep.ID != testEndpointID || ep.Revision != 3 || ep.Port != 9443 || ep.DNSName != "ai.internal.example" || ep.TLSMode != TLSModeTunnexCA {
		t.Fatalf("endpoint: %+v", ep)
	}
	if len(ep.Addresses) != 2 || ep.Addresses[0] != netip.MustParseAddr("10.123.0.1") || ep.Addresses[1] != netip.MustParseAddr("192.168.10.5") {
		t.Fatalf("addresses: %v", ep.Addresses)
	}
	if len(ep.Sources) != 2 || ep.Sources[0] != netip.MustParsePrefix("10.20.0.0/16") {
		t.Fatalf("sources: %v", ep.Sources)
	}
	doc := validDoc()
	doc.Endpoint.DNSName, doc.Endpoint.TLSMode, doc.Endpoint.ListenAddresses = "", TLSModeCustom, []string{"172.16.0.1"}
	if _, err := ParseDesired(doc); err != nil {
		t.Fatalf("an address-only custom endpoint was refused: %v", err)
	}
}

func TestParseDesiredWithoutAnEndpointIsOff(t *testing.T) {
	ep, err := ParseDesired(control.AIInternalDesired{Version: 1})
	if err != nil || ep != nil {
		t.Fatalf("ep=%v err=%v", ep, err)
	}
}

func TestParseDesiredRefusesEverythingElse(t *testing.T) {
	cases := map[string]func(*control.AIInternalDesired){
		"version 0":                  func(d *control.AIInternalDesired) { d.Version = 0 },
		"version 2":                  func(d *control.AIInternalDesired) { d.Version = 2 },
		"version 2 without endpoint": func(d *control.AIInternalDesired) { d.Version = 2; d.Endpoint = nil },
		"id not a uuid":              func(d *control.AIInternalDesired) { d.Endpoint.ID = "endpoint-1" },
		"id upper case":              func(d *control.AIInternalDesired) { d.Endpoint.ID = "0B6F7C1E-3A52-4C1D-9E8F-2A7B5C4D3E21" },
		"revision 0":                 func(d *control.AIInternalDesired) { d.Endpoint.Revision = 0 },
		"no address":                 func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = nil },
		"three addresses": func(d *control.AIInternalDesired) {
			d.Endpoint.ListenAddresses = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
		},
		"duplicate address":     func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"10.0.0.1", "10.0.0.1"} },
		"public address":        func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"203.0.113.7"} },
		"loopback address":      func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"127.0.0.1"} },
		"unspecified address":   func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"0.0.0.0"} },
		"IPv6 address":          func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"fd00::1"} },
		"mapped address":        func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"::ffff:10.0.0.1"} },
		"non-canonical address": func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"010.0.0.1"} },
		"address with a port":   func(d *control.AIInternalDesired) { d.Endpoint.ListenAddresses = []string{"10.0.0.1:9443"} },
		"port 0":                func(d *control.AIInternalDesired) { d.Endpoint.Port = 0 },
		"port 443":              func(d *control.AIInternalDesired) { d.Endpoint.Port = 443 },
		"port 1023":             func(d *control.AIInternalDesired) { d.Endpoint.Port = 1023 },
		"port 65536":            func(d *control.AIInternalDesired) { d.Endpoint.Port = 65536 },
		"the AI VPN port":       func(d *control.AIInternalDesired) { d.Endpoint.Port = 8083 },
		"the MCP gateway port":  func(d *control.AIInternalDesired) { d.Endpoint.Port = 8084 },
		"no source":             func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = nil },
		"33 sources": func(d *control.AIInternalDesired) {
			d.Endpoint.SourceCIDRs = nil
			for i := 0; i < 33; i++ {
				d.Endpoint.SourceCIDRs = append(d.Endpoint.SourceCIDRs, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16).String())
			}
		},
		"public source":          func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"0.0.0.0/0"} },
		"source spanning public": func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"10.0.0.0/7"} },
		"source with host bits":  func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"10.20.0.1/16"} },
		"source without bits":    func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"10.20.0.1"} },
		"IPv6 source":            func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"fd00::/8"} },
		"duplicate source":       func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"10.20.0.0/16", "10.20.0.0/16"} },
		"loopback source":        func(d *control.AIInternalDesired) { d.Endpoint.SourceCIDRs = []string{"127.0.0.0/8"} },
		"tls mode empty":         func(d *control.AIInternalDesired) { d.Endpoint.TLSMode = "" },
		"tls mode acme":          func(d *control.AIInternalDesired) { d.Endpoint.TLSMode = "acme" },
		"dns name upper case":    func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "AI.internal.example" },
		"dns name trailing dot":  func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "ai.internal.example." },
		"dns name wildcard":      func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "*.internal.example" },
		"dns name underscore":    func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "ai_gw.internal.example" },
		"dns name an address":    func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "10.0.0.1" },
		"dns name hyphen edge":   func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "-ai.internal.example" },
		"dns name empty label":   func(d *control.AIInternalDesired) { d.Endpoint.DNSName = "ai..example" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := validDoc()
			mutate(&doc)
			if ep, err := ParseDesired(doc); err == nil {
				t.Fatalf("accepted: %+v", ep)
			}
		})
	}
}

func TestAllowsChecksTheUnmappedTCPPeerOnly(t *testing.T) {
	sources := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	for addr, want := range map[string]bool{
		"10.20.3.4":        true,
		"::ffff:10.20.3.4": true,
		"10.21.0.1":        false,
		"192.168.1.1":      false,
		"fd00::1":          false,
	} {
		if got := allows(sources, netip.MustParseAddr(addr)); got != want {
			t.Fatalf("%s: got %v want %v", addr, got, want)
		}
	}
	if allows(sources, netip.Addr{}) {
		t.Fatal("an invalid peer was allowed")
	}
}
