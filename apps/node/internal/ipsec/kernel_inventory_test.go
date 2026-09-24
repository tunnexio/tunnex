package ipsec

import (
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
)

const kernelLinksFixture = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP"],"mtu":65536},{"ifindex":10,"ifname":"ipsec-a","flags":["UP","LOWER_UP"],"linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0x14"}}},{"ifindex":11,"ifname":"ipsec-b","flags":[],"linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0xffffffff"}}}]`
const kernelRoutesFixture = `[{"type":"1","dst":"10.20.0.0/16","dev":"ipsec-a","table":"200","protocol":"99","scope":"0","metric":7,"gateway":"169.254.10.2","prefsrc":"10.0.0.1","flags":[]},{"type":"1","dst":"default","dev":"ipsec-b","table":"4294967295","protocol":"255","scope":"253","flags":[]},{"type":"2","dst":"127.0.0.1","dev":"lo","table":"255","protocol":"2","scope":"254"}]`

func TestKernelInventoryRealisticFacts(t *testing.T) {
	got, err := ParseKernelInventory("net:[4026531992]", []byte(kernelLinksFixture), []byte(kernelRoutesFixture))
	if err != nil {
		t.Fatal(err)
	}
	if got.Namespace != "net:[4026531992]" || len(got.Links) != 2 || len(got.Routes) != 2 {
		t.Fatalf("unexpected inventory %+v", got)
	}
	if got.Links[0] != (KernelLink{Name: "ipsec-a", Index: 10, XFRMID: 20, Up: true}) || got.Links[1].Up || got.Links[1].XFRMID != 1<<32-1 {
		t.Fatalf("link facts: %+v", got.Links)
	}
	r := got.Routes[0]
	if r.OutputInterface != 10 || r.Table != 200 || r.Protocol != 99 || r.Metric != 7 || r.Scope != 0 || r.Gateway != netip.MustParseAddr("169.254.10.2") || r.PreferredSource != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("route facts: %+v", r)
	}
	if got.Routes[1].Destination != netip.MustParsePrefix("0.0.0.0/0") || got.Routes[1].Metric != 0 {
		t.Fatal("default facts lost")
	}
}
func TestKernelInventoryEmptyAndHostRoute(t *testing.T) {
	got, err := ParseKernelInventory("net:[1]", []byte(`[]`), []byte(`[]`))
	if err != nil || len(got.Links) != 0 || len(got.Routes) != 0 {
		t.Fatal("empty observation refused")
	}
	routes := strings.Replace(kernelRoutesFixture, "10.20.0.0/16", "10.20.0.1", 1)
	got, err = ParseKernelInventory("net:[1]", []byte(kernelLinksFixture), []byte(routes))
	if err != nil || got.Routes[0].Destination != netip.MustParsePrefix("10.20.0.1/32") {
		t.Fatalf("host route not normalized: %+v %v", got, err)
	}
}
func TestKernelInventoryNamespace(t *testing.T) {
	for _, v := range []string{"", "owned", "net:[0]", "net:[01]", "net:[-1]", "net:[18446744073709551616]", "net:[1]extra", " net:[1]"} {
		t.Run(v, func(t *testing.T) {
			_, err := ParseKernelInventory(v, []byte(`[]`), []byte(`[]`))
			if !errors.Is(err, ErrKernelInventoryInvalid) {
				t.Fatal("invalid namespace accepted")
			}
		})
	}
}
func TestKernelInventoryJSONBoundary(t *testing.T) {
	for _, v := range []string{`null`, `{}`, `[null]`, `[] null`, `[] {}`, `[`, `[{"ifindex":1,"ifindex":2}]`, `[{"ifindex":1,"\u0069findex":2}]`, strings.Repeat(" ", 1<<20) + `[]`, `[` + strings.Repeat(`{},`, 4096) + `{}]`} {
		t.Run(v[:min(len(v), 60)], func(t *testing.T) {
			for _, links := range []bool{true, false} {
				l, r := []byte(kernelLinksFixture), []byte(kernelRoutesFixture)
				if links {
					l = []byte(v)
				} else {
					r = []byte(v)
				}
				got, err := ParseKernelInventory("net:[1]", l, r)
				if !errors.Is(err, ErrKernelInventoryInvalid) || len(got.Links) != 0 || len(got.Routes) != 0 {
					t.Fatal("invalid JSON did not refuse atomically")
				}
				if err.Error() != ErrKernelInventoryInvalid.Error() {
					t.Fatal("non-static error")
				}
			}
		})
	}
}
func TestKernelInventoryLinkRefusals(t *testing.T) {
	cases := map[string]string{"id overflow": strings.Replace(kernelLinksFixture, "0x14", "0x100000000", 1), "nonhex id": strings.Replace(kernelLinksFixture, "0x14", "20", 1), "null id": strings.Replace(kernelLinksFixture, `"0x14"`, `null`, 1), "missing id": strings.Replace(kernelLinksFixture, `"if_id":"0x14"`, `"unused":1`, 1), "index zero": strings.Replace(kernelLinksFixture, `"ifindex":10`, `"ifindex":0`, 1), "index overflow": strings.Replace(kernelLinksFixture, `"ifindex":10`, `"ifindex":2147483648`, 1), "duplicate index": strings.Replace(kernelLinksFixture, `"ifindex":11`, `"ifindex":10`, 1), "duplicate name": strings.Replace(kernelLinksFixture, `"ifname":"ipsec-b"`, `"ifname":"ipsec-a"`, 1), "duplicate xfrm": strings.Replace(kernelLinksFixture, "0xffffffff", "0x14", 1), "external": strings.Replace(kernelLinksFixture, `"if_id":"0x14"`, `"if_id":"0x14","external":true`, 1), "null flags": strings.Replace(kernelLinksFixture, `["UP","LOWER_UP"]`, `null`, 1), "dot interface": strings.Replace(kernelLinksFixture, `"ipsec-a"`, `"."`, 1)}
	for name, links := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKernelInventory("net:[1]", []byte(links), []byte(`[]`))
			if !errors.Is(err, ErrKernelInventoryInvalid) {
				t.Fatal("invalid link accepted")
			}
		})
	}
}
func TestKernelInventoryRouteRefusals(t *testing.T) {
	cases := map[string]string{"noncanonical": strings.Replace(kernelRoutesFixture, "10.20.0.0/16", "10.20.1.0/16", 1), "v6": strings.Replace(kernelRoutesFixture, "10.20.0.0/16", "2001:db8::/64", 1), "metric overflow": strings.Replace(kernelRoutesFixture, `"metric":7`, `"metric":4294967296`, 1), "metric negative": strings.Replace(kernelRoutesFixture, `"metric":7`, `"metric":-1`, 1), "protocol overflow": strings.Replace(kernelRoutesFixture, `"protocol":"99"`, `"protocol":"256"`, 1), "scope overflow": strings.Replace(kernelRoutesFixture, `"scope":"0"`, `"scope":"256"`, 1), "missing table": strings.Replace(kernelRoutesFixture, `"table":"200",`, "", 1), "null gateway": strings.Replace(kernelRoutesFixture, `"169.254.10.2"`, `null`, 1), "nonunicast": strings.Replace(kernelRoutesFixture, `"type":"1"`, `"type":"blackhole"`, 1), "unknown device": strings.Replace(kernelRoutesFixture, `"dev":"ipsec-a"`, `"dev":"unseen"`, 1), "forward flags": strings.Replace(kernelRoutesFixture, `"flags":[]`, `"flags":["onlink"]`, 1), "unknown semantic": strings.Replace(kernelRoutesFixture, `"metric":7`, `"metric":7,"ttl-propagate":true`, 1), "nhid": `[{"nhid":12,"dst":"10.0.0.0/8"}]`, "multipath": `[{"dst":"10.0.0.0/8","nexthops":[{"dev":"ipsec-a"}]}]`, "source selector": strings.Replace(kernelRoutesFixture, `"metric":7`, `"metric":7,"from":"10.0.0.0/8"`, 1)}
	for name, routes := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseKernelInventory("net:[1]", []byte(kernelLinksFixture), []byte(routes))
			if !errors.Is(err, ErrKernelInventoryInvalid) {
				t.Fatal("invalid route accepted")
			}
		})
	}
}

func TestKernelInventoryDuplicateRoutes(t *testing.T) {
	route := `{"type":"1","dst":"10.20.0.0/16","dev":"ipsec-a","table":"200","protocol":"99","scope":"0","flags":[]}`
	_, err := ParseKernelInventory("net:[1]", []byte(kernelLinksFixture), []byte("["+route+","+route+"]"))
	if err == nil {
		t.Fatal("duplicate route observation accepted")
	}
}

// These unmodified iproute2-6.9.0 dumps came from an owned disposable Linux
// lab with network=none and synthetic XFRM links/routes. No PSKs, policy or
// CHILD_SA dumps were collected. Parser format proof is not traffic proof.
func TestKernelInventoryCapturedIPRoute269(t *testing.T) {
	links, err := os.ReadFile("testdata/iproute2-6.9.0-links.json")
	if err != nil {
		t.Fatal(err)
	}
	routes, err := os.ReadFile("testdata/iproute2-6.9.0-routes.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKernelInventory("net:[1234]", links, routes)
	if err != nil {
		t.Fatal(err)
	}
	if got.Namespace != "net:[1234]" || len(got.Links) != 2 || len(got.Routes) != 2 {
		t.Fatalf("unexpected captured inventory: %+v", got)
	}
	for i, link := range got.Links {
		if link.XFRMID != uint32(701+i) || link.Index != 2+i || !link.Up || link.Name != []string{"tnx-test-a", "tnx-test-b"}[i] {
			t.Fatalf("unexpected link: %+v", link)
		}
		route := got.Routes[i]
		if route.Table != uint32(220+i) || route.Protocol != 99 || route.Scope != 253 || route.Metric != 10 || route.OutputInterface != link.Index || route.Destination != netip.MustParsePrefix([]string{"198.18.10.0/24", "198.18.11.0/24"}[i]) || route.Gateway.IsValid() || route.PreferredSource.IsValid() {
			t.Fatalf("unexpected route: %+v", route)
		}
	}
}
