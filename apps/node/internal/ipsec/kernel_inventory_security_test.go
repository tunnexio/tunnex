package ipsec

import (
	"strings"
	"testing"
)

const securityKernelLinks = `[{"ifindex":12,"ifname":"ipsec-a","flags":["UP"],"linkinfo":{"info_kind":"xfrm","info_data":{"if_id":"0x14"}}}]`
const securityKernelRoutes = `[{"type":"1","dst":"10.20.0.0/16","dev":"ipsec-a","table":"220","protocol":"4","scope":"253","flags":[]}]`

func TestKernelInventorySecurityBaseline(t *testing.T) {
	if _, err := ParseKernelInventory("net:[4026531992]", []byte(securityKernelLinks), []byte(securityKernelRoutes)); err != nil {
		t.Fatalf("valid baseline: %v", err)
	}
}

func TestKernelInventorySecurityMalformedLinks(t *testing.T) {
	cases := map[string]string{
		"escaped index duplicate":       strings.Replace(securityKernelLinks, `"ifindex":12`, `"ifindex":12,"if\u0069ndex":12`, 1),
		"nested escaped kind duplicate": strings.Replace(securityKernelLinks, `"info_kind":"xfrm"`, `"info_kind":"wireguard","info_\u006bind":"xfrm"`, 1),
		"nested id duplicate":           strings.Replace(securityKernelLinks, `"if_id":"0x14"`, `"if_id":"0x15","if_id":"0x14"`, 1),
		"null index":                    strings.Replace(securityKernelLinks, `"ifindex":12`, `"ifindex":null`, 1),
		"index overflow":                strings.Replace(securityKernelLinks, `"ifindex":12`, `"ifindex":4294967296`, 1),
		"fraction index":                strings.Replace(securityKernelLinks, `"ifindex":12`, `"ifindex":12.5`, 1),
		"missing flags":                 strings.Replace(securityKernelLinks, `"flags":["UP"],`, ``, 1),
		"null flags":                    strings.Replace(securityKernelLinks, `"flags":["UP"]`, `"flags":null`, 1),
		"null info":                     strings.Replace(securityKernelLinks, `{"if_id":"0x14"}`, `null`, 1),
		"missing id":                    strings.Replace(securityKernelLinks, `"if_id":"0x14"`, ``, 1),
		"id overflow":                   strings.Replace(securityKernelLinks, `"0x14"`, `"0x100000000"`, 1),
		"external with id":              strings.Replace(securityKernelLinks, `"if_id":"0x14"`, `"if_id":"0x14","external":true`, 1),
		"null document":                 `null`,
		"trailing document":             securityKernelLinks + `[]`,
	}
	for name, links := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKernelInventory("net:[4026531992]", []byte(links), []byte(securityKernelRoutes)); err == nil {
				t.Fatal("accepted ambiguous link inventory")
			}
		})
	}
}

func TestKernelInventorySecurityMalformedRoutes(t *testing.T) {
	cases := map[string]string{
		"escaped dev duplicate":     strings.Replace(securityKernelRoutes, `"dev":"ipsec-a"`, `"dev":"eth0","d\u0065v":"ipsec-a"`, 1),
		"null table":                strings.Replace(securityKernelRoutes, `"table":"220"`, `"table":null`, 1),
		"missing table":             strings.Replace(securityKernelRoutes, `"table":"220",`, ``, 1),
		"table overflow":            strings.Replace(securityKernelRoutes, `"table":"220"`, `"table":"4294967296"`, 1),
		"protocol overflow":         strings.Replace(securityKernelRoutes, `"protocol":"4"`, `"protocol":"256"`, 1),
		"scope overflow":            strings.Replace(securityKernelRoutes, `"scope":"253"`, `"scope":"256"`, 1),
		"metric overflow":           strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"metric":4294967296`, 1),
		"metric null":               strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"metric":null`, 1),
		"gateway null":              strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"gateway":null`, 1),
		"unknown semantics":         strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"future_forwarding_mode":1`, 1),
		"nexthop":                   strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"nhid":12`, 1),
		"multipath":                 strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"multipath":[]`, 1),
		"encap":                     strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"encap":{}`, 1),
		"source selector":           strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":[],"from":"10.10.0.0/16"`, 1),
		"onlink":                    strings.Replace(securityKernelRoutes, `"flags":[]`, `"flags":["onlink"]`, 1),
		"indirect nexthop no dev":   `[{"dst":"10.20.0.0/16","nhid":12}]`,
		"indirect multipath no dev": `[{"dst":"10.20.0.0/16","multipath":[{"dev":"ipsec-a"}]}]`,
	}
	for name, routes := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseKernelInventory("net:[4026531992]", []byte(securityKernelLinks), []byte(routes)); err == nil {
				t.Fatal("accepted ambiguous route inventory")
			}
		})
	}
}

func TestKernelInventorySecurityDuplicateOwnership(t *testing.T) {
	for _, dimension := range []string{"index", "name", "xfrm"} {
		t.Run(dimension, func(t *testing.T) {
			second := strings.TrimSuffix(strings.TrimPrefix(securityKernelLinks, "["), "]")
			if dimension != "index" {
				second = strings.Replace(second, `"ifindex":12`, `"ifindex":13`, 1)
			}
			if dimension != "name" {
				second = strings.Replace(second, `"ipsec-a"`, `"ipsec-b"`, 1)
			}
			if dimension != "xfrm" {
				second = strings.Replace(second, `"0x14"`, `"0x15"`, 1)
			}
			links := strings.TrimSuffix(securityKernelLinks, "]") + "," + second + "]"
			if _, err := ParseKernelInventory("net:[4026531992]", []byte(links), []byte(securityKernelRoutes)); err == nil {
				t.Fatal("accepted duplicated ownership dimension")
			}
		})
	}
}

func TestKernelInventorySecurityIndirectXFRMOnOrdinaryDevice(t *testing.T) {
	links := strings.TrimSuffix(securityKernelLinks, "]") + `,{"ifindex":2,"ifname":"eth0","flags":["UP"]}]`
	routes := `[{"type":"1","dst":"10.20.0.0/16","dev":"eth0","table":"220","protocol":"4","scope":"0","encap":{"type":"xfrm","if_id":20}}]`
	if _, err := ParseKernelInventory("net:[4026531992]", []byte(links), []byte(routes)); err == nil {
		t.Fatal("encapsulated XFRM traffic classified as unrelated ordinary route")
	}
}
