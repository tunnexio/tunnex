package ipsec

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestDockerDNSIndependentNATProof(t *testing.T) {
	nft, err := os.ReadFile("testdata/runtime-docker-dns-nft.json")
	if err != nil {
		t.Fatal(err)
	}
	listing, err := os.ReadFile("testdata/runtime-docker-dns-save.txt")
	if err != nil {
		t.Fatal(err)
	}
	protected := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	if runtimeHookCensus(nft, protected) || !runtimeDockerDNSCensus(nft, listing, protected) {
		t.Fatal("opaque NAT targets must require independent exact semantics")
	}
	for _, change := range []struct{ name, old, next string }{
		{"remote DNAT", "--to-destination 127.0.0.11:40101", "--to-destination 10.20.0.2:40101"},
		{"remote SNAT", "--to-source :53", "--to-source 10.20.0.2:53"},
		{"extra rule", "COMMIT", "-A OUTPUT -j ACCEPT\nCOMMIT"},
		{"extra hook", ":INPUT ACCEPT [0:0]", ":INPUT ACCEPT [0:0]\n:FOREIGN ACCEPT [0:0]"},
		{"broader DNS", "127.0.0.11/32", "127.0.0.0/8"},
		{"wrong return port", "--sport 40101", "--sport 40102"},
		{"duplicate target", "COMMIT", "-A DOCKER_OUTPUT -d 127.0.0.11/32 -p tcp -m tcp --dport 53 -j DNAT --to-destination 127.0.0.11:40101\nCOMMIT"},
		{"second table", "COMMIT", "COMMIT\n*filter\nCOMMIT"},
	} {
		t.Run(change.name, func(t *testing.T) {
			altered := strings.Replace(string(listing), change.old, change.next, 1)
			if altered == string(listing) || runtimeDockerDNSCensus(nft, []byte(altered), protected) {
				t.Fatal("unsafe compat semantics admitted")
			}
		})
	}
	for _, change := range []struct{ name, old, next string }{
		{"forward hook", `"hook": "output"`, `"hook": "forward"`},
		{"late priority", `"prio": 100`, `"prio": 400`},
		{"foreign address", `"right": "127.0.0.11"`, `"right": "10.20.0.2"`},
		{"wrong compat target", `"name": "DNAT"`, `"name": "REDIRECT"`},
		{"wrong port", `"right": 40101`, `"right": 40102`},
		{"wrong protocol", `"protocol": "udp"`, `"protocol": "icmp"`},
		{"foreign chain", `"name": "DOCKER_OUTPUT"`, `"name": "FOREIGN"`},
	} {
		t.Run(change.name, func(t *testing.T) {
			altered := strings.Replace(string(nft), change.old, change.next, 1)
			if altered == string(nft) || runtimeDockerDNSCensus([]byte(altered), listing, protected) {
				t.Fatal("unsafe NFT topology admitted")
			}
		})
	}
	if runtimeDockerDNSCensus(nft, listing, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}) || runtimeDockerDNSCensus(nft, nil, protected) {
		t.Fatal("protected overlap or missing independent semantics admitted")
	}
	otherNFT := strings.ReplaceAll(strings.ReplaceAll(string(nft), "40101", "44157"), "43032", "35322")
	otherSave := strings.ReplaceAll(strings.ReplaceAll(string(listing), "40101", "44157"), "43032", "35322")
	if !runtimeDockerDNSCensus([]byte(otherNFT), []byte(otherSave), protected) {
		t.Fatal("valid namespace-specific DNS ports rejected")
	}
	var doc map[string][]map[string]any
	if json.Unmarshal(nft, &doc) != nil {
		t.Fatal("fixture JSON")
	}
	doc["nftables"] = append(doc["nftables"], map[string]any{"chain": map[string]any{"family": "ip", "table": "foreign", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}})
	extra, _ := json.Marshal(doc)
	if runtimeDockerDNSCensus(extra, listing, protected) {
		t.Fatal("foreign forwarding bypass admitted")
	}
}
