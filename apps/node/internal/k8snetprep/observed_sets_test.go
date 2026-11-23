package k8snetprep

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// The rule Calico installs for outgoing pod traffic, as iptables-nft-save prints it.
const calicoSaved = `*nat
:POSTROUTING ACCEPT [0:0]
:cali-POSTROUTING - [0:0]
:cali-nat-outgoing - [0:0]
-A POSTROUTING -m comment --comment "cali:O3lYWMrLQYEMJtB5" -j cali-POSTROUTING
-A cali-POSTROUTING -m comment --comment "cali:Z-c7XtVd2Bq7s_hA" -j cali-nat-outgoing
-A cali-nat-outgoing -m comment --comment "cali:flqWnvo8yq4ULQLa" -m set --match-set cali40masq-ipam-pools src -m set ! --match-set cali40all-ipam-pools dst -j MASQUERADE --random-fully
COMMIT
`

func TestParseSavedSetMatchesKeepsRuleOrderAndNegation(t *testing.T) {
	got, err := parseSavedSetMatches(calicoSaved)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]setMatch{{
		{Name: "cali40masq-ipam-pools", Dirs: []string{"src"}},
		{Name: "cali40all-ipam-pools", Dirs: []string{"dst"}, Negated: true},
	}}
	if !reflect.DeepEqual(got["cali-nat-outgoing"], want) {
		t.Fatalf("set matches = %+v", got["cali-nat-outgoing"])
	}
	// A rule without a set match still holds its position, so rule N pairs with rule N.
	if len(got["POSTROUTING"]) != 1 || len(got["POSTROUTING"][0]) != 0 {
		t.Fatalf("POSTROUTING = %+v", got["POSTROUTING"])
	}
}

func TestParseSavedSetMatchesRefusesWhatItCannotRead(t *testing.T) {
	for name, saved := range map[string]string{
		"unknown direction": "-A c -m set --match-set s foo -j MASQUERADE",
		"cut short":         "-A c -m set --match-set s",
		"other option":      "-A c -m set --return-nomatch --match-set s src -j MASQUERADE",
		"name too long":     "-A c -m set --match-set " + strings.Repeat("x", 40) + " src -j MASQUERADE",
	} {
		if _, err := parseSavedSetMatches(saved); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseIPSetSave(t *testing.T) {
	members, err := parseIPSetSave("cali40masq-ipam-pools", "create cali40masq-ipam-pools hash:net family inet hashsize 1024 maxelem 1048576\nadd cali40masq-ipam-pools 10.42.0.0/16\nadd cali40masq-ipam-pools 192.168.7.9\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16"), netip.MustParsePrefix("192.168.7.9/32")}
	if !reflect.DeepEqual(members, want) {
		t.Fatalf("members = %v", members)
	}
	for name, saved := range map[string]string{
		"not listed":   "",
		"other set":    "create other hash:net family inet\n",
		"ipv6":         "create s hash:net family inet6\n",
		"port set":     "create s hash:ip,port family inet\n",
		"bad member":   "create s hash:net family inet\nadd s not-an-address\n",
		"foreign line": "create s hash:net family inet\nflush s\n",
	} {
		if _, err := parseIPSetSave("s", saved); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSetsLimitSourceOutside(t *testing.T) {
	tunnel := netip.MustParsePrefix("10.99.0.0/16")
	pods := map[string][]netip.Prefix{"pools": {netip.MustParsePrefix("10.42.0.0/16")}}
	src := func(name string, negated bool) setMatch {
		return setMatch{Name: name, Dirs: []string{"src"}, Negated: negated}
	}

	if ok, proof := setsLimitSourceOutside([]setMatch{src("pools", false), {Name: "all", Dirs: []string{"dst"}, Negated: true}}, pods, tunnel); !ok || !reflect.DeepEqual(proof, []string{"pools"}) {
		t.Fatalf("Calico's rule was not accepted: %v %v", ok, proof)
	}
	for name, tc := range map[string]struct {
		matches []setMatch
		sets    map[string][]netip.Prefix
	}{
		"pool overlaps the tunnel range": {[]setMatch{src("pools", false)}, map[string][]netip.Prefix{"pools": {netip.MustParsePrefix("10.0.0.0/8")}}},
		"negated source match":           {[]setMatch{src("pools", true)}, pods},
		"destination match only":         {[]setMatch{{Name: "pools", Dirs: []string{"dst"}}}, pods},
		"source and destination pair":    {[]setMatch{{Name: "pools", Dirs: []string{"src", "dst"}}}, pods},
		"set was not read":               {[]setMatch{src("missing", false)}, pods},
		"no set match at all":            {nil, pods},
	} {
		if ok, _ := setsLimitSourceOutside(tc.matches, tc.sets, tunnel); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	// A set with no members can match nothing, so the masquerade behind it cannot fire.
	if ok, _ := setsLimitSourceOutside([]setMatch{src("empty", false)}, map[string][]netip.Prefix{"empty": {}}, tunnel); !ok {
		t.Error("an empty source set was refused")
	}
}
