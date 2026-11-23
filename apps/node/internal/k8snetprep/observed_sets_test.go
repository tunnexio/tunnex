package k8snetprep

import (
	"net/netip"
	"os"
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

// Review finding 2. A hash:ip set created with `netmask 24` stores and prints
// the masked address: ipset 7.24 saved the member 10.5.6.7 of such a set as
// `add t 10.5.6.0`, and the set matches every address of 10.5.6.0/24. Read as
// the one address it prints, it would look disjoint from a tunnel range that
// it covers. The create lines below are what ipset 7.24 printed on kernel 6.8.
func TestParseIPSetSaveRefusesASetThatMatchesMoreThanItLists(t *testing.T) {
	for name, tc := range map[string]struct{ saved, want string }{
		"hash:ip with a netmask": {
			"create s hash:ip family inet hashsize 1024 maxelem 65536 netmask 24 bucketsize 12 initval 0x43ae691d\nadd s 10.5.6.0\n",
			"set s has netmask 24: its members match whole networks",
		},
		"netmask 31":           {"create s hash:ip family inet netmask 31\nadd s 10.5.6.0\n", "set s has netmask 31"},
		"netmask 0":            {"create s hash:ip family inet netmask 0\n", "set s has netmask 0"},
		"netmask on a net set": {"create s hash:net family inet netmask 16\nadd s 10.5.0.0/16\n", "set s has netmask 16"},
		"hash:ip with a bitmask": {
			"create s hash:ip family inet hashsize 1024 maxelem 65536 bitmask 255.255.0.255 bucketsize 12 initval 0x312d219d\nadd s 10.6.0.8\n",
			"set s has a bitmask",
		},
		"a bitmask of all ones":        {"create s hash:ip family inet bitmask 255.255.255.255\nadd s 10.6.7.8\n", "set s has a bitmask"},
		"a bitmask before the family":  {"create s hash:ip bitmask 255.0.0.0 family inet\n", "set s has a bitmask"},
		"netmask given twice":          {"create s hash:ip family inet netmask 32 netmask 24\n", "header option that is not understood"},
		"netmask without a value":      {"create s hash:ip family inet netmask\n", "header option that is not understood"},
		"netmask that is not a number": {"create s hash:ip family inet netmask 255.255.255.0\n", "header option that is not understood"},
	} {
		members, err := parseIPSetSave("s", tc.saved)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: members = %v, err = %v", name, members, err)
		}
	}
	// The false proof itself: before the fix the member read as 10.5.6.0/32,
	// which does not overlap 10.5.6.128/25, a range the set matches entirely.
	saved := "create s hash:ip family inet hashsize 1024 maxelem 65536 netmask 24 bucketsize 12 initval 0x43ae691d\nadd s 10.5.6.0\n"
	if members, err := parseIPSetSave("s", saved); err == nil {
		if ok, _ := setsLimitSourceOutside([]setMatch{{Name: "s", Dirs: []string{"src"}}}, map[string][]netip.Prefix{"s": members}, netip.MustParsePrefix("10.5.6.128/25")); ok {
			t.Fatal("a set that matches the tunnel range was read as lying outside it")
		}
		t.Fatal("a netmask set was read")
	}
}

// Every option on a create line is one this package has decided on. What
// ipset prints for a hash:net or hash:ip set and cannot widen a member is
// accepted and otherwise ignored; anything else refuses the set.
func TestParseIPSetSaveHeaderIsAnAllowList(t *testing.T) {
	for name, header := range map[string]string{
		"family only":                 "hash:net family inet",
		"as ipset 7.24 prints":        "hash:net family inet hashsize 1024 maxelem 65536 bucketsize 12 initval 0x843a21cc",
		"as an older ipset prints":    "hash:ip family inet hashsize 1024 maxelem 65536",
		"every accepted option":       "hash:net family inet hashsize 64 maxelem 100 timeout 300 counters comment skbinfo forceadd bucketsize 12 initval 0x87053f72",
		"netmask 32 is an address":    "hash:ip family inet hashsize 1024 maxelem 65536 netmask 32",
		"options in another order":    "hash:ip maxelem 65536 comment family inet timeout 0",
		"largest values ipset prints": "hash:net family inet hashsize 4294967295 maxelem 4294967295 bucketsize 255 initval 0xffffffff timeout 2147483",
	} {
		if _, err := parseIPSetSave("s", "create s "+header+"\nadd s 10.42.0.0/16\n"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct{ header, want string }{
		"no family":                  {"hash:net hashsize 1024 maxelem 65536", "does not state its family"},
		"no option at all":           {"hash:net", "does not state its family"},
		"IPv6":                       {"hash:net family inet6 hashsize 1024", "is not IPv4"},
		"unknown family":             {"hash:net family bridge", "header option that is not understood"},
		"family given twice":         {"hash:net family inet family inet", "header option that is not understood"},
		"family overridden later":    {"hash:net family inet hashsize 1024 family inet6", "header option that is not understood"},
		"family without a value":     {"hash:net family", "header option that is not understood"},
		"markmask of another type":   {"hash:ip family inet markmask 0x000000ff hashsize 1024", "header option that is not understood"},
		"range of another type":      {"hash:ip family inet range 10.8.0.0-10.8.0.255", "header option that is not understood"},
		"an option ipset may add":    {"hash:net family inet hashsize 1024 wildcard", "header option that is not understood"},
		"hashsize without a number":  {"hash:net family inet hashsize maxelem 65536", "header option that is not understood"},
		"hashsize that is not one":   {"hash:net family inet hashsize 0x400", "header option that is not understood"},
		"initval that is not hex":    {"hash:net family inet initval 12345", "header option that is not understood"},
		"timeout with a negative":    {"hash:net family inet timeout -1", "header option that is not understood"},
		"flag given twice":           {"hash:net family inet counters counters", "header option that is not understood"},
		"flag with a value":          {"hash:net family inet comment yes", "header option that is not understood"},
		"option cut off at the end":  {"hash:net family inet maxelem", "header option that is not understood"},
		"type that takes two fields": {"hash:net,net family inet", "type hash:net,net, which is not understood"},
		"bitmap with netmask":        {"bitmap:ip range 10.8.0.0-10.8.0.255 netmask 28", "type bitmap:ip, which is not understood"},
		"hash:ip,mark":               {"hash:ip,mark family inet markmask 0x000000ff", "type hash:ip,mark, which is not understood"},
	} {
		members, err := parseIPSetSave("s", "create s "+tc.header+"\nadd s 10.42.0.0/16\n")
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: members = %v, err = %v", name, members, err)
		}
	}
	// `ipset save NAME` prints one set. A second create line is not that.
	if _, err := parseIPSetSave("s", "create s hash:ip family inet netmask 24\ncreate s hash:ip family inet\nadd s 10.5.6.0\n"); err == nil {
		t.Error("a listing with two create lines was read")
	}
	if _, err := parseIPSetSave("s", "create s hash:ip family inet\ncreate s hash:ip family inet\n"); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Errorf("two create lines: %v", err)
	}
}

// The sets captured on real nodes are read as before.
func TestParseIPSetSaveReadsTheCapturedSets(t *testing.T) {
	for file, tc := range map[string]struct{ name, member string }{
		"testdata/calico-v3.31.2-kind.ipset-cali40masq-ipam-pools.txt":        {"cali40masq-ipam-pools", "192.168.0.0/16"},
		"testdata/calico-v3.31.2-kind.ipset-cali40all-ipam-pools.txt":         {"cali40all-ipam-pools", "192.168.0.0/16"},
		"testdata/cilium-1.20.5-kind-C-iptables.ipset-cilium_node_set_v4.txt": {"cilium_node_set_v4", "172.21.0.2/32"},
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		members, err := parseIPSetSave(tc.name, string(raw))
		if err != nil || !reflect.DeepEqual(members, []netip.Prefix{netip.MustParsePrefix(tc.member)}) {
			t.Errorf("%s: members = %v, err = %v", file, members, err)
		}
	}
}

// What follows a member on its line can only make the set match less, so a
// member is read by its address alone. A `nomatch` network is an exception
// inside a wider member; counting it as a member refuses more, never less.
func TestParseIPSetSaveReadsMembersByAddressAlone(t *testing.T) {
	saved := "create s hash:net family inet hashsize 64 maxelem 100 timeout 300 counters comment skbinfo bucketsize 12 initval 0x87053f72\n" +
		"add s 10.2.0.0/16 timeout 99 packets 0 bytes 0 comment \"hello world\"\n" +
		"add s 10.3.0.0/16 timeout 299 packets 0 bytes 0 skbmark 0x1/0x2 skbprio 1:10 skbqueue 3\n" +
		"add s 10.1.2.0/24 nomatch\n"
	members, err := parseIPSetSave("s", saved)
	want := []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16"), netip.MustParsePrefix("10.3.0.0/16"), netip.MustParsePrefix("10.1.2.0/24")}
	if err != nil || !reflect.DeepEqual(members, want) {
		t.Fatalf("members = %v, err = %v", members, err)
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
