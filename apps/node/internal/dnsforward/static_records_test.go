package dnsforward

import (
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"testing"
)

func staticProfileFixture() ResolverProfile {
	p := privateProfile()
	p.Config.IPsecPath = nil
	p.Config.Endpoints = nil
	p.ZoneSuffixes = []string{"office.test"}
	p.StaticRecords = []StaticRecord{{Name: "app.office.test", Type: "A", Value: "10.20.0.80", TTL: 300}, {Name: "app.office.test", Type: "AAAA", Value: "fd00::80", TTL: 300}, {Name: "alias.office.test", Type: "CNAME", Value: "app.office.test", TTL: 300}, {Name: "external.office.test", Type: "CNAME", Value: "internal.lb.example", TTL: 300}}
	return p
}
func queryType(name string, kind dnsmessage.Type) []byte {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET}}}
	out, _ := m.Pack()
	return out
}
func decodeDNS(t *testing.T, wire []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return m
}
func TestStaticDNSAuthoritativeTypesAliasesAndNoCloudDependency(t *testing.T) {
	f := New(nil, func(netip.Addr, []byte) ([]byte, error) { t.Fatal("static DNS used upstream"); return nil, nil })
	p := staticProfileFixture()
	f.SetResolverProfiles([]ResolverProfile{p})
	source := netip.MustParseAddr("10.99.0.7")
	for _, tc := range []struct {
		name  string
		kind  dnsmessage.Type
		count int
		rcode dnsmessage.RCode
	}{
		{"app.office.test.", dnsmessage.TypeA, 1, 0}, {"app.office.test.", dnsmessage.TypeAAAA, 1, 0}, {"alias.office.test.", dnsmessage.TypeA, 2, 0}, {"alias.office.test.", dnsmessage.TypeAAAA, 2, 0}, {"alias.office.test.", dnsmessage.TypeCNAME, 1, 0}, {"external.office.test.", dnsmessage.TypeA, 1, 0}, {"app.office.test.", dnsmessage.TypeTXT, 0, 0}, {"missing.office.test.", dnsmessage.TypeA, 0, dnsmessage.RCodeNameError},
	} {
		m := decodeDNS(t, f.handle(queryType(tc.name, tc.kind), source))
		if m.RCode != tc.rcode || len(m.Answers) != tc.count || !m.Authoritative {
			t.Fatalf("%s/%v: %+v", tc.name, tc.kind, m)
		}
		for _, r := range m.Answers {
			if r.Header.TTL != 300 {
				t.Fatal("lost configured TTL")
			}
		}
	}
	if got := packetRCode(t, f.handle(mkQuery("app.office.test."), netip.MustParseAddr("10.99.0.8"))); got != dnsmessage.RCodeRefused {
		t.Fatal("static record bypassed DNS grant")
	}
	p.StaticRecords[0].Value = "10.20.0.90"
	f.SetResolverProfiles([]ResolverProfile{p})
	m := decodeDNS(t, f.handle(mkQuery("app.office.test."), source))
	if m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 20, 0, 90} {
		t.Fatal("static update stayed stale")
	}
	f.SetResolverProfiles(nil)
	if packetRCode(t, f.handle(mkQuery("app.office.test."), source)) != dnsmessage.RCodeRefused {
		t.Fatal("deleted static record still served")
	}
}
func TestInvalidStaticProfilesFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []StaticRecord
	}{
		{"cycle", []StaticRecord{{"a.office.test", "CNAME", "b.office.test", 300}, {"b.office.test", "CNAME", "a.office.test", 300}}},
		{"coexist", []StaticRecord{{"a.office.test", "CNAME", "b.office.test", 300}, {"a.office.test", "A", "10.0.0.1", 300}}},
		{"publicip", []StaticRecord{{"a.office.test", "A", "8.8.8.8", 300}}},
		{"outofzone", []StaticRecord{{"a.foreign.test", "A", "10.0.0.1", 300}}},
		{"badttl", []StaticRecord{{"a.office.test", "A", "10.0.0.1", 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := New(nil, nil)
			p := staticProfileFixture()
			p.StaticRecords = tc.records
			f.SetResolverProfiles([]ResolverProfile{p})
			if packetRCode(t, f.handle(mkQuery("a.office.test."), netip.MustParseAddr("10.99.0.7"))) != dnsmessage.RCodeServerFailure {
				t.Fatal("invalid profile did not fail closed")
			}
		})
	}
}

func TestStaticDNSCNAMEAndRRsetBounds(t *testing.T) {
	for _, hops := range []int{8, 9} {
		records := []StaticRecord{}
		for i := 0; i < hops; i++ {
			records = append(records, StaticRecord{fmt.Sprintf("a%d.office.test", i), "CNAME", fmt.Sprintf("a%d.office.test", i+1), 300})
		}
		records = append(records, StaticRecord{fmt.Sprintf("a%d.office.test", hops), "A", "10.0.0.1", 300})
		if _, ok := compileStaticRecords(records, []string{"office.test."}); ok != (hops == 8) {
			t.Fatal("CNAME bound mismatch", hops)
		}
	}
	for _, records := range [][]StaticRecord{
		{{"app.office.test", "A", "10.0.0.1", 300}, {"app.office.test", "A", "10.0.0.2", 301}},
		{{"alias.office.test", "CNAME", "10.0.0.1", 300}},
		{{"alias.office.test", "CNAME", "_bad.office.test", 300}},
	} {
		if _, ok := compileStaticRecords(records, []string{"office.test."}); ok {
			t.Fatal("malformed RRset accepted")
		}
	}
	records := []StaticRecord{}
	for i := 1; i <= 33; i++ {
		records = append(records, StaticRecord{"app.office.test", "A", fmt.Sprintf("10.0.0.%d", i), 300})
	}
	if _, ok := compileStaticRecords(records, []string{"office.test."}); ok {
		t.Fatal("address RRset exceeded32")
	}
}
