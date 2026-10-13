package policy

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"testing"
)

func dnsProfileFixture() IPsecDNSProfile {
	return IPsecDNSProfile{TransportAvailable: true, LocalPrefixes: []string{"10.10.0.0/24"}, Profile: policyspec.DNSResolverProfile{ContextConfigID: uuid.NewString(), ContextConfigVersion: 2, ProfileID: uuid.NewString(), ZoneSuffixes: []string{"private.test"}, Endpoints: []policyspec.DNSResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}, {Address: "10.20.0.54", Port: 53, Transport: "tcp"}}, IPsecPath: policyspec.DNSResolverIPsecPath{ConnectionID: uuid.NewString(), ConfigurationRevision: 1, SourceAddress: "10.10.0.5"}}}
}
func TestIPsecDNSProxySourcesRequireCompleteOrdinaryPermission(t *testing.T) {
	declared := dnsProfileFixture()
	udp := policyspec.AllowEntry{SrcIP: "10.10.0.7", DstCIDR: "10.20.0.0/24", Protocol: "udp", PortLow: 53, PortHigh: 53}
	tcp := udp
	tcp.Protocol = "tcp"
	for _, input := range [][]policyspec.AllowEntry{nil, {udp}, {tcp}} {
		if got := DNSProfileForAllowedTraffic(declared, input); len(got.AllowedSources) != 0 {
			t.Fatal("partial DNS permission authorized proxy")
		}
	}
	got := DNSProfileForAllowedTraffic(declared, []policyspec.AllowEntry{udp, tcp})
	if len(got.AllowedSources) != 1 || got.AllowedSources[0] != "10.10.0.7/32" {
		t.Fatal("exact DNS sources absent")
	}
	udp.FQDNManaged = true
	if got := DNSProfileForAllowedTraffic(declared, []policyspec.AllowEntry{udp, tcp}); len(got.AllowedSources) != 0 {
		t.Fatal("managed FQDN granted site DNS")
	}
	udp.FQDNManaged = false
	udp.SrcIP = "10.99.0.7"
	tcp.SrcIP = udp.SrcIP
	if got := DNSProfileForAllowedTraffic(declared, []policyspec.AllowEntry{udp, tcp}); len(got.AllowedSources) != 1 || got.AllowedSources[0] != "10.99.0.7/32" {
		t.Fatal("explicitly authorized WG source outside cloud-advertised ranges was refused")
	}
	// That proxy scope does not add a forwarded IPsec data-plane permit.
	base := ipsec.RuntimePolicy{}
	in := ipsec.RuntimePolicyInput{ConnectionID: uuid.MustParse(declared.Profile.IPsecPath.ConnectionID)}
	if err := attachRuntimeDNSProfiles(&base, []IPsecDNSProfile{declared}, in, []policyspec.AllowEntry{udp, tcp}); err != nil || len(base.Grants) != 0 || len(base.DNSResolverGrants) != 2 || base.DNSResolverGrants[0].SourceAddress != "10.10.0.5" || len(base.DNSResolverProfiles[0].AllowedSources) != 1 || base.DNSResolverProfiles[0].AllowedSources[0] != "10.99.0.7/32" {
		t.Fatal("proxy scope widened forwarded grants or upstream source", err)
	}
}
func TestIPsecDNSHostAuthorityScopedBoundedAndHashSignificant(t *testing.T) {
	declared := dnsProfileFixture()
	in := ipsec.RuntimePolicyInput{OrgID: uuid.New(), NodeID: uuid.New(), SiteID: uuid.New(), ConnectionID: uuid.MustParse(declared.Profile.IPsecPath.ConnectionID)}
	base := ipsec.RuntimePolicy{Grants: []ipsec.RuntimeGrant{}}
	before, err := hashRuntimePolicy(base, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachRuntimeDNSProfiles(&base, []IPsecDNSProfile{declared}, in, nil); err != nil || len(base.DNSResolverGrants) != 2 {
		t.Fatal("DNS host authority", err)
	}
	after, _ := hashRuntimePolicy(base, in)
	if before.Hash == after.Hash {
		t.Fatal("DNS authority omitted from hash")
	}
	if len(base.DNSResolverProfiles[0].AllowedSources) != 0 {
		t.Fatal("host DNS authorized arbitrary client")
	}
	declared.TransportAvailable = false
	none := ipsec.RuntimePolicy{}
	if err := attachRuntimeDNSProfiles(&none, []IPsecDNSProfile{declared}, in, nil); err != nil || len(none.DNSResolverGrants) != 0 {
		t.Fatal("inactive transport authorized")
	}
	declared.TransportAvailable = true
	full := ipsec.RuntimePolicy{Grants: make([]ipsec.RuntimeGrant, 125)}
	if err := attachRuntimeDNSProfiles(&full, []IPsecDNSProfile{declared}, in, nil); err == nil {
		t.Fatal("DNS bypassed original 128 grant bound")
	}
}
