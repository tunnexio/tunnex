package policy

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"testing"
	"time"
)

func desktopFQDNFixture() (Snapshot, ipsec.RuntimePolicyInput) {
	s, in := desktopPolicyFixture()
	in.DesktopFQDNVersion = 1
	in.FQDNPolicyVersion = 2
	in.ConfigurationRevision = 1
	s.FQDNResourcesLicensed = true
	s.FQDNResourcesEnabled = true
	s.Rules[0].DstKind = "fqdn_resource"
	r := s.Resources[0]
	s.Resources = nil
	s.FQDNRuleReferences = []FQDNRuleReference{{PolicyRuleID: s.Rules[0].ID, FQDNResourceID: r.ID}}
	s.FQDNResources = []FQDNResource{{ID: r.ID, FQDN: "app.office.test", Protocol: "tcp", PortLow: 443, PortHigh: 443, Active: &FQDNGeneration{ResourceID: r.ID, SelectedSiteID: in.SiteID, SelectedGatewayID: in.NodeID, ResolverConfigID: uuid.New(), ResolverProfileID: uuid.New(), ResolverConfigVersion: 1, ResolverMatchSuffix: "office.test", ResolvedAt: in.CompiledAt, FreshUntil: in.CompiledAt.Add(time.Minute), Answers: []string{"10.180.1.8"}, ResolverAddresses: []string{"10.99.0.1/32"}, StaticCNAME: true, ApplicationIPsecPath: &policyspec.FQDNApplicationIPsecPath{ConnectionID: in.ConnectionID.String(), ConfigurationRevision: 1}}}}
	return s, in
}
func TestDesktopFQDNExactGenerationIdentityAndRevocation(t *testing.T) {
	s, in := desktopFQDNFixture()
	p, e := compileIPsecRuntimePolicy(s, in)
	if e != nil || len(p.FQDNGrants) != 1 || len(p.DesktopGrants) != 0 || len(p.Grants) != 0 {
		t.Fatalf("exact new descriptor missing: %+v %v", p, e)
	}
	g := p.FQDNGrants[0]
	if g.DeviceID != s.Devices[0].ID.String() || g.PublicKey != s.Devices[0].PublicKey || g.ResolverKind != "static_cname" || g.ResolverSourceAddress != "" || g.Source != "10.99.0.7/32" || g.Destination != "10.180.1.8/32" {
		t.Fatal("identity/provenance lost", g)
	}
	for name, mutate := range map[string]func(*Snapshot, *ipsec.RuntimePolicyInput){"old node": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopFQDNVersion = 0 }, "v1": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.FQDNPolicyVersion = 1 }, "missing desktop": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopTransitVersion = 0 }, "static": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.Config.BGP = nil }, "unlicensed": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.FQDNResourcesLicensed = false }, "disabled feature": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.FQDNResourcesEnabled = false }, "mode off": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Mode = ModeOff }, "revoked membership": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Memberships = nil }, "revoked device": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices = nil }, "foreign device gateway": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices[0].NodeID = uuid.New() }, "missing key": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices[0].PublicKey = "" }, "duplicate source": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		d := s.Devices[0]
		d.ID = uuid.New()
		s.Devices = append(s.Devices, d)
	}, "agent": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices[0].Kind = "agent" }, "pool rule": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.Rules[0].SrcKind = "cidr"
		s.Rules[0].SrcCIDR = "10.99.0.0/24"
	}, "expired rule": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { end := i.CompiledAt; s.Rules[0].ExpiresAt = &end }, "expired generation": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active.FreshUntil = i.CompiledAt }, "future generation": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNResources[0].Active.ResolvedAt = i.CompiledAt.Add(time.Second)
	}, "foreign connection": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNResources[0].Active.ApplicationIPsecPath.ConnectionID = uuid.NewString()
	}, "bad revision": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNResources[0].Active.ApplicationIPsecPath.ConfigurationRevision = 2
	}, "foreign site": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active.SelectedSiteID = uuid.New() }, "not CNAME": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.FQDNResources[0].Active.StaticCNAME = false }, "fake DNS path": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNResources[0].Active.IPsecConnectionID = i.ConnectionID
	}, "outside remote": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNResources[0].Active.Answers = []string{"8.8.8.8"}
	}, "zero port": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNResources[0].PortLow = 0
		s.FQDNResources[0].PortHigh = 0
	}, "ambiguous reference": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
		s.FQDNRuleReferences = append(s.FQDNRuleReferences, s.FQDNRuleReferences[0])
	}} {
		t.Run(name, func(t *testing.T) {
			s, i := desktopFQDNFixture()
			mutate(&s, &i)
			if got := compileIPsecDesktopFQDNGrants(s, i); len(got) != 0 {
				t.Fatal("unqualified grant", got)
			}
		})
	}
	s.FQDNResources[0].Active.Answers = []string{"10.180.1.9"}
	next, e := compileIPsecRuntimePolicy(s, in)
	if e != nil || len(next.FQDNGrants) != 1 || next.Hash == p.Hash || next.FQDNGrants[0].Generation == g.Generation || next.FQDNGrants[0].Destination != "10.180.1.9/32" {
		t.Fatal("answer change did not replace identity", e)
	}
}
func TestDesktopFQDNDerivedDNSOnlySelectedProfile(t *testing.T) {
	s, in := desktopFQDNFixture()
	pol := Compile(s)[in.NodeID]
	var tagged int
	for _, a := range pol.Allow {
		if a.PortLow == 53 {
			tagged++
			if a.DNSResolverProfileID != s.FQDNResources[0].Active.ResolverProfileID.String() || a.FQDNDeviceID != s.Devices[0].ID.String() {
				t.Fatal("unscoped DNS grant", a)
			}
		}
	}
	if tagged != 2 {
		t.Fatalf("DNS grants=%d", tagged)
	}
	profile := IPsecDNSProfile{Profile: policyspec.DNSResolverProfile{ProfileID: s.FQDNResources[0].Active.ResolverProfileID.String(), StaticRecords: []policyspec.DNSStaticRecord{{Name: "app.office.test", Type: "CNAME", Value: "outside.example", TTL: 60}}}}
	if got := DNSProfileForAllowedTraffic(profile, pol.Allow, "10.99.0.1"); len(got.AllowedSources) != 1 {
		t.Fatal("selected resolver unavailable", got)
	}
	profile.Profile.ProfileID = uuid.NewString()
	if got := DNSProfileForAllowedTraffic(profile, pol.Allow, "10.99.0.1"); len(got.AllowedSources) != 0 {
		t.Fatal("foreign DNS profile authorized", got)
	}
	f := deviceFQDNForwardsFromSnapshot(s, s.Devices[0].ID, nil)
	if len(f) != 1 || f[0].Domain != "office.test" || f[0].ResolverIP != "10.99.0.1" {
		t.Fatal("scoped forward", f)
	}
	s.Rules[0].Disabled = true
	if len(deviceFQDNForwardsFromSnapshot(s, s.Devices[0].ID, nil)) != 0 || len(Compile(s)[in.NodeID].Allow) != 0 {
		t.Fatal("revocation retained derived DNS")
	}
}
