package ipsec

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

func desktopStaticFQDNFixture(t *testing.T) (RuntimeMaterial, GuardGrant, *nodepolicy.Compiled) {
	t.Helper()
	m, _, p := v2FQDNFixture(t)
	m.Manifest.ProfileID = "aws-bgp-ipv4-v1"
	v := 1
	m.Manifest.BGPVersion = &v
	m.Manifest.BGP = &BGPConfig{LocalASN: 65000, RemoteASN: 7224, RouterID: "10.10.0.1", MaximumPrefixes: 64}
	m.Manifest.Tunnels[0].Selected = false
	runtimeReseal(&m)
	d := desktopGrantFixture()
	f := &m.Policy.FQDNGrants[0]
	f.Source, f.DeviceID, f.PublicKey = d.Source, d.DeviceID, d.PublicKey
	f.ResolverKind, f.ResolverSourceAddress = "static_cname", ""
	p.Allow[0].SrcIP, p.Allow[0].SrcDeviceID = strings.TrimSuffix(d.Source, "/32"), d.DeviceID
	p.Allow[0].FQDNDeviceID = d.DeviceID
	p.FQDNGenerations[0].ApplicationIPsecPath = &nodepolicy.FQDNApplicationIPsecPath{ConnectionID: f.ConnectionID, ConfigurationRevision: f.ConfigurationRevision}
	p.DNSResolverProfiles[0].IPsecPath = nodepolicy.DNSResolverIPsecPath{}
	p.DNSResolverProfiles[0].StaticRecords = []nodepolicy.DNSStaticRecord{{Name: f.Name, Type: "CNAME", Value: "backend.example.net", TTL: 30}}
	_, grants, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil || len(grants) != 1 {
		t.Fatal("exact desktop/static application refused", err)
	}
	return m, grants[0], p
}

func TestDesktopStaticFQDNExactAuthorityAndGenerationWithdrawal(t *testing.T) {
	_, g, p := desktopStaticFQDNFixture(t)
	s := &RuntimeFQDNPolicySource{}
	if s.view.Load().matches(g) {
		t.Fatal("restart adopted authority")
	}
	s.CommittedPolicy(p)
	if !s.view.Load().matches(g) {
		t.Fatal("committed exact identity/path/profile refused")
	}
	for name, mutate := range map[string]func(*nodepolicy.Compiled){
		"broad-source":               func(p *nodepolicy.Compiled) { p.Allow[0].SrcIP = "10.99.0.0/24" },
		"foreign-enforcement-device": func(p *nodepolicy.Compiled) { p.Allow[0].FQDNDeviceID = "foreign" },
		"foreign-device":             func(p *nodepolicy.Compiled) { p.Allow[0].SrcDeviceID = "foreign" },
		"missing-application":        func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].ApplicationIPsecPath = nil },
		"wrong-revision":             func(p *nodepolicy.Compiled) { p.FQDNGenerations[0].ApplicationIPsecPath.ConfigurationRevision++ },
		"fabricated-dns-path": func(p *nodepolicy.Compiled) {
			p.DNSResolverProfiles[0].IPsecPath.ConnectionID = g.FQDN.ConnectionID.String()
		},
		"ambiguous-static": func(p *nodepolicy.Compiled) {
			p.DNSResolverProfiles[0].StaticRecords = append(p.DNSResolverProfiles[0].StaticRecords, p.DNSResolverProfiles[0].StaticRecords[0])
		},
		"missing-static": func(p *nodepolicy.Compiled) { p.DNSResolverProfiles[0].StaticRecords = nil },
		"wrong-record":   func(p *nodepolicy.Compiled) { p.DNSResolverProfiles[0].StaticRecords[0].Name = "other.example.test" },
	} {
		t.Run(name, func(t *testing.T) {
			b := copyFQDNPolicy(p)
			mutate(&b.policy)
			if b.matches(g) {
				t.Fatal("foreign/missing authority accepted")
			}
		})
	}
	// Mutating caller-owned path/record storage cannot change committed authority.
	p.FQDNGenerations[0].ApplicationIPsecPath.ConfigurationRevision++
	p.DNSResolverProfiles[0].StaticRecords[0].Name = "foreign.test"
	if !s.view.Load().matches(g) {
		t.Fatal("desired mutation changed committed authority")
	}
	// Reuse exact identity but revoke old answer before accepting a replacement.
	var next nodepolicy.Compiled
	raw, _ := json.Marshal(s.view.Load().policy)
	json.Unmarshal(raw, &next)
	next.Mode = nodepolicy.ModeEnforcing
	next.FQDNGenerations[0].Generation = strings.Repeat("b", 64)
	next.FQDNGenerations[0].Answers = []string{"10.20.0.10/32"}
	if err := s.BeforePolicy(context.Background(), &next); err != nil {
		t.Fatal(err)
	}
	replacement := g
	replacement.FQDN.Generation = next.FQDNGenerations[0].Generation
	replacement.Destination = netip.MustParsePrefix("10.20.0.10/32")
	next.Allow[0].DstCIDR = replacement.Destination.String()
	if s.view.Load().matches(g) || s.view.Load().matches(replacement) {
		t.Fatal("pending generation granted")
	}
	s.CommittedPolicy(&next)
	if s.view.Load().matches(g) || !s.view.Load().matches(replacement) {
		t.Fatal("generation switch incorrect")
	}
	expired := replacement
	expired.FQDN.ExpiresAt = time.Now().Add(-time.Second)
	if s.view.Load().matches(expired) {
		t.Fatal("expired authority accepted")
	}
	s.CommittedPolicy(nil)
	if s.view.Load().matches(replacement) {
		t.Fatal("revoked policy retained authority")
	}
}

func TestDesktopStaticFQDNLegacyDecodeRefusesAndDigestBindsIdentity(t *testing.T) {
	m, _, _ := desktopStaticFQDNFixture(t)
	f := m.Policy.FQDNGrants[0]
	original := runtimeFQDNGrantDigest(f)
	for _, change := range []func(*RuntimeFQDNGrant){func(f *RuntimeFQDNGrant) { f.DeviceID = "foreign" }, func(f *RuntimeFQDNGrant) { f.PublicKey = "foreign" }, func(f *RuntimeFQDNGrant) { f.ResolverKind = "" }} {
		b := f
		change(&b)
		if runtimeFQDNGrantDigest(b) == original {
			t.Fatal("descriptor digest omitted identity")
		}
	}
	// Old decoders discard additive fields; its existing empty DNS-source/source
	// outside local guards must still fail, never flatten this into an IP grant.
	raw, _ := json.Marshal(f)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	delete(fields, "device_id")
	delete(fields, "public_key")
	delete(fields, "resolver_kind")
	raw, _ = json.Marshal(fields)
	var old RuntimeFQDNGrant
	json.Unmarshal(raw, &old)
	m.Policy.FQDNGrants = []RuntimeFQDNGrant{old}
	if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
		t.Fatal("old consumer accepted new grant")
	}
}

func TestDesktopStaticFQDNGuardRetainsMarksExpiryAndExactWGIngress(t *testing.T) {
	_, g, _ := desktopStaticFQDNFixture(t)
	in := guardFixture()
	c := &in.Connections[0]
	g.FQDN.SelectedGatewayID = in.OwnerID
	g.FQDN.ConnectionID = c.ID
	g.DesktopIngressIndex = 7
	g.FQDNPermitFor = 20 * time.Second
	c.Grants = []GuardGrant{g}
	rendered, err := RenderGuard(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"meta iif 7 meta oif 10", "meta iif 10 meta oif 7", "ct mark", "@" + guardFQDNSetName(g), "ct status snat counter drop"} {
		if !strings.Contains(rendered.NFT, needle) {
			t.Fatal("lost guard invariant", needle)
		}
	}
	c.Grants[0].DesktopIngressIndex = 10
	if _, err := RenderGuard(in); err == nil {
		t.Fatal("tunnel adopted as desktop ingress")
	}
}

func TestDesktopStaticFQDNMaterialRejectsIdentityAndTransportBypass(t *testing.T) {
	for name, mutate := range map[string]func(*RuntimeMaterial){
		"unqualified-ipsec-resolver-desktop": func(m *RuntimeMaterial) {
			m.Policy.FQDNGrants[0].ResolverKind = ""
			m.Policy.FQDNGrants[0].ResolverSourceAddress = "10.10.0.1"
		},
		"unqualified-static-LAN": func(m *RuntimeMaterial) {
			f := &m.Policy.FQDNGrants[0]
			f.DeviceID = ""
			f.PublicKey = ""
			f.Source = "10.10.0.8/32"
		},
		"unqualified-any": func(m *RuntimeMaterial) {
			f := &m.Policy.FQDNGrants[0]
			f.Protocol = "any"
			f.PortLow = 0
			f.PortHigh = 0
		},
		"missing-key":           func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].PublicKey = "" },
		"missing-device":        func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].DeviceID = "" },
		"source-subnet":         func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Source = "10.99.0.0/24" },
		"local-spoof":           func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Source = "10.10.0.8/32" },
		"outside-approved":      func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].Destination = "8.8.8.8/32" },
		"fabricated-dns-source": func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ResolverSourceAddress = "10.10.0.1" },
		"unknown-resolver":      func(m *RuntimeMaterial) { m.Policy.FQDNGrants[0].ResolverKind = "other" },
		"legacy-v1":             func(m *RuntimeMaterial) { m.Policy.FQDNPolicyVersion = 1 },
		"static-tunnel":         func(m *RuntimeMaterial) { m.Manifest.ProfileID = "aws-static-ipv4-v1"; runtimeReseal(m) },
	} {
		t.Run(name, func(t *testing.T) {
			m, _, _ := desktopStaticFQDNFixture(t)
			mutate(&m)
			if _, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]"); err == nil {
				t.Fatal("invalid combined descriptor accepted")
			}
		})
	}
}

func TestDesktopStaticFQDNOnlyUsesDesktopExportAndNATLifecycle(t *testing.T) {
	m, g, _ := desktopStaticFQDNFixture(t)
	if len(m.Policy.DesktopGrants) != 0 {
		t.Fatal("fixture accidentally has ordinary desktop grant")
	}
	grants := []GuardGrant{g}
	prefixes := desktopExportPrefixes(grants)
	if len(prefixes) != 1 || prefixes[0] != g.Source {
		t.Fatal("FQDN-only source omitted from BGP exports")
	}
	nat := &DesktopNATSource{}
	c := &RuntimeController{config: RuntimeControllerConfig{DesktopNAT: nat}}
	c.publishDesktopNAT(m.Manifest.ConnectionID, grants)
	snapshot := nat.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Source != g.Source || snapshot[0].Destination != g.Destination {
		t.Fatal("FQDN-only noSNAT tuple missing")
	}
	expired := g
	expired.FQDN.ExpiresAt = time.Now().Add(-time.Second)
	remaining := liveFQDNGrants([]GuardGrant{expired}, time.Now())
	c.publishDesktopNAT(m.Manifest.ConnectionID, remaining)
	if len(desktopExportPrefixes(remaining)) != 0 || len(nat.Snapshot()) != 0 {
		t.Fatal("last expired FQDN retained desktop desired exports/NAT")
	}
}

func TestDesktopStaticFQDNLeaseIdentityMatchesGuard(t *testing.T) {
	m, g, _ := desktopStaticFQDNFixture(t)
	wire := runtimeFQDNGrantDigest(m.Policy.FQDNGrants[0])
	if wire != guardFQDNGrantDigest(g) {
		t.Fatal("desktop/source resolver provenance lost between current wire lease and native guard")
	}
	a := NewPermitLeaseAuthority()
	id := permitIdentity()
	q, err := a.BeginFQDN(id, []string{wire})
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: 60000, FQDNPermits: []RuntimeFQDNPermit{{GrantDigest: wire, TTLMS: 30000}}}); err != nil {
		t.Fatal(err)
	}
	intent := GuardIntent{Connections: []GuardConnection{{ID: g.FQDN.ConnectionID, PermitFor: time.Minute, Grants: []GuardGrant{g}}}}
	qualified := limitFQDNGuardIntent(intent, time.Now(), 5*time.Second, func(_ uuid.UUID, g GuardGrant, b time.Duration) (time.Duration, error) {
		return a.RemainingFQDNForApply(id, guardFQDNGrantDigest(g), b)
	})
	if len(qualified.Connections[0].Grants) != 1 || qualified.Connections[0].Grants[0].FQDNPermitFor <= 0 {
		t.Fatal("valid desktop CP permit silently dropped its timed membership")
	}
	for name, change := range map[string]func(*GuardGrant){"device": func(g *GuardGrant) { g.DesktopDeviceID = uuid.New() }, "key": func(g *GuardGrant) { g.DesktopPublicKey += "wrong" }, "resolver": func(g *GuardGrant) { g.FQDN.ResolverKind = "" }} {
		t.Run(name, func(t *testing.T) {
			bad := g
			change(&bad)
			if _, err := a.RemainingFQDNForApply(id, guardFQDNGrantDigest(bad), time.Millisecond); err == nil {
				t.Fatal("changed desktop identity reused issued permit")
			}
		})
	}
}
