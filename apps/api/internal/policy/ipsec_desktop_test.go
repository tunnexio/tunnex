package policy

import (
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
	"time"
)

func desktopPolicyFixture() (Snapshot, ipsec.RuntimePolicyInput) {
	org, node, site, conn, device, user, resource, group := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	in := ipsec.RuntimePolicyInput{OrgID: org, NodeID: node, SiteID: site, ConnectionID: conn, DesktopTransitVersion: 1, CompiledAt: time.Now(), Config: ipsec.StaticConfig{ProfileID: "aws-bgp-ipv4-v1", BGP: &ipsec.BGPConfig{}, LocalPrefixes: []string{"192.168.1.0/24"}, RemotePrefixes: []string{"10.180.0.0/16"}}}
	s := Snapshot{Mode: ModeEnforcing, SiteNodes: []SiteNode{{NodeID: node, SiteID: site}}, Devices: []Device{{ID: device, UserID: user, NodeID: node, AssignedIP: "10.99.0.7", Kind: "human", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}}, Memberships: []Membership{{UserID: user, GroupID: group}}, Resources: []Resource{{ID: resource, CIDR: "10.180.1.8/32", Protocol: "tcp", PortLow: 443, PortHigh: 443}}, Rules: []Rule{{ID: uuid.New(), SrcKind: "group", SrcGroupID: group, DstKind: "resource", DstResourceID: resource}}}
	return s, in
}
func TestIPsecDesktopExplicitIdentityAndLifecycle(t *testing.T) {
	s, in := desktopPolicyFixture()
	p, err := compileIPsecRuntimePolicy(s, in)
	if err != nil || len(p.DesktopGrants) != 1 || len(p.Grants) != 0 {
		t.Fatalf("projection: %+v %v", p, err)
	}
	g := p.DesktopGrants[0]
	if g.Source != "10.99.0.7/32" || g.Destination != "10.180.1.8/32" || g.DeviceID != s.Devices[0].ID.String() || g.PublicKey != s.Devices[0].PublicKey || g.PortLow != 443 {
		t.Fatal("identity or tuple widened", g)
	}
	for name, mutate := range map[string]func(*Snapshot, *ipsec.RuntimePolicyInput){
		"literal VPN CIDR": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
			s.Rules[0].SrcKind = "cidr"
			s.Rules[0].SrcCIDR = "10.99.0.0/24"
		},
		"wrong gateway":      func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices[0].NodeID = uuid.New() },
		"revoked device":     func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices = nil },
		"removed membership": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Memberships = nil },
		"disabled rule":      func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Rules[0].Disabled = true },
		"expired rule":       func(s *Snapshot, i *ipsec.RuntimePolicyInput) { end := i.CompiledAt; s.Rules[0].ExpiresAt = &end },
		"mode off":           func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Mode = ModeOff },
		"legacy capability":  func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopTransitVersion = 0 },
		"static unsupported": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
			i.Config.ProfileID = "aws-static-ipv4-v1"
			i.Config.BGP = nil
		},
		"Azure unqualified": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.Config.ProfileID = "azure-active-active-bgp-ipv4-v1" },
		"outside remote":    func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Resources[0].CIDR = "8.8.8.8/32" },
		"ambiguous assigned IP": func(s *Snapshot, i *ipsec.RuntimePolicyInput) {
			d := s.Devices[0]
			d.ID = uuid.New()
			s.Devices = append(s.Devices, d)
		},
		"unenrolled key": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices[0].PublicKey = "" },
		"agent excluded": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices[0].Kind = "agent" },
	} {
		t.Run(name, func(t *testing.T) {
			s, i := desktopPolicyFixture()
			mutate(&s, &i)
			got, err := compileIPsecRuntimePolicy(s, i)
			if err == nil && len(got.DesktopGrants) != 0 {
				t.Fatalf("unqualified authority: %+v", got.DesktopGrants)
			}
		})
	}
	s.Rules[0].Disabled = true
	next, err := compileIPsecRuntimePolicy(s, in)
	if err != nil || next.Hash == p.Hash {
		t.Fatal("revocation did not invalidate lease hash")
	}
}
func TestIPsecDesktopExpiryAndExportBound(t *testing.T) {
	s, in := desktopPolicyFixture()
	end := in.CompiledAt.Add(time.Minute)
	s.Rules[0].ExpiresAt = &end
	p, err := compileIPsecRuntimePolicy(s, in)
	if err != nil || len(p.DesktopGrants) != 1 || p.DesktopGrants[0].ExpiresAt == nil || !p.DesktopGrants[0].ExpiresAt.Equal(end) {
		t.Fatal("expiry lost")
	}
	for i := 0; i < 64; i++ {
		d := s.Devices[0]
		d.ID = uuid.New()
		d.AssignedIP = fmt.Sprintf("10.99.1.%d", i+1)
		s.Devices = append(s.Devices, d)
	}
	if len(compileIPsecDesktopGrants(s, in)) != 0 {
		t.Fatal("export prefix bound silently exceeded")
	}
}
