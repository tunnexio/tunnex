package policy

import (
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"testing"
)

func TestDesktopStaticCapabilityAndAuthorityIsolation(t *testing.T) {
	for _, fqdn := range []bool{false, true} {
		fixture := desktopPolicyFixture
		if fqdn {
			fixture = desktopFQDNFixture
		}
		setup := func() (Snapshot, ipsec.RuntimePolicyInput) {
			s, in := fixture()
			in.Config.ProfileID = "aws-static-ipv4-v1"
			in.Config.BGP = nil
			in.DesktopStaticVersion = 2
			return s, in
		}
		s, in := setup()
		p, e := compileIPsecRuntimePolicy(s, in)
		if e != nil || len(p.DesktopGrants)+len(p.FQDNGrants) != 1 || len(p.Grants) != 0 {
			t.Fatalf("static authority missing fqdn%t: %+v %v", fqdn, p, e)
		}
		for name, mutate := range map[string]func(*Snapshot, *ipsec.RuntimePolicyInput){
			"old gateway":               func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopStaticVersion = 0 },
			"unqualified first version": func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopStaticVersion = 1 },
			"future version":            func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopStaticVersion = 3 },
			"missing transit":           func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.DesktopTransitVersion = 0 },
			"malformed BGP":             func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.Config.BGP = &ipsec.BGPConfig{} },
			"other provider":            func(s *Snapshot, i *ipsec.RuntimePolicyInput) { i.Config.ProfileID = "gcp-classic-ipv4-v1" },
			"rule removed":              func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Rules = nil },
			"identity removed":          func(s *Snapshot, i *ipsec.RuntimePolicyInput) { s.Devices = nil },
			"expired":                   func(s *Snapshot, i *ipsec.RuntimePolicyInput) { end := i.CompiledAt; s.Rules[0].ExpiresAt = &end },
		} {
			t.Run(name, func(t *testing.T) {
				s, i := setup()
				mutate(&s, &i)
				next, e := compileIPsecRuntimePolicy(s, i)
				if e == nil && (len(next.DesktopGrants)+len(next.FQDNGrants) > 0 || next.Hash == p.Hash) {
					t.Fatal("unsupported static authority retained", e)
				}
			})
		}
	}
}
