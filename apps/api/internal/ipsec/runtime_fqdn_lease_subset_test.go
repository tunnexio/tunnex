package ipsec

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func desktopExpirySubsetFixture(t *testing.T, profile string) (RuntimePolicy, RuntimeLeaseRequest, RuntimePolicyInput, time.Time) {
	t.Helper()
	p, in := runtimeFQDNPolicyFixture()
	fence := time.Date(2026, 10, 24, 7, 31, 0, 0, time.UTC)
	in.CompiledAt, in.FQDNPolicyVersion, in.DesktopTransitVersion, in.DesktopFQDNVersion, in.DesktopStaticVersion = fence, 2, 1, 1, 2
	in.Config.ProfileID = profile
	if profile == "aws-bgp-ipv4-v1" {
		in.Config.BGP = &BGPConfig{}
	}
	p.FQDNPolicyVersion = 2
	g := p.FQDNGrants[0]
	g.Source, g.DeviceID, g.PublicKey, g.ResolverKind = "10.99.0.3/32", uuid.NewString(), "ZzN444nzLsFjGeLNmSE9lzuvLAWI7mGMU2Z3fLroWnc=", "static_cname"
	g.ExpiresAt = fence.Add(20 * time.Second)
	p.FQDNGrants = []RuntimeFQDNGrant{g}
	other := g
	other.Destination = "10.85.2.10/32"
	p.FQDNGrants = append(p.FQDNGrants, other)
	p.Grants = []RuntimeGrant{{Source: "10.84.2.3/32", Destination: "10.85.3.10/32", Protocol: "tcp", PortLow: 80, PortHigh: 80, RuleID: uuid.NewString()}}
	sortSubsetDescriptors(p.FQDNGrants)
	var err error
	p, err = HashRuntimePolicy(p, in)
	if err != nil || !validRuntimeFQDNPolicy(p, in) {
		t.Fatal("invalid fixture", err)
	}
	request := RuntimeLeaseRequest{PolicyHash: p.Hash, Nonce: strings.Repeat("a", 64), FQDNGrants: append([]RuntimeFQDNGrant(nil), p.FQDNGrants...)}
	p.FQDNGrants = append([]RuntimeFQDNGrant(nil), p.FQDNGrants...)
	for i := range p.FQDNGrants {
		p.FQDNGrants[i].ExpiresAt = p.FQDNGrants[i].ExpiresAt.Add(15 * time.Second)
	}
	p, err = HashRuntimePolicy(p, in)
	if err != nil || p.Hash == request.PolicyHash || !validRuntimeFQDNPolicy(p, in) {
		t.Fatal("missing authentic expiry turnover", err)
	}
	return p, request, in, fence
}

func sortSubsetDescriptors(g []RuntimeFQDNGrant) {
	sort.Slice(g, func(i, j int) bool {
		a, _ := json.Marshal(g[i])
		b, _ := json.Marshal(g[j])
		return string(a) < string(b)
	})
}

func TestRuntimeFQDNDesktopEarlierExpirySubset(t *testing.T) {
	for _, profile := range []string{"aws-static-ipv4-v1", "aws-bgp-ipv4-v1"} {
		t.Run(profile, func(t *testing.T) {
			current, request, in, fence := desktopExpirySubsetFixture(t, profile)
			beforeCurrent, _ := json.Marshal(current)
			beforeRequest, _ := json.Marshal(request)
			got, zero, err := runtimeFQDNLeaseContinuity(current, request, in, fence)
			if err != nil {
				t.Fatalf("same current answer with later DNS expiry rejected: %v", err)
			}
			if got.Hash != request.PolicyHash || len(zero) != 0 || !reflect.DeepEqual(got.FQDNGrants, request.FQDNGrants) || !reflect.DeepEqual(got.Grants, current.Grants) {
				t.Fatal("request authority bytes changed")
			}
			for _, tc := range []struct {
				elapsed time.Duration
				want    int64
			}{{0, 20000}, {1500 * time.Millisecond, 18500}, {20 * time.Second, 0}, {21 * time.Second, 0}} {
				permits, err := runtimeFQDNLeasePermits(got, fence, tc.elapsed)
				if err != nil || len(permits) != len(request.FQDNGrants) {
					t.Fatal("permits", err, permits)
				}
				for i, p := range permits {
					if p.TTLMS != tc.want || p.GrantDigest != runtimeFQDNGrantDigest(request.FQDNGrants[i]) {
						t.Fatal("earlier expiry/digest not preserved", p)
					}
				}
			}
			afterCurrent, _ := json.Marshal(current)
			afterRequest, _ := json.Marshal(request)
			if string(beforeCurrent) != string(afterCurrent) || string(beforeRequest) != string(afterRequest) {
				t.Fatal("input mutated")
			}
		})
	}
}

func TestRuntimeFQDNDesktopExpirySubsetCurrentAuthorityRequired(t *testing.T) {
	cases := map[string]func(*RuntimePolicy, *RuntimeLeaseRequest, *RuntimePolicyInput){
		"revoked": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants = nil
			p.FQDNPolicyVersion = 0
		},
		"current_shorter": func(p *RuntimePolicy, q *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ExpiresAt = q.FQDNGrants[0].ExpiresAt.Add(-time.Second)
		},
		"current_expired": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, in *RuntimePolicyInput) {
			p.FQDNGrants[0].ExpiresAt = in.CompiledAt
		},
		"answer": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].Destination = "10.85.9.10/32"
		},
		"added_answer": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			g := p.FQDNGrants[0]
			g.Destination = "10.85.9.10/32"
			p.FQDNGrants = append(p.FQDNGrants, g)
		},
		"omitted_answer": func(_ *RuntimePolicy, q *RuntimeLeaseRequest, _ *RuntimePolicyInput) { q.FQDNGrants = q.FQDNGrants[:1] },
		"generation": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].Generation = strings.Repeat("b", 64)
		},
		"rule": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].RuleID = uuid.NewString()
		},
		"resource": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ResourceID = uuid.NewString()
		},
		"device": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].DeviceID = uuid.NewString()
		},
		"public_key": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
		"source": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].Source = "10.99.0.4/32"
		},
		"protocol": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].Protocol = "udp"
		},
		"port": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) { p.FQDNGrants[0].PortHigh++ },
		"name": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].Name = "other.corp.example"
		},
		"resolver_config": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ResolverConfigID = uuid.NewString()
		},
		"resolver_version": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ResolverConfigVersion++
		},
		"resolver_profile": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ResolverProfileID = uuid.NewString()
		},
		"resolver_suffix": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ResolverMatchSuffix = "example"
		},
		"site": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].SelectedSiteID = uuid.NewString()
		},
		"gateway": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].SelectedGatewayID = uuid.NewString()
		},
		"connection": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ConnectionID = uuid.NewString()
		},
		"config_revision": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants[0].ConfigurationRevision++
		},
		"ordinary": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) { p.Grants[0].PortHigh++ },
		"desktop": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.DesktopGrants = []RuntimeDesktopGrant{{}}
		},
		"dns": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.DNSResolverGrants = []RuntimeDNSResolverGrant{{}}
		},
		"current_duplicate": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			p.FQDNGrants = append(p.FQDNGrants, p.FQDNGrants[0])
		},
		"current_duplicate_expiry": func(p *RuntimePolicy, _ *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			g := p.FQDNGrants[0]
			g.ExpiresAt = g.ExpiresAt.Add(time.Second)
			p.FQDNGrants = append(p.FQDNGrants, g)
		},
		"request_duplicate": func(_ *RuntimePolicy, q *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			q.FQDNGrants = append(q.FQDNGrants, q.FQDNGrants[0])
		},
		"request_duplicate_expiry": func(_ *RuntimePolicy, q *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			g := q.FQDNGrants[0]
			g.ExpiresAt = g.ExpiresAt.Add(time.Second)
			q.FQDNGrants = append(q.FQDNGrants, g)
		},
		"missing_expiry": func(_ *RuntimePolicy, q *RuntimeLeaseRequest, _ *RuntimePolicyInput) {
			q.FQDNGrants[0].ExpiresAt = time.Time{}
		},
		"unqualified": func(_ *RuntimePolicy, _ *RuntimeLeaseRequest, in *RuntimePolicyInput) { in.DesktopStaticVersion = 1 },
		"foreign_provider": func(_ *RuntimePolicy, _ *RuntimeLeaseRequest, in *RuntimePolicyInput) {
			in.Config.ProfileID = "gcp-classic-ipv4-v1"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			current, q, in, fence := desktopExpirySubsetFixture(t, "aws-static-ipv4-v1")
			original := current
			original.Grants = append([]RuntimeGrant(nil), current.Grants...)
			original.FQDNGrants = nil
			mutate(&current, &q, &in)
			sortSubsetDescriptors(q.FQDNGrants)
			// Rehash altered requests to ensure invalid descriptor sets are refused
			// independently of a trivially incorrect request hash.
			original.FQDNGrants = q.FQDNGrants
			original, err := HashRuntimePolicy(original, in)
			if err != nil {
				t.Fatal(err)
			}
			q.PolicyHash = original.Hash
			if _, _, err := runtimeFQDNLeaseContinuity(current, q, in, fence); err == nil {
				t.Fatal("changed current authority accepted")
			}
		})
	}
}

func TestRuntimeFQDNDesktopExpirySubsetExpiredStaysZero(t *testing.T) {
	current, q, in, fence := desktopExpirySubsetFixture(t, "aws-static-ipv4-v1")
	got, _, err := runtimeFQDNLeaseContinuity(current, q, in, fence.Add(21*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	permits, err := runtimeFQDNLeasePermits(got, fence.Add(21*time.Second), time.Second)
	if err != nil || len(permits) != 2 {
		t.Fatal(err, permits)
	}
	for i, p := range permits {
		if p.TTLMS != 0 || p.GrantDigest != runtimeFQDNGrantDigest(q.FQDNGrants[i]) {
			t.Fatal("expired grant revived", p)
		}
	}
}

func TestRuntimeFQDNExpirySubsetPreservesLANExactContract(t *testing.T) {
	current, q, in, fence := desktopExpirySubsetFixture(t, "aws-static-ipv4-v1")
	for i := range current.FQDNGrants {
		for _, g := range []*RuntimeFQDNGrant{&current.FQDNGrants[i], &q.FQDNGrants[i]} {
			g.Source = "10.84.2.3/32"
			g.DeviceID = ""
			g.PublicKey = ""
			g.ResolverKind = ""
			g.ResolverSourceAddress = "10.84.2.1"
		}
	}
	before := current
	before.FQDNGrants = q.FQDNGrants
	before, _ = HashRuntimePolicy(before, in)
	q.PolicyHash = before.Hash
	if _, _, err := runtimeFQDNLeaseContinuity(current, q, in, fence); err == nil {
		t.Fatal("LAN expiry-only matching widened")
	}
	current.FQDNGrants = append([]RuntimeFQDNGrant(nil), q.FQDNGrants...)
	if _, _, err := runtimeFQDNLeaseContinuity(current, q, in, fence); err != nil {
		t.Fatal("exact LAN descriptor refused", err)
	}
}
