package policy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestIPsecFQDNV2ObservationClockProvenance(t *testing.T) {
	for _, tc := range []string{"missing_observation", "future_observation", "missing_compiler_clock", "expired_observation", "expiry_before_observation"} {
		t.Run(tc, func(t *testing.T) {
			s, in := runtimeFQDNFixture(t)
			in.FQDNPolicyVersion = 2
			in.CompiledAt = time.Now().UTC()
			g := s.FQDNResources[0].Active
			g.ResolvedAt = in.CompiledAt
			g.FreshUntil = in.CompiledAt.Add(30 * time.Second)
			switch tc {
			case "missing_observation":
				g.ResolvedAt = time.Time{}
			case "future_observation":
				g.ResolvedAt = in.CompiledAt.Add(time.Second)
			case "missing_compiler_clock":
				in.CompiledAt = time.Time{}
			case "expired_observation":
				g.ResolvedAt = in.CompiledAt.Add(-time.Minute)
				g.FreshUntil = in.CompiledAt.Add(-time.Second)
			case "expiry_before_observation":
				g.ResolvedAt = in.CompiledAt.Add(-time.Second)
				g.FreshUntil = in.CompiledAt.Add(-2 * time.Second)
			}
			p, err := compileIPsecRuntimePolicy(s, in)
			if err != nil || len(p.FQDNGrants) != 0 || p.FQDNPolicyVersion != 0 || len(p.Grants) != 1 {
				t.Fatal("invalid observation clock admitted or ordinary grant changed")
			}
		})
	}
}

func TestIPsecFQDNV2AbsoluteCutoffAndResolverSource(t *testing.T) {
	snapshot, input := runtimeFQDNFixture(t)
	input.FQDNPolicyVersion = 2
	now := time.Now().UTC()
	generationEnd := now.Add(45 * time.Second)
	ruleEnd := now.Add(25 * time.Second)
	snapshot.FQDNResources[0].Active.FreshUntil = generationEnd
	snapshot.Rules[0].ExpiresAt = &ruleEnd
	p, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || p.FQDNPolicyVersion != 2 || len(p.FQDNGrants) != 1 {
		t.Fatal("fresh cap2 grant missing", err)
	}
	g := p.FQDNGrants[0]
	if !g.ExpiresAt.Equal(ruleEnd) || g.ResolverSourceAddress != "10.84.2.254" {
		t.Fatal("absolute rule minimum/source lost")
	}
	snapshot.Rules[0].ExpiresAt = nil
	p, err = compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || !p.FQDNGrants[0].ExpiresAt.Equal(generationEnd) {
		t.Fatal("generation absolute cutoff lost", err)
	}
	// Recompilation cannot renew a saved generation's absolute TTL.
	q, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil || !q.FQDNGrants[0].ExpiresAt.Equal(generationEnd) {
		t.Fatal("saved generation renewed", err)
	}
	for _, expiry := range []time.Time{{}, now.Add(-time.Second), now.Add(2 * time.Hour)} {
		snapshot.FQDNResources[0].Active.FreshUntil = expiry
		q, err = compileIPsecRuntimePolicy(snapshot, input)
		if err != nil || len(q.FQDNGrants) != 0 || q.FQDNPolicyVersion != 0 {
			t.Fatal("stale/unbounded generation granted", err)
		}
	}
}

func TestIPsecFQDNV1OmitsAbsoluteAuthorityFields(t *testing.T) {
	snapshot, input := runtimeFQDNFixture(t)
	p, err := compileIPsecRuntimePolicy(snapshot, input)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := json.Marshal(p)
	end := time.Now().Add(time.Minute)
	snapshot.FQDNResources[0].Active.FreshUntil = end
	snapshot.Rules[0].ExpiresAt = &end
	q, err := compileIPsecRuntimePolicy(snapshot, input)
	second, _ := json.Marshal(q)
	if err != nil || !bytes.Equal(first, second) || bytes.Contains(first, []byte("expires_at")) || bytes.Contains(first, []byte("resolver_source_address")) {
		t.Fatal("v1 wire/hash changed", err)
	}
}
