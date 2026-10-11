package policy

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

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
