package fqdnresources

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func intPtr(v int) *int { return &v }

func TestValidRejectsHalfPortRanges(t *testing.T) {
	for _, in := range []Input{
		{Name: "api", FQDN: "api.example.test", Protocol: "tcp", PortLow: intPtr(443)},
		{Name: "api", FQDN: "api.example.test", Protocol: "udp", PortHigh: intPtr(53)},
	} {
		if err := valid(&in); err == nil {
			t.Fatalf("half port range %+v was accepted", in)
		}
	}
	if err := valid(&Input{Name: "api", FQDN: "api.example.test", Protocol: "tcp", PortLow: intPtr(443), PortHigh: intPtr(443)}); err != nil {
		t.Fatalf("complete TCP port range rejected: %v", err)
	}
}

func TestMutationTokenCanonicalizesPorts(t *testing.T) {
	current := Resource{ID: uuid.New(), UpdatedAt: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)}
	impact := Impact{ReferencingRuleIDs: []uuid.UUID{uuid.New()}}
	aLow, aHigh := 443, 8443
	bLow, bHigh := 443, 8443
	a := Input{FQDN: "api.example.test", Protocol: "tcp", PortLow: &aLow, PortHigh: &aHigh}
	b := Input{FQDN: "api.example.test", Protocol: "tcp", PortLow: &bLow, PortHigh: &bHigh}
	if got, want := mutationToken(current, a, impact), mutationToken(current, b, impact); got != want {
		t.Fatalf("equal dereferenced ports produced distinct tokens: %q != %q", got, want)
	}
	changed := 8444
	b.PortHigh = &changed
	if mutationToken(current, a, impact) == mutationToken(current, b, impact) {
		t.Fatal("changed port did not change token")
	}
	b.PortLow, b.PortHigh = nil, nil
	if mutationToken(current, a, impact) == mutationToken(current, b, impact) {
		t.Fatal("nil ports did not change token")
	}
}
