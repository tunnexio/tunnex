package fqdnrpc

import (
	"context"
	"testing"
)

func TestCNAMEVaryingTTLConsensusModel(t *testing.T) {
	host := "alias.example.test"
	target := "target.example.test"
	for _, vary := range []bool{false, true} {
		d := DirectResolver{exchange: func(_ context.Context, e ResolverEndpoint, n string, typ RecordType) ([]Record, error) {
			ttl := 30
			if vary && e.Transport == "udp" && typ == RecordAAAA {
				ttl = 29
			}
			c := Record{Name: host, Type: RecordCNAME, Target: target, TTLSeconds: ttl}
			if typ == RecordA {
				return []Record{c, {Name: target, Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30}}, nil
			}
			return []Record{c, {Name: target, Type: RecordAAAA, Address: "fd00::10", TTLSeconds: 30}}, nil
		}}
		cfg := ResolverConfig{ID: "66666666-6666-6666-6666-666666666666", Version: 1, ProfileID: "77777777-7777-7777-7777-777777777777", Endpoints: []ResolverEndpoint{{Address: "10.81.0.2", Port: 53, Transport: "tcp"}, {Address: "10.81.0.2", Port: 53, Transport: "udp"}}}
		got, err := d.ResolveBound(context.Background(), host, []RecordType{RecordA, RecordAAAA, RecordCNAME}, cfg)
		if err != nil {
			t.Fatalf("TTL-only variation=%v must preserve identical answer consensus, got %v", vary, err)
		}
		if len(got) != 3 {
			t.Fatalf("want one CNAME and two addresses, got %d", len(got))
		}
		wantTTL := 30
		if vary {
			wantTTL = 29
		}
		for _, r := range got {
			if r.Type == RecordCNAME && r.TTLSeconds != wantTTL {
				t.Fatalf("CNAME TTL=%d want %d", r.TTLSeconds, wantTTL)
			}
		}
	}
}
func TestCanonicalTTLIdentityConservative(t *testing.T) {
	a := Record{Name: "a.example.test", Type: RecordCNAME, Target: "b.example.test", TTLSeconds: 30}
	b := a
	b.TTLSeconds = 29
	in := []Record{a, b}
	got := canonicalRecords(in)
	if len(got) != 1 || got[0].TTLSeconds != 29 || in[0].TTLSeconds != 30 {
		t.Fatal("minimum TTL/input isolation")
	}
	b.Target = "c.example.test"
	if len(canonicalRecords([]Record{a, b})) != 2 {
		t.Fatal("target disagreement collapsed")
	}
	b = a
	b.TTLSeconds = 0
	got = canonicalRecords([]Record{a, b})
	if len(got) != 1 || got[0].TTLSeconds != 0 {
		t.Fatal("invalid TTL masked")
	}
	b = a
	b.Address = "10.81.0.10"
	if len(canonicalRecords([]Record{a, b})) != 2 {
		t.Fatal("malformed field collapsed")
	}
}

func TestCanonicalTTLValueDisagreementRetained(t *testing.T) {
	a := Record{Name: "target.example.test", Type: RecordA, Address: "10.81.0.10", TTLSeconds: 30}
	b := a
	b.Address = "10.81.0.11"
	if len(canonicalRecords([]Record{a, b})) != 2 || sameRecords(canonicalRecords([]Record{a}), canonicalRecords([]Record{b})) {
		t.Fatal("address disagreement collapsed")
	}
	for _, ttl := range []int{-1, 0} {
		b = a
		b.TTLSeconds = ttl
		got := canonicalRecords([]Record{a, b})
		if len(got) != 1 || got[0].TTLSeconds != ttl {
			t.Fatal("minimum invalid TTL masked")
		}
	}
	b = a
	b.TTLSeconds = 29
	if !sameRecords(canonicalRecords([]Record{b, a}), canonicalRecords([]Record{a, b, a})) {
		t.Fatal("reordering changed identity")
	}
}
