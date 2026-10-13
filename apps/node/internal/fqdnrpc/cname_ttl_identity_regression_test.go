package fqdnrpc

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCanonicalRecordsTTLIdentityMinimumOrdering(t *testing.T) {
	a := Record{Name: "edge.example.test", Type: RecordA, Address: "10.20.0.8", TTLSeconds: 13}
	b := a
	b.TTLSeconds = 2 // Numeric minimum must win even when decimal lexical order differs.
	c := Record{Name: "api.example.test", Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: 30}
	d := c
	d.TTLSeconds = 29
	otherAddress := a
	otherAddress.Address = "10.20.0.9"
	otherTarget := c
	otherTarget.Target = "other.example.test"
	input := []Record{a, d, otherAddress, c, b, otherTarget}
	want := []Record{d, otherTarget, b, otherAddress}
	for _, records := range [][]Record{input, {otherTarget, b, c, otherAddress, d, a}} {
		before := append([]Record(nil), records...)
		got := canonicalRecords(records)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("identity/minimum/order: got %+v, want %+v", got, want)
		}
		if !reflect.DeepEqual(records, before) {
			t.Fatal("canonicalization mutated caller records")
		}
	}
	invalid := c
	invalid.TTLSeconds = -1
	if got := canonicalRecords([]Record{c, invalid}); len(got) != 1 || got[0].TTLSeconds != -1 {
		t.Fatalf("invalid smaller TTL was hidden: %+v", got)
	}
}

func TestDirectResolverCNAMETTLIdentityConsensus(t *testing.T) {
	for _, multiplicityDiffers := range []bool{false, true} {
		name := "varying TTLs at both endpoints"
		minimum := 5
		if multiplicityDiffers {
			name, minimum = "equal TTL duplicates at only one endpoint", 7
		}
		t.Run(name, func(t *testing.T) {
			config := concurrentResolverConfig(2)
			resolver := DirectResolver{exchange: func(_ context.Context, endpoint ResolverEndpoint, hostname string, typ RecordType) ([]Record, error) {
				second := endpoint == config.Endpoints[1]
				if hostname == "api.example.test" {
					ttl := 30
					if typ == RecordAAAA {
						ttl = 29
					}
					if second {
						ttl = 7
						if typ == RecordAAAA && !multiplicityDiffers {
							ttl = 5
						}
					}
					return []Record{{Name: hostname, Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: ttl}}, nil
				}
				if hostname != "edge.example.test" {
					return nil, errors.New("unexpected CNAME target")
				}
				if typ == RecordA {
					ttl := 60
					if second {
						ttl = 20
					}
					return []Record{{Name: hostname, Type: RecordA, Address: "10.20.0.8", TTLSeconds: ttl}}, nil
				}
				ttl := 50
				if second {
					ttl = 10
				}
				return []Record{{Name: hostname, Type: RecordAAAA, Address: "fd00::8", TTLSeconds: ttl}}, nil
			}}
			records, err := resolver.ResolveBound(context.Background(), "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
			want := []Record{
				{Name: "api.example.test", Type: RecordCNAME, Target: "edge.example.test", TTLSeconds: minimum},
				{Name: "edge.example.test", Type: RecordAAAA, Address: "fd00::8", TTLSeconds: 10},
				{Name: "edge.example.test", Type: RecordA, Address: "10.20.0.8", TTLSeconds: 20},
			}
			if err != nil || !reflect.DeepEqual(records, want) {
				t.Fatalf("same RDATA must reach conservative consensus: err=%v got=%+v want=%+v", err, records, want)
			}
		})
	}
}

func TestDirectResolverCNAMETTLIdentityRDATARefuses(t *testing.T) {
	for _, scope := range []string{"within endpoint", "between endpoints"} {
		t.Run(scope, func(t *testing.T) {
			config := concurrentResolverConfig(2)
			resolver := DirectResolver{exchange: func(_ context.Context, endpoint ResolverEndpoint, hostname string, typ RecordType) ([]Record, error) {
				if hostname == "api.example.test" {
					target, ttl := "edge.example.test", 30
					if scope == "within endpoint" && typ == RecordAAAA || scope == "between endpoints" && endpoint == config.Endpoints[1] {
						target, ttl = "other.example.test", 29
					}
					return []Record{{Name: hostname, Type: RecordCNAME, Target: target, TTLSeconds: ttl}}, nil
				}
				if typ == RecordA {
					return []Record{{Name: hostname, Type: RecordA, Address: "10.20.0.8", TTLSeconds: 30}}, nil
				}
				return nil, nil
			}}
			if records, err := resolver.ResolveBound(context.Background(), "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config); !errors.Is(err, errResolverConfig) || len(records) != 0 {
				t.Fatalf("different actual target must fail closed: err=%v records=%+v", err, records)
			}
		})
	}
}
