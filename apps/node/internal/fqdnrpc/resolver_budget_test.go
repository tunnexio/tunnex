package fqdnrpc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// This fixture models measured independent proof latency, not live networking.
func TestDirectResolverSequentialProofCostConsumesOriginalDeadline(t *testing.T) {
	config := ResolverConfig{ID: "66666666-6666-6666-6666-666666666666", Version: 4, ProfileID: "77777777-7777-7777-7777-777777777777", MatchedSuffix: "example.test"}
	for _, address := range []string{"10.20.0.53", "10.20.0.54"} {
		for _, protocol := range []string{"udp", "tcp"} {
			config.Endpoints = append(config.Endpoints, ResolverEndpoint{Address: address, Port: 53, Transport: protocol})
		}
	}
	calls := 0
	resolver := DirectResolver{exchange: func(ctx context.Context, _ ResolverEndpoint, name string, typ RecordType) ([]Record, error) {
		calls++
		// Two complete independent reads at the lower measured latency bound.
		for range 2 {
			timer := time.NewTimer(400 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
		if typ == RecordA {
			return []Record{{Name: name, Type: RecordA, Address: "10.20.0.8", TTLSeconds: 30}}, nil
		}
		return nil, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	records, err := resolver.ResolveBound(ctx, "api.example.test", []RecordType{RecordA, RecordAAAA, RecordCNAME}, config)
	if !errors.Is(err, errResolverConfig) || len(records) != 0 || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("original deadline must refuse incomplete consensus: err=%v records=%d context=%v", err, len(records), ctx.Err())
	}
	if calls != 7 {
		t.Fatalf("expected six complete exchanges and seventh interrupted, got %d", calls)
	}
	if time.Since(start) > 6*time.Second {
		t.Fatal("resolution extended original deadline")
	}
}
