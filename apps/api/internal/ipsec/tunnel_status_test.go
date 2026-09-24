package ipsec

import (
	"testing"
	"time"
)

func TestTunnelStatusFreshnessBoundary(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		age  time.Duration
		want bool
	}{{0, true}, {90 * time.Second, true}, {90*time.Second + time.Nanosecond, false}, {-time.Nanosecond, false}} {
		received := now.Add(-tt.age)
		if tunnelStatusFresh(&received, now) != tt.want {
			t.Fatalf("age %s", tt.age)
		}
	}
	if tunnelStatusFresh(nil, now) {
		t.Fatal("nil fresh")
	}
}
